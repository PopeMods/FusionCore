// Copyright (c) 2026 XtraCube
#include <unistd.h>
#include <jni.h>
#include <filesystem>
#include <logger.h>
#include <libmain.h>
#include <fusion_config.h>
#include <hooking/il2cpp.h>
#include <hooking/safehook.h>
#include <hooking/allocator.h>
#include <hooking/libunity.h>
#include <dotnet.h>
#include <external/dobby.h>
#include <utilities/java.h>
#include <dlfcn.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <fstream>

#define TAG "FusionCore"

namespace fs = std::filesystem;

FusionConfig runtime_config;

static std::string jstring_value(JNIEnv *env, jstring value) {
    if (!value) return {};
    const char *chars = env->GetStringUTFChars(value, nullptr);
    std::string result = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(value, chars);
    return result;
}

static bool extract_asset_tree(JNIEnv *env, jobject javaAssets, jmethodID listAssets,
                               AAssetManager *assets, const std::string &assetRoot,
                               const fs::path &destination, size_t &verifiedFiles) {
    jstring root = env->NewStringUTF(assetRoot.c_str());
    auto names = static_cast<jobjectArray>(env->CallObjectMethod(javaAssets, listAssets, root));
    env->DeleteLocalRef(root);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        log_format(LogLevel::ERROR, TAG, "Could not list runtime assets at {}", assetRoot);
        return false;
    }
    if (!names) return false;
    const jsize count = env->GetArrayLength(names);
    if (count == 0) {
        env->DeleteLocalRef(names);
        log_format(LogLevel::ERROR, TAG, "Runtime asset directory is empty or missing: {}", assetRoot);
        return false;
    }
    fs::create_directories(destination);
    bool success = true;
    for (jsize i = 0; i < count; ++i) {
        auto javaName = static_cast<jstring>(env->GetObjectArrayElement(names, i));
        const std::string name = jstring_value(env, javaName);
        env->DeleteLocalRef(javaName);
        if (name.empty() || name == "." || name == ".." || name.find_first_of("/\\:") != std::string::npos) {
            success = false;
            continue;
        }
        const std::string assetPath = assetRoot + "/" + name;
        const fs::path outputPath = destination / name;
        AAsset *asset = AAssetManager_open(assets, assetPath.c_str(), AASSET_MODE_STREAMING);
        if (!asset) {
            success = extract_asset_tree(env, javaAssets, listAssets, assets, assetPath, outputPath, verifiedFiles) && success;
            continue;
        }
        const auto expectedSize = static_cast<uintmax_t>(AAsset_getLength64(asset));
        const bool existing = fs::is_regular_file(outputPath);
        // retain user config, but repair missing/truncated runtime files
        // even when an older build left a success marker behind
        if (existing && ((name == "BepInEx.cfg" && fs::file_size(outputPath) > 0)
                         || fs::file_size(outputPath) == expectedSize)) {
            ++verifiedFiles;
            AAsset_close(asset);
            continue;
        }
        const fs::path pending = outputPath.string() + ".extracting";
        std::ofstream output(pending, std::ios::binary | std::ios::trunc);
        char buffer[32 * 1024];
        int read = 0;
        while (output && (read = AAsset_read(asset, buffer, sizeof(buffer))) > 0)
            output.write(buffer, read);
        output.flush();
        bool copied = output.good() && read == 0;
        output.close();
        copied = copied && !output.fail();
        AAsset_close(asset);
        if (copied && fs::file_size(pending) == expectedSize) {
            fs::rename(pending, outputPath);
            ++verifiedFiles;
        } else {
            fs::remove(pending);
            log_format(LogLevel::ERROR, TAG, "Could not extract runtime asset {}", assetPath);
            success = false;
        }
    }
    env->DeleteLocalRef(names);
    return success;
}

static bool extract_injected_runtime(JNIEnv *env, const FusionConfig &config) {
    const fs::path marker = fs::path(config.bepInExDirectory).parent_path() / ".popemanager-runtime-v1";
    jobject activity = getUnityActivity(env);
    if (!activity) return false;
    jclass activityClass = env->GetObjectClass(activity);
    jmethodID getAssets = env->GetMethodID(activityClass, "getAssets", "()Landroid/content/res/AssetManager;");
    jobject javaAssets = getAssets ? env->CallObjectMethod(activity, getAssets) : nullptr;
    AAssetManager *assets = javaAssets ? AAssetManager_fromJava(env, javaAssets) : nullptr;
    jclass assetClass = javaAssets ? env->GetObjectClass(javaAssets) : nullptr;
    jmethodID listAssets = assetClass ? env->GetMethodID(assetClass, "list", "(Ljava/lang/String;)[Ljava/lang/String;") : nullptr;
    size_t verifiedFiles = 0;
    bool ok = false;
    try {
        fs::remove(marker);
        ok = assets && listAssets
            && extract_asset_tree(env, javaAssets, listAssets, assets, "PopeMods/runtime/BepInEx", config.bepInExDirectory, verifiedFiles)
            && extract_asset_tree(env, javaAssets, listAssets, assets, "PopeMods/runtime/dotnet", config.dotnetDirectory, verifiedFiles)
            && fs::is_regular_file(fs::path(config.bepInExDirectory) / "core/BepInEx.Unity.IL2CPP.dll")
            && fs::is_regular_file(fs::path(config.bepInExDirectory) / "core/BepInEx.Core.dll")
            && fs::is_regular_file(fs::path(config.dotnetDirectory) / "System.Private.CoreLib.dll");
        if (ok) {
            fs::create_directories(fs::path(config.bepInExDirectory) / "plugins");
            std::ofstream output(marker, std::ios::trunc);
            output << "ok\n";
            output.close();
            ok = !output.fail();
        }
    } catch (const std::exception &error) {
        log_format(LogLevel::ERROR, TAG, "Runtime extraction failed: {}", error.what());
        ok = false;
    }
    if (assetClass) env->DeleteLocalRef(assetClass);
    if (javaAssets) env->DeleteLocalRef(javaAssets);
    if (activityClass) env->DeleteLocalRef(activityClass);
    if (activity) env->DeleteLocalRef(activity);
    if (!ok) {
        log(LogLevel::ERROR, TAG, "Could not extract the FusionCore runtime.");
        return false;
    }
    log_format(LogLevel::INFO, TAG, "Verified {} runtime files, including BepInEx/core", verifiedFiles);
    return true;
}

static FusionConfig gorilla_tag_config(JNIEnv *env) {
    FusionConfig config{};
    jobject activity = getUnityActivity(env);
    if (!activity) return config;
    jclass context = env->FindClass("android/content/Context");
    jclass applicationInfo = env->FindClass("android/content/pm/ApplicationInfo");
    auto getFilesDir = env->GetMethodID(context, "getFilesDir", "()Ljava/io/File;");
    auto getCodeCacheDir = env->GetMethodID(context, "getCodeCacheDir", "()Ljava/io/File;");
    auto getExternalFilesDir = env->GetMethodID(context, "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;");
    auto getApplicationInfo = env->GetMethodID(context, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jclass fileClass = env->FindClass("java/io/File");
    auto getPath = env->GetMethodID(fileClass, "getAbsolutePath", "()Ljava/lang/String;");
    jobject files = env->CallObjectMethod(activity, getFilesDir);
    jobject cache = env->CallObjectMethod(activity, getCodeCacheDir);
    jobject external = env->CallObjectMethod(activity, getExternalFilesDir, nullptr);
    jobject info = env->CallObjectMethod(activity, getApplicationInfo);
    auto nativeLibraryDir = env->GetFieldID(applicationInfo, "nativeLibraryDir", "Ljava/lang/String;");
    std::string filesPath = jstring_value(env, (jstring)env->CallObjectMethod(files, getPath));
    std::string externalPath = jstring_value(env, external ? (jstring)env->CallObjectMethod(external, getPath) : nullptr);
    config.gameLibraryDirectory = jstring_value(env, (jstring)env->GetObjectField(info, nativeLibraryDir));
    config.appLibraryDirectory = config.gameLibraryDirectory;
    config.appDataDirectory = filesPath.empty() ? "" : std::filesystem::path(filesPath).parent_path().string();
    config.codeCacheDirectory = jstring_value(env, (jstring)env->CallObjectMethod(cache, getPath));
    std::filesystem::path root = std::filesystem::path(externalPath) / "PopeManager" / "FusionCore";
    config.bepInExDirectory = (root / "BepInEx").string();
    config.dotnetDirectory = (root / "dotnet").string();
    config.unityDataDirectory = (root / "Data").string();
    config.unityVersion = "6000.0.0";
    jmethodID getAssets = env->GetMethodID(context, "getAssets", "()Landroid/content/res/AssetManager;");
    jobject javaAssets = getAssets ? env->CallObjectMethod(activity, getAssets) : nullptr;
    AAssetManager *assets = javaAssets ? AAssetManager_fromJava(env, javaAssets) : nullptr;
    AAsset *versionAsset = assets ? AAssetManager_open(assets,
        "PopeMods/runtime/BepInEx/UnityVersion.txt", AASSET_MODE_STREAMING) : nullptr;
    if (versionAsset) {
        char version[128] = {};
        const int size = AAsset_read(versionAsset, version, sizeof(version) - 1);
        if (size > 0) config.unityVersion.assign(version, size);
        AAsset_close(versionAsset);
    }
    if (javaAssets) env->DeleteLocalRef(javaAssets);
    config.useOriginalLibUnity = true;
    config.isIl2Cpp2Mono = false;
    config.initialized = !config.gameLibraryDirectory.empty() && !externalPath.empty();
    return config;
}

static bool execute_fusion_config(const FusionConfig &config)
{
    fusion_print_config(config);

    fs::path gameLibsPath(config.gameLibraryDirectory);
    fs::path codeCache(config.codeCacheDirectory);
    fs::path gamePath = fs::path(config.bepInExDirectory).parent_path();

    fs::path libUnity;
    fs::path patchedLibIl2Cpp;
    if(config.isIl2Cpp2Mono){
        fs::path MonoPath(config.dotnetDirectory);

        fs::path monoLib = MonoPath / "libmonosgen-2.0.so";
        void* handle = dlopen(monoLib.c_str(), RTLD_GLOBAL | RTLD_NOW);
        if (!handle) {
            log_format(LogLevel::ERROR, TAG, "Failed to dlopen libmonosgen-2.0.so: {}", dlerror());
            return false;
        }
        patchedLibIl2Cpp = MonoPath / "libil2cpp.so";
        handle = dlopen(patchedLibIl2Cpp.c_str(), RTLD_GLOBAL | RTLD_NOW);
        if (!handle) {
            log_format(LogLevel::ERROR, TAG, "Failed to dlopen {}: {}", patchedLibIl2Cpp.string(), dlerror());
            return false;
        }
        using SetOverrideDirs = void (*)(const char*, const char*);
        auto set_override_dirs =
                reinterpret_cast<SetOverrideDirs>(
                        dlsym(handle, "il2cpp2mono_set_override_dirs")
                );
        fs::path dllpath = gamePath / "PersistentData/mono";
        fs::path monopath = MonoPath / "mono";
        log_format(LogLevel::INFO, TAG, "setting il2cpp2mono paths: {}, {}", dllpath.c_str(), monopath.c_str());
        set_override_dirs(dllpath.c_str(), monopath.c_str());
    }
    else{
        patchedLibIl2Cpp = codeCache / "libil2cpp.so";
        fs::path libIl2Cpp = gameLibsPath / "libil2cpp.so";
        allocate_setup_injected(libIl2Cpp.c_str(), patchedLibIl2Cpp.c_str(), 1024 * 1024);
    }
    if (config.useOriginalLibUnity)
    {
        libUnity = gameLibsPath / "libunity.so";
    }
    else
    {
        libUnity = codeCache / "libunity.so";
    }

    std::string libUnityPath = libUnity.string();
    try_hook_libunity(libUnityPath, (gameLibsPath / "libunity.so").string());

    std::string patchedPath = patchedLibIl2Cpp.string();
    libmain_set_override_il2cpp_path(patchedPath.c_str());
    libmain_set_override_unity_path(libUnityPath.c_str());

    log(LogLevel::INFO, TAG, "FusionCore bootstrap finished successfully.");
    return true;
}

int il2cpp_init_hook(char *domain_name)
{
    const char *d_name = domain_name ? domain_name : "Unknown Domain Name";
    log_format(LogLevel::INFO, TAG, "il2cpp_init called with domain: {}", d_name);
    il2cpp_restore_library_loads();
    il2cpp_destroy_init_hook();

    // call the original il2cpp_init function
    int result = il2cpp_init(domain_name);

    if (runtime_config.initialized)
    {
        // setup environment variables
        setenv("BEPINEX_GAME_ASSEMBLY_PATH", libmain_get_override_il2cpp_path(), 1);
        setenv("FUSION_BEPINEX_PATH", runtime_config.bepInExDirectory.c_str(), 1);
        setenv("FUSION_GAME_BINARY", libmain_get_override_il2cpp_path(), 1);
        setenv("FUSION_GAME_DATA_DIR", runtime_config.unityDataDirectory.c_str(), 1);
        setenv("FUSION_APP_DATA_DIR", runtime_config.appDataDirectory.c_str(), 1);
        setenv("FUSION_UNITY_VERSION", runtime_config.unityVersion.c_str(), 1);
        const auto preloaderLog = (fs::path(runtime_config.bepInExDirectory) / "preloader.log").string();
        setenv("BEPINEX_PRELOADER_LOG", preloaderLog.c_str(), 1);

        const char *ssl_cert_path = "/apex/com.android.conscrypt/cacerts";
        const char *backup_cert_path = "/system/etc/security/cacerts";
        if (access(ssl_cert_path, R_OK) == 0) {
            setenv("SSL_CERT_DIR", ssl_cert_path, 1);
        } else if (access(backup_cert_path, R_OK) == 0) {
            setenv("SSL_CERT_DIR", backup_cert_path, 1);
        } else {
            log(LogLevel::WARN, TAG, "No readable SSL cert file found; HTTPS requests may fail.");
        }
        const char *ssl_path = getenv("SSL_CERT_DIR");
        const char *safe_ssl_path = ssl_path ? ssl_path : "(null)";
        log_format(LogLevel::INFO, TAG, "Using {} for SSL certificates", safe_ssl_path);

        fs::path bepInExCoreDirectory = fs::path(runtime_config.bepInExDirectory) / "core";

        DotNetConfig dotNetConfig;
        dotNetConfig.runtimeDir = runtime_config.dotnetDirectory;
        dotNetConfig.managedLibsDir = bepInExCoreDirectory.string();
        dotNetConfig.entryPointAssembly = "BepInEx.Unity.IL2CPP";
        dotNetConfig.entryPointType = "BepInEx.Unity.IL2CPP.FusionCoreEntrypoint";
        dotNetConfig.entryPointMethod = "Start";
        dotNetConfig.IsMono = runtime_config.isIl2Cpp2Mono;
        // set TMPDIR for MonoMod lib drops
        setenv("TMPDIR", runtime_config.codeCacheDirectory.c_str(), 1);

        setenv("HOME", runtime_config.appDataDirectory.c_str(), 1);
        setenv("XDG_CACHE_HOME", runtime_config.codeCacheDirectory.c_str(), 1);

        // create AuxFolderPluginList
        auto aux = runtime_config.auxiliaryPluginFolders;
        int size = static_cast<int>(aux.size());
        const char** pointerArray = new const char*[size];

        for (int i = 0; i < size; i++) {
            char* strCopy = new char[aux[i].length() + 1];
            std::copy(aux[i].begin(), aux[i].end(), strCopy);
            strCopy[aux[i].length()] = '\0';

            pointerArray[i] = strCopy;
        }

        AuxPluginFolderList list{};
        list.count = size;
        list.folders = pointerArray;

        // change working directory to fusion's scoped data directory
        chdir(runtime_config.appDataDirectory.c_str());
        dotnet_execute_assembly(dotNetConfig, &list);
    }
    else
    {
        log(LogLevel::WARN, TAG, "FusionConfig not initialized. Skipping modloader initialization.");
    }

    log_format(LogLevel::INFO, TAG, "il2cpp_init returned: {}", result);
    return result;
}

extern "C" [[maybe_unused]] bool fusion_bootstrap_from_libmain(JNIEnv *env)
{
    log(LogLevel::INFO, TAG, "FusionCore bootstrap starting...");
    jobject javaConfig = get_fusion_config(env);
    const bool injected = javaConfig == nullptr;
    FusionConfig config = javaConfig ? fusion_parse_config(env, javaConfig) : gorilla_tag_config(env);
    if (javaConfig) env->DeleteLocalRef(javaConfig);

    if (injected && !extract_injected_runtime(env, config)) return false;

    log(LogLevel::INFO, TAG, "Executing Fusion bootstrap from libmain namespace...");
    if (!execute_fusion_config(config)) {
        log(LogLevel::ERROR, TAG, "Failed to execute Fusion bootstrap.");
        return false;
    }

    runtime_config = config;
    auto il2cpp_path = libmain_get_override_il2cpp_path();
    if (!il2cpp_initialize(il2cpp_path))
    {
        log_format(LogLevel::ERROR, TAG, "Failed to initialize il2cpp with path: {}", il2cpp_path);
        return false;
    }
    if(runtime_config.isIl2Cpp2Mono){
        setLoadingState(false);
        log(LogLevel::WARN, TAG, "BepInEx is currently disabled in il2cpp2mono.");
        return true;
    }
    // Pool placement and library bounds must be trustworthy before any hooking.
    const uintptr_t pool_base = get_injected_pool_base();
    const uintptr_t il2cpp_base = il2cpp_get_library_base();
    if (pool_base == 0 || il2cpp_base == 0 || pool_base <= il2cpp_base)
    {
        log_format(LogLevel::ERROR, TAG,
                   "Invalid pool/library base relationship! pool=0x{:X}, il2cpp=0x{:X}",
                   pool_base, il2cpp_base);
        return false;
    }

    // plain integer subtraction (pool sits directly above the library image)
    const size_t library_size = pool_base - il2cpp_base;
    constexpr size_t kMaxPlausibleLibrarySize = 512ull * 1024 * 1024;
    if (library_size > kMaxPlausibleLibrarySize)
    {
        log_format(LogLevel::ERROR, TAG,
                   "Implausible library size 0x{:X}; refusing to initialize SafeHook",
                   library_size);
        return false;
    }

    if (!safehook_initialize(il2cpp_get_handle(), il2cpp_base, library_size, allocate_injected))
    {
        log(LogLevel::ERROR, TAG, "Failed to initialize SafeHook");
        return false;
    }

    log(LogLevel::INFO, TAG, "Installing il2cpp hooks...");
    il2cpp_install_init_hook(il2cpp_init_hook);
    if (injected && !il2cpp_redirect_library_loads()) return false;
    log(LogLevel::INFO, TAG, "il2cpp hooks installed successfully!");
    log(LogLevel::INFO, TAG, "FusionCore bootstrap finished successfully.");
    return true;
}
