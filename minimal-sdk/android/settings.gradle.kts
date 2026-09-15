pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "utexo-minimal-sdk-android"

// AGP locates the SDK from ANDROID_HOME / ANDROID_SDK_ROOT or `sdk.dir` in
// local.properties (gitignored). CI sets the variable; for a developer
// machine with the SDK at its default location, write local.properties once
// so the plan's gate command needs no extra environment.
run {
    val localProperties = rootDir.resolve("local.properties")
    val fromEnv = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
    if (fromEnv == null && !localProperties.exists()) {
        val defaultSdk = File(System.getProperty("user.home"), "Android/Sdk")
        if (defaultSdk.resolve("platforms").isDirectory) {
            localProperties.writeText("sdk.dir=${defaultSdk.absolutePath}\n")
        }
    }
}
