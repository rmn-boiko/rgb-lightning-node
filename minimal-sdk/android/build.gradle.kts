// Android packaging of the minimal SDK core (minimal-sdk/rust-sdk).
//
// Conventions follow bindings/kotlin-android-sdk/build.gradle.kts (AGP 8.7.3,
// Kotlin 1.9.24, JDK 17, compileSdk 34, minSdk 24, consumerProguardFiles,
// singleVariant("release")) without its uniffi-node source wiring and
// without JReleaser: nothing is published from this project.
//
// Inputs, both produced by scripts under ../scripts and gitignored here:
//   generated/kotlin   uniffi Kotlin bindings (library mode, no UDL)
//   generated/jniLibs  <abi>/libutexo_minimal_sdk.so for the three ABIs
// The JVM unit tests load the HOST release cdylib through JNA instead of the
// Android .so files, so `./gradlew test` needs cargo and no NDK.

plugins {
    id("com.android.library") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "1.9.24"
}

group = "com.utexo"
version = "0.1.0"

val rustSdkDir = layout.projectDirectory.dir("../rust-sdk")
val scriptsDir = layout.projectDirectory.dir("../scripts")
val generatedKotlinDir = layout.projectDirectory.dir("generated/kotlin")
val generatedJniLibsDir = layout.projectDirectory.dir("generated/jniLibs")
val hostReleaseDir = rustSdkDir.dir("target/release")
// The rgb-lib-authored parity fixture, read by RELATIVE path from the
// TypeScript client SDK. Never copied, never regenerated here.
val parityFixture =
    layout.projectDirectory.file("../packages/client-sdk/test/fixtures/rgblib-parity.json")

dependencies {
    // uniffi's Kotlin bindings talk to the Rust library through JNA. This is
    // the library's only dependency.
    api("net.java.dev.jna:jna:5.14.0@aar")

    // Test-only: the plain JNA jar carries the host (linux/mac x86_64, arm64)
    // jnidispatch the AAR lacks, so JVM unit tests can load the host cdylib.
    testImplementation("net.java.dev.jna:jna:5.14.0")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:1.9.24")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}

android {
    namespace = "com.utexo.minimalsdk"
    compileSdk = 34

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    // ABI splits. The AAR itself always carries all three slices; what makes
    // a consumer download ONE .so is the app shipping as an App Bundle (Play
    // serves the device's ABI) or configuring the same splits on the app.
    // Declaring them here documents the supported set and keeps the AAR from
    // ever carrying a stray ABI.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = false
        }
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDir(generatedKotlinDir)
            jniLibs.srcDir(generatedJniLibsDir)
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    testOptions {
        unitTests.all { test ->
            // JNA resolves "utexo_minimal_sdk" against the host release build.
            test.systemProperty("jna.library.path", hostReleaseDir.asFile.absolutePath)
            test.systemProperty("utexo.minimalsdk.fixture", parityFixture.asFile.absolutePath)
            test.systemProperty(
                "utexo.minimalsdk.consumerRules",
                layout.projectDirectory.file("consumer-rules.pro").asFile.absolutePath,
            )
            test.testLogging {
                events("passed", "failed", "skipped")
                showStandardStreams = true
            }
        }
    }
}

// ---- Rust build steps, wired so `./gradlew test` and `./gradlew assemble`
// ---- are self-contained on a clean checkout.

val rustSources = fileTree(rustSdkDir.dir("src")) + files(rustSdkDir.file("Cargo.toml"), rustSdkDir.file("Cargo.lock"))

// Host release cdylib for the JVM unit tests (same profile the Rust size
// gate measures).
val buildHostLibrary by tasks.registering(Exec::class) {
    description = "cargo build --release --lib of the minimal SDK core for the host"
    group = "rust"
    workingDir = rustSdkDir.asFile
    commandLine("cargo", "build", "--release", "--lib")
    // Always run: cargo is incremental itself, and Gradle's own up-to-date
    // check would need inputs/outputs it cannot see (the cargo target dir).
    outputs.upToDateWhen { false }
}

val generateKotlinBindings by tasks.registering(Exec::class) {
    description = "uniffi library-mode Kotlin bindings into generated/kotlin"
    group = "rust"
    commandLine("bash", scriptsDir.file("generate_bindings.sh").asFile.absolutePath, "kotlin", generatedKotlinDir.asFile.absolutePath)
    inputs.files(rustSources)
    inputs.file(rustSdkDir.file("uniffi.toml"))
    outputs.dir(generatedKotlinDir)
}

val buildAndroidJniLibs by tasks.registering(Exec::class) {
    description = "cargo ndk for arm64-v8a, armeabi-v7a, x86_64 plus the 16 KB alignment, export and size gates"
    group = "rust"
    commandLine("bash", scriptsDir.file("build_android.sh").asFile.absolutePath, generatedJniLibsDir.asFile.absolutePath)
    inputs.files(rustSources)
    outputs.dir(generatedJniLibsDir)
}

val checkAndroidJniLibs by tasks.registering(Exec::class) {
    description = "Re-run the 16 KB alignment, export and arm64 size gates on generated/jniLibs"
    group = "verification"
    dependsOn(buildAndroidJniLibs)
    commandLine("bash", scriptsDir.file("build_android.sh").asFile.absolutePath, "--check-only", generatedJniLibsDir.asFile.absolutePath)
}

tasks.named("preBuild") {
    dependsOn(generateKotlinBindings)
}

// The .so files are only needed when the AAR is packaged, not for unit tests.
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }.configureEach {
    dependsOn(buildAndroidJniLibs)
}
tasks.matching { it.name.startsWith("bundle") && it.name.endsWith("Aar") }.configureEach {
    dependsOn(checkAndroidJniLibs)
}

tasks.withType<Test>().configureEach {
    dependsOn(buildHostLibrary)
}
