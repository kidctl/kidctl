import java.io.File
import java.util.Properties

plugins {
    id("com.android.application")
}

// versionCode/versionName: agent/version.properties (bumped by scripts/release-agent.sh).
// `-Pkidctl.versionCode=N` overrides the code (e2e builds of v+1 without touching the file).
val versionProps = Properties().apply { rootProject.file("version.properties").inputStream().use { load(it) } }
val kidctlVersionCode = providers.gradleProperty("kidctl.versionCode").orNull?.toInt()
    ?: versionProps.getProperty("versionCode").toInt()

android {
    namespace = "io.github.kidctl.agent"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.kidctl.agent"
        minSdk = 33
        targetSdk = 37
        versionCode = kidctlVersionCode
        versionName = versionProps.getProperty("versionName")
    }

    // Release signing: ~/.config/kidctl/signing.properties (storeFile, storePassword,
    // keyAlias, keyPassword). A device-owner app can only be updated with the
    // SAME key, so this keystore must be kept (and backed up) forever.
    val signingProps = File(System.getProperty("user.home"), ".config/kidctl/signing.properties")
    signingConfigs {
        if (signingProps.exists()) {
            val p = Properties().apply { signingProps.inputStream().use { load(it) } }
            create("release") {
                storeFile = file(p.getProperty("storeFile"))
                storePassword = p.getProperty("storePassword")
                keyAlias = p.getProperty("keyAlias")
                keyPassword = p.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    sourceSets["test"].resources.srcDir("../../spec")
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
}
