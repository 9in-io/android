plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "io.ninein.example"
    // Android 17 QPR1 (37.1): what the current Compose release compiles against.
    compileSdk {
        version = release(37) { minorApiLevel = 1 }
    }

    defaultConfig {
        applicationId = "io.ninein.example"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"

        // The redirect URI's scheme: io.ninein.example:/callback must be an allowed callback URL
        // (and an allowed logout URL) of the application in the 9in console.
        manifestPlaceholders["nineRedirectScheme"] = "io.ninein.example"

        // Point these at your tenant and application (or pass -PnineIssuer=… -PnineClientId=…).
        buildConfigField("String", "NINE_ISSUER", "\"${providers.gradleProperty("nineIssuer").getOrElse("https://acme.9in.io")}\"")
        buildConfigField("String", "NINE_CLIENT_ID", "\"${providers.gradleProperty("nineClientId").getOrElse("app_7f3k2m9q")}\"")
        buildConfigField("String", "NINE_REDIRECT_URI", "\"io.ninein.example:/callback\"")
    }

    buildTypes {
        release {
            // Shrunk like a real app, to check the SDK (and the Java core's rules) under R8.
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11
    }
}

dependencies {
    // In your app: implementation("com.github.9in-io:android:v0.1.0")
    implementation(project(":nine"))

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.material3)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.activity.compose)
}
