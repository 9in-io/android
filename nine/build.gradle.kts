import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

// JitPack passes the tag as VERSION; local builds publish 0.1.0.
val sdkVersion: String = providers.environmentVariable("VERSION").getOrElse("0.1.0")
group = "com.github.9in-io"
version = sdkVersion

android {
    namespace = "io.ninein.android"
    compileSdk = 37

    defaultConfig {
        minSdk = 26 // the Java core uses java.time and java.util.Base64
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Apps may compile against any SDK from 34 (what androidx.browser needs), not only 37.
        aarMetadata { minCompileSdk = 34 }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            all { test ->
                // Live end-to-end tests are opt-in: NINE_E2E=1 (settings from NINE_E2E_ENV or E2E_* variables).
                for (name in listOf("NINE_E2E", "NINE_E2E_ENV")) System.getenv(name)?.let { test.environment(name, it) }
                System.getenv().filterKeys { it.startsWith("E2E_") }.forEach { (k, v) -> test.environment(k, v) }
                if (System.getenv("NINE_E2E") == "1") test.outputs.upToDateWhen { false }
                test.testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
            }
        }
    }

    // The fake 9in server and test keys are used by both the JVM and the device tests.
    sourceSets {
        getByName("test").kotlin.directories.add("src/sharedTest/kotlin")
        getByName("androidTest").kotlin.directories.add("src/sharedTest/kotlin")
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

// The library's own tests need a redirect scheme; the published manifest keeps
// ${nineRedirectScheme} for apps to set.
androidComponents {
    onVariants { variant ->
        variant.hostTests.values.forEach { it.manifestPlaceholders.put("nineRedirectScheme", "io.ninein.android.test") }
        variant.deviceTests.values.forEach { it.manifestPlaceholders.put("nineRedirectScheme", "io.ninein.android.test") }
    }
}

kotlin {
    explicitApi()
    // Readable by Kotlin 2.0+ apps.
    coreLibrariesVersion = "2.0.21"
    compilerOptions {
        jvmTarget = JvmTarget.JVM_11
        languageVersion = KotlinVersion.KOTLIN_2_0
        apiVersion = KotlinVersion.KOTLIN_2_0
    }
}

dependencies {
    api(libs.nine.java) // io.ninein.AuthClient: the protocol (discovery, PKCE, checks, tokens)
    api(libs.kotlinx.coroutines.android)
    api(libs.androidx.browser) // CustomTabsBrowser takes a CustomTabsIntent.Builder customisation

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.androidx.test.ext.junit)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.github.9in-io"
            artifactId = "android"
            version = sdkVersion
            afterEvaluate { from(components["release"]) }
            pom {
                name = "9in Android SDK"
                description = "Official Android SDK for 9in: sign-in with PKCE in Custom Tabs, Keystore-encrypted tokens, refresh token rotation and sign-out."
                url = "https://github.com/9in-io/android"
                licenses {
                    license {
                        name = "The MIT License"
                        url = "https://opensource.org/licenses/MIT"
                    }
                }
                organization {
                    name = "Cubelet Ltd"
                    url = "https://cubelet.co.uk"
                }
                scm {
                    url = "https://github.com/9in-io/android"
                    connection = "scm:git:https://github.com/9in-io/android.git"
                }
            }
        }
    }
}
