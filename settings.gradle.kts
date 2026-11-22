pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        google()
        mavenCentral()
        // The 9in Java SDK (com.github.9in-io:java), the protocol core this library is built on.
        maven("https://jitpack.io") { content { includeGroup("com.github.9in-io") } }
    }
}

rootProject.name = "nine-android"

// The library (published as com.github.9in-io:android) and the example app.
include(":nine")
include(":examples:app")
