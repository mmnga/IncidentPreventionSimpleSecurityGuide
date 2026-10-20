plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("dev.flutter.flutter-gradle-plugin")
}
android {
    namespace = "invalid.atlas.notes"
    compileSdk = flutter.compileSdkVersion
    defaultConfig {
        applicationId = "invalid.atlas.notes"
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            // No debug-key fallback. Supply approved signing outside this fixture.
        }
    }
}
flutter { source = "../.." }
