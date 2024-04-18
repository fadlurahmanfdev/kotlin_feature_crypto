plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
}

android {
    namespace = "co.id.fadlurahmanf.core_crypto"
    compileSdk = 34

    defaultConfig {
        applicationId = "co.id.fadlurahmanf.core_crypto"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

//    buildFeatures {
//        buildConfig = true
//        viewBinding = true
//    }

//    flavorDimensions.add("environment")
//
//    productFlavors {
//        create("fake") {
//            dimension = "environment"
//            applicationIdSuffix = ".fake"
//        }
//
//        create("dev") {
//            dimension = "environment"
//            applicationIdSuffix = ".dev"
//        }
//
//        create("staging") {
//            dimension = "environment"
//            applicationIdSuffix = ".staging"
//        }
//
//        create("prod") {
//            dimension = "environment"
//        }
//    }
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}