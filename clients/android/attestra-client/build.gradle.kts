plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "dev.attestra.client"
    compileSdk = 37

    defaultConfig {
        minSdk = 23
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(libs.play.integrity)
    implementation(libs.coroutines.android)
    implementation(libs.coroutines.play.services)

    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
    // org.json is part of Android but only stubbed in JVM unit tests.
    testImplementation(libs.json)
}
