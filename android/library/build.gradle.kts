plugins {
    id("com.android.library")
    `maven-publish`
    signing
}

val sdkGroup = "cc.ace-base"
val sdkArtifact = "ace-id-android"
val sdkVersion = (findProperty("aceIdVersion") as String?) ?: "0.2.4"

group = sdkGroup
version = sdkVersion

android {
    namespace = "tab.aid.sdk"
    compileSdk = 36

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

dependencies {
    implementation("androidx.browser:browser:1.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    testImplementation("junit:junit:4.13.2")
    // Use the real JVM JSON implementation in local unit tests instead of Android's mocked stubs.
    testImplementation("org.json:json:20240303")
}

// Maven Central publication. Run `gradle publishReleasePublicationToCentralStagingRepository`
// to build a signed, checksummed bundle layout under build/central-staging.
afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = sdkGroup
                artifactId = sdkArtifact
                version = sdkVersion

                pom {
                    name.set("Ace ID Android SDK")
                    description.set("Android SDK for authenticating users with Ace ID via OpenID Connect (Authorization Code + PKCE).")
                    url.set("https://github.com/aceyash-dev/ace-id-sdk")
                    inceptionYear.set("2026")

                    licenses {
                        license {
                            name.set("MIT License")
                            url.set("https://opensource.org/licenses/MIT")
                            distribution.set("repo")
                        }
                    }
                    developers {
                        developer {
                            id.set("aceyash-dev")
                            name.set("Yash")
                            url.set("https://github.com/aceyash-dev")
                        }
                    }
                    scm {
                        url.set("https://github.com/aceyash-dev/ace-id-sdk")
                        connection.set("scm:git:https://github.com/aceyash-dev/ace-id-sdk.git")
                        developerConnection.set("scm:git:ssh://git@github.com/aceyash-dev/ace-id-sdk.git")
                    }
                    issueManagement {
                        system.set("GitHub Issues")
                        url.set("https://github.com/aceyash-dev/ace-id-sdk/issues")
                    }
                }
            }
        }

        repositories {
            maven {
                name = "CentralStaging"
                url = uri(layout.buildDirectory.dir("central-staging"))
            }
        }
    }

    signing {
        val key = providers.environmentVariable("SIGNING_KEY").orNull
        val password = providers.environmentVariable("SIGNING_PASSWORD").orNull
        // Sign only when a key is supplied (CI release); local builds and tests stay unsigned.
        isRequired = key != null
        if (key != null) {
            useInMemoryPgpKeys(key, password)
            sign(publishing.publications["release"])
        }
    }
}
