plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    `java-library`
    `maven-publish`
    signing
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Kotlin coroutines
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // JSON serialization
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    // JWT + JWKS verification (nimbus-jose-jwt is the JVM standard)
    api("com.nimbusds:nimbus-jose-jwt:9.41.2")

    // Google Tink: required at runtime for EdDSA (OKP/Ed25519) sign + verify.
    // nimbus-jose-jwt declares it as <optional> so consumers must add it explicitly.
    implementation("com.google.crypto.tink:tink:1.14.1")

    // OkHttp for HTTP transport (coroutine-compatible via suspendCoroutine bridge)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // SLF4J for logging (implementation detail, not exposed)
    implementation("org.slf4j:slf4j-api:2.0.13")

    // Test dependencies
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("io.mockk:mockk:1.13.12")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.slf4j:slf4j-simple:2.0.13")
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "hearth-core"
            from(components["java"])
            pom {
                name.set("Hearth Core SDK")
                description.set("Official Kotlin/JVM SDK for Hearth identity server")
                url.set("https://github.com/hearth-auth/hearth")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                // Maven Central REQUIRES a developers block; a deployment
                // without one is rejected at validation (task 26.53).
                developers {
                    developer {
                        id.set("hearth-auth")
                        name.set("Hearth maintainers")
                        url.set("https://github.com/hearth-auth")
                    }
                }
                scm {
                    url.set("https://github.com/hearth-auth/hearth")
                    connection.set("scm:git:git://github.com/hearth-auth/hearth.git")
                    developerConnection.set("scm:git:ssh://git@github.com/hearth-auth/hearth.git")
                }
            }
        }
    }

    // Task 26.53 — WITHOUT THIS BLOCK, `gradle publish` SUCCEEDS AND PUBLISHES
    // NOTHING.
    //
    // The publication above was declared with no repository to publish it to.
    // Gradle's `publish` task then has zero targets, does no work, and exits 0.
    // So 43 `sdk-kotlin-v*` tags produced 43 green workflow runs and zero
    // artifacts, `io.hearth` is absent from Maven Central (group 404), and the
    // `ossrhUsername`/`ossrhPassword` properties the workflow passes in were
    // read by nothing.
    //
    // Credentials come from `ORG_GRADLE_PROJECT_ossrhUsername` /
    // `ORG_GRADLE_PROJECT_ossrhPassword`. When they are absent — a local build,
    // or a dry-run — the repository is not declared at all, so `publish` still
    // has nothing to do rather than failing on missing credentials. That is why
    // the workflow must ALSO assert an artifact was produced: see
    // `.github/workflows/sdk-publish-kotlin.yml`.
    repositories {
        val ossrhUsername: String? by project
        val ossrhPassword: String? by project
        if (ossrhUsername != null && ossrhPassword != null) {
            maven {
                name = "ossrh"
                url = uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
                credentials {
                    username = ossrhUsername
                    password = ossrhPassword
                }
            }
        }
    }
}

signing {
    // signingKey is an in-memory ASCII-armored PGP private key injected at release time.
    // When absent (dry-run / publishToMavenLocal), signing is skipped entirely.
    val signingKey: String? by project
    val signingPassword: String? by project
    if (signingKey != null) {
        useInMemoryPgpKeys(signingKey, signingPassword ?: "")
    }
    isRequired = signingKey != null
    sign(publishing.publications["maven"])
}
