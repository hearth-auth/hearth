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

// Maven Central rejects a deployment without -sources and -javadoc jars
// (GA audit: the Kotlin SDK has never reached Maven Central). Kotlin sources
// yield a near-empty javadoc jar, which Central accepts.
java {
    withSourcesJar()
    withJavadocJar()
}

val ktorVersion = "2.3.12"

dependencies {
    // Hearth core SDK (transitively brings coroutines, nimbus-jose-jwt, OkHttp)
    api(project(":hearth-core"))

    // Ktor server auth — compileOnly so consumers control the Ktor version
    compileOnly("io.ktor:ktor-server-auth:$ktorVersion")
    compileOnly("io.ktor:ktor-server-core:$ktorVersion")

    // SLF4J for debug logging (provided by the consumer's Ktor server at runtime)
    implementation("org.slf4j:slf4j-api:2.0.13")

    // ── Test dependencies ──────────────────────────────────────────────────────

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")

    // MockK for idiomatic Kotlin mocking (suspend-function support)
    testImplementation("io.mockk:mockk:1.13.12")

    // Ktor test host + real auth stack
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
    testImplementation("io.ktor:ktor-server-auth:$ktorVersion")
    testImplementation("io.ktor:ktor-server-core:$ktorVersion")

    // SLF4J binding for test output
    testImplementation("org.slf4j:slf4j-simple:2.0.13")
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "hearth-ktor"
            from(components["java"])
            pom {
                name.set("Hearth Ktor Auth Plugin")
                description.set("Ktor authentication provider for Hearth JWT bearer tokens")
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

    // Same OSSRH target as hearth-core (task 26.53): without a repository
    // `gradle publish` is a silent no-op for this module — the v1.6.11 tag run
    // logged `:hearth-ktor:publish UP-TO-DATE` and shipped nothing. Declared
    // only when credentials are present, so local builds stay offline.
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
    val signingKey: String? by project
    val signingPassword: String? by project
    if (signingKey != null) {
        useInMemoryPgpKeys(signingKey, signingPassword ?: "")
    }
    isRequired = signingKey != null
    sign(publishing.publications["maven"])
}
