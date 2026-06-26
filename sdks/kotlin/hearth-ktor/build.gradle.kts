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
                scm {
                    url.set("https://github.com/hearth-auth/hearth")
                    connection.set("scm:git:git://github.com/hearth-auth/hearth.git")
                    developerConnection.set("scm:git:ssh://git@github.com/hearth-auth/hearth.git")
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
