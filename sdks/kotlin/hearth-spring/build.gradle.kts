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

val springBootVersion = "3.3.4"
val springSecurityVersion = "6.3.3"

dependencies {
    // Hearth core SDK (transitively brings coroutines, nimbus-jose-jwt, OkHttp)
    api(project(":hearth-core"))

    // Spring Security — compileOnly so consumers control the Spring version
    compileOnly("org.springframework.security:spring-security-web:$springSecurityVersion")
    compileOnly("org.springframework.security:spring-security-config:$springSecurityVersion")

    // Spring Boot auto-configuration support — compileOnly
    compileOnly("org.springframework.boot:spring-boot-autoconfigure:$springBootVersion")

    // Jakarta Servlet API (Spring Boot 3 / Jakarta EE 10)
    compileOnly("jakarta.servlet:jakarta.servlet-api:6.0.0")

    // SLF4J for filter-level debug logging (provided by Spring Boot at runtime)
    implementation("org.slf4j:slf4j-api:2.0.13")

    // ── Test dependencies ──────────────────────────────────────────────────────

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")

    // MockK for idiomatic Kotlin mocking (suspend-function support)
    testImplementation("io.mockk:mockk:1.13.12")

    // Spring Boot Test (MockMvc, @SpringBootTest, ApplicationContextRunner)
    testImplementation("org.springframework.boot:spring-boot-starter-test:$springBootVersion")
    testImplementation("org.springframework.security:spring-security-test:$springSecurityVersion")

    // Bring in a real web + security stack for integration tests
    testImplementation("org.springframework.boot:spring-boot-starter-web:$springBootVersion")
    testImplementation("org.springframework.boot:spring-boot-starter-security:$springBootVersion")

    // No slf4j-simple here on purpose: spring-boot-starter-test and
    // spring-boot-starter-web both pull logback-classic, and Spring Boot's
    // LoggingApplicationListener aborts context startup with
    // "LoggerFactory is not a Logback LoggerContext but Logback is on the
    // classpath" when a second binding wins the service lookup. That is what
    // made every @SpringBootTest in this module fail (audit 2026-08-28 §25.8).
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "hearth-spring"
            from(components["java"])
            pom {
                name.set("Hearth Spring Security Adapter")
                description.set("Spring Security filter and auto-configuration for Hearth JWT authentication")
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
    // logged `:hearth-spring:publish UP-TO-DATE` and shipped nothing. Declared
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
