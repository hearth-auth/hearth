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

    // SLF4J binding for test output
    testImplementation("org.slf4j:slf4j-simple:2.0.13")
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
