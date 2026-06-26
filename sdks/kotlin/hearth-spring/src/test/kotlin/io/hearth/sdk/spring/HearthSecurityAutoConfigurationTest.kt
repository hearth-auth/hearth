package io.hearth.sdk.spring

import io.hearth.sdk.HearthClient
import io.mockk.mockk
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.WebApplicationContextRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HearthSecurityAutoConfigurationTest {

    private val contextRunner = WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(HearthSecurityAutoConfiguration::class.java))

    // ── Activation ─────────────────────────────────────────────────────────────

    @Test
    fun `auto-configuration is inactive without issuer-url`() {
        contextRunner.run { ctx ->
            assertFalse(ctx.containsBean("hearthClient"))
            assertFalse(ctx.containsBean("hearthJwtAuthenticationFilter"))
        }
    }

    @Test
    fun `auto-configuration creates HearthClient and filter when issuer-url is set`() {
        contextRunner
            .withPropertyValues("hearth.issuer-url=https://auth.example.com")
            .run { ctx ->
                assertNotNull(ctx.getBean(HearthClient::class.java))
                assertNotNull(ctx.getBean(HearthJwtAuthenticationFilter::class.java))
            }
    }

    // ── HearthClient properties ────────────────────────────────────────────────

    @Test
    fun `HearthClient uses issuer-url from properties`() {
        contextRunner
            .withPropertyValues("hearth.issuer-url=https://id.example.org")
            .run { ctx ->
                val client = ctx.getBean(HearthClient::class.java)
                assertEquals("https://id.example.org", client.issuerUrl)
            }
    }

    @Test
    fun `HearthClient uses clientId from properties`() {
        contextRunner
            .withPropertyValues(
                "hearth.issuer-url=https://auth.example.com",
                "hearth.client-id=my-app",
            )
            .run { ctx ->
                val client = ctx.getBean(HearthClient::class.java)
                assertEquals("my-app", client.clientId)
            }
    }

    @Test
    fun `HearthClient has null clientId when not set`() {
        contextRunner
            .withPropertyValues("hearth.issuer-url=https://auth.example.com")
            .run { ctx ->
                val client = ctx.getBean(HearthClient::class.java)
                assertNull(client.clientId)
            }
    }

    @Test
    fun `HearthClient uses realmId from properties`() {
        contextRunner
            .withPropertyValues(
                "hearth.issuer-url=https://auth.example.com",
                "hearth.realm-id=my-realm",
            )
            .run { ctx ->
                val client = ctx.getBean(HearthClient::class.java)
                assertEquals("my-realm", client.realmId)
            }
    }

    // ── Bean overrides ─────────────────────────────────────────────────────────

    @Test
    fun `user-provided HearthClient bean takes precedence — only one HearthClient exists`() {
        contextRunner
            .withPropertyValues("hearth.issuer-url=https://auth.example.com")
            .withUserConfiguration(CustomClientConfig::class.java)
            .run { ctx ->
                // @ConditionalOnMissingBean prevents a second HearthClient from being created.
                assertEquals(1, ctx.getBeanNamesForType(HearthClient::class.java).size)
            }
    }

    @Test
    fun `user-provided filter bean takes precedence — only one filter exists`() {
        contextRunner
            .withPropertyValues("hearth.issuer-url=https://auth.example.com")
            .withUserConfiguration(CustomFilterConfig::class.java)
            .run { ctx ->
                // @ConditionalOnMissingBean prevents a second filter from being created.
                assertEquals(1, ctx.getBeanNamesForType(HearthJwtAuthenticationFilter::class.java).size)
            }
    }

    // ── Support configurations ─────────────────────────────────────────────────

    @Configuration
    class CustomClientConfig {
        @Bean
        fun hearthClient(): HearthClient = mockk()
    }

    @Configuration
    class CustomFilterConfig {
        @Bean
        fun hearthJwtAuthenticationFilter(): HearthJwtAuthenticationFilter =
            HearthJwtAuthenticationFilter(mockk())
    }
}
