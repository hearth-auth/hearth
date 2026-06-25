package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SessionVersionCacheTest {

    private lateinit var server: MockWebServer

    @BeforeTest
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterTest
    fun tearDown() {
        server.shutdown()
    }

    private val baseUrl get() = server.url("/").toString().trimEnd('/')

    private fun defaultConfig(serviceToken: String = "svc-token") = SessionVersionConfig(
        pollIntervalMs = 5_000L,
        staleThresholdMs = 30_000L,
        onStale = "reject",
        serviceToken = serviceToken,
    )

    @Test
    fun `age returns very large value before first fetch`() {
        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        // Never seeded → age should signal "infinite" staleness
        assertTrue(cache.age() > 100_000L, "expected large age before seeding, got ${cache.age()}")
    }

    @Test
    fun `check returns SKIP when svPresent is false`() {
        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        assertEquals(SvCheckResult.SKIP, cache.check(svPresent = false, sv = 5L, sessionId = "sid-1"))
    }

    @Test
    fun `check returns STALE when cache age exceeds staleThresholdMs`() {
        val cache = SessionVersionCache(
            baseUrl,
            "realm-1",
            SessionVersionConfig(
                pollIntervalMs = 5_000L,
                staleThresholdMs = 1L,  // 1 ms → instantly stale
                onStale = "reject",
                serviceToken = "tok",
            ),
        )
        Thread.sleep(5) // outlast the 1ms threshold
        assertEquals(SvCheckResult.STALE, cache.check(svPresent = true, sv = 1L, sessionId = "sid-1"))
    }

    @Test
    fun `check returns OK when sv meets minSv`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"realm":"r","current_seq":5,"versions":{"sid-1":2}}""")
                .setResponseCode(200)
        )

        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        cache.fetchSnapshot()

        // sv=3 >= minSV=2 → OK
        assertEquals(SvCheckResult.OK, cache.check(svPresent = true, sv = 3L, sessionId = "sid-1"))
    }

    @Test
    fun `check returns OK when sv exactly equals minSv`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"realm":"r","current_seq":1,"versions":{"sid-1":4}}""")
                .setResponseCode(200)
        )

        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        cache.fetchSnapshot()

        // sv=4 == minSV=4 → OK
        assertEquals(SvCheckResult.OK, cache.check(svPresent = true, sv = 4L, sessionId = "sid-1"))
    }

    @Test
    fun `check returns REVOKED when sv is below minSv`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"realm":"r","current_seq":5,"versions":{"sid-1":5}}""")
                .setResponseCode(200)
        )

        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        cache.fetchSnapshot()

        // sv=3 < minSV=5 → REVOKED
        assertEquals(SvCheckResult.REVOKED, cache.check(svPresent = true, sv = 3L, sessionId = "sid-1"))
    }

    @Test
    fun `check defaults to minSv 1 for unknown session`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"realm":"r","current_seq":1,"versions":{}}""")
                .setResponseCode(200)
        )

        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        cache.fetchSnapshot()

        // unknown session → minSV defaults to 1
        assertEquals(SvCheckResult.OK, cache.check(svPresent = true, sv = 1L, sessionId = "unknown"))
        assertEquals(SvCheckResult.REVOKED, cache.check(svPresent = true, sv = 0L, sessionId = "unknown"))
    }

    @Test
    fun `fetchSnapshot sends Authorization header`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"realm":"r","current_seq":1,"versions":{}}""")
                .setResponseCode(200)
        )

        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig("my-svc-token"))
        cache.fetchSnapshot()

        val req = server.takeRequest()
        assertEquals("Bearer my-svc-token", req.getHeader("Authorization"))
    }

    @Test
    fun `fetchSnapshot hits the correct path`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"realm":"r","current_seq":1,"versions":{}}""")
                .setResponseCode(200)
        )

        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        cache.fetchSnapshot()

        val req = server.takeRequest()
        assertTrue(req.path!!.contains("/oauth/session-versions/snapshot"), "path was: ${req.path}")
        assertTrue(req.path!!.contains("realm=realm-1"), "missing realm param: ${req.path}")
    }

    @Test
    fun `poll applies delta updates from server`() = runTest {
        // Seed with sid-1 minSv=1
        server.enqueue(
            MockResponse()
                .setBody("""{"realm":"r","current_seq":1,"versions":{"sid-1":1}}""")
                .setResponseCode(200)
        )
        // Delta bumps sid-1 to minSv=3
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"realm":"r","next_seq":2,"deltas":[{"seq":2,"session_id":"sid-1","min_sv":3,"bumped_at":1000}]}"""
                )
                .setResponseCode(200)
        )

        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        cache.fetchSnapshot()
        cache.poll()

        // After delta, sv=2 < minSV=3 → REVOKED
        assertEquals(SvCheckResult.REVOKED, cache.check(svPresent = true, sv = 2L, sessionId = "sid-1"))
        // sv=3 == minSV=3 → OK
        assertEquals(SvCheckResult.OK, cache.check(svPresent = true, sv = 3L, sessionId = "sid-1"))
    }

    @Test
    fun `poll treats 204 as no-op and updates lastRefreshed`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"realm":"r","current_seq":1,"versions":{}}""")
                .setResponseCode(200)
        )
        server.enqueue(MockResponse().setResponseCode(204))

        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        cache.fetchSnapshot()

        Thread.sleep(60) // let age grow past the 204 check threshold
        assertTrue(cache.age() >= 50L, "sanity: age should have grown")

        cache.poll() // 204 → resets lastRefreshedMs
        // After a 204, the cache was just refreshed so age should be very small
        assertTrue(cache.age() < 50L, "age should be reset after 204 poll, was ${cache.age()}")
    }

    @Test
    fun `start and stop do not throw`() {
        val cache = SessionVersionCache(baseUrl, "realm-1", defaultConfig())
        cache.start()
        Thread.sleep(20)
        cache.stop()
    }
}
