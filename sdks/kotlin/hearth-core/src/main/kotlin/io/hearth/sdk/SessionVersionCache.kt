package io.hearth.sdk

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Configures the client-side session-version cache (RFC HEA-930 § 13).
 *
 * When a [SessionVersionCache] is active, it polls `GET /oauth/session-versions`
 * at [pollIntervalMs] intervals and applies delta entries to an in-memory
 * `{sessionId → minSv}` map. [SessionVersionCache.check] validates the `sv` claim
 * on access tokens without any per-request network hop.
 *
 * Recommended values: `staleThresholdMs = pollIntervalMs × 3`.
 */
data class SessionVersionConfig(
    /** How often to poll the delta feed, in milliseconds. */
    val pollIntervalMs: Long,
    /**
     * Maximum cache age before it is considered stale, in milliseconds.
     * Must be greater than [pollIntervalMs].
     */
    val staleThresholdMs: Long,
    /**
     * Action when the cache exceeds [staleThresholdMs]:
     * - `"reject"` — callers should treat as an authorization failure (fail-closed).
     * - `"introspect"` — callers should fall back to the introspection endpoint.
     */
    val onStale: String,
    /**
     * Service-to-service access token with `hearth.sv_feed` scope.
     * Required — sent as `Authorization: Bearer` on every poll request.
     */
    val serviceToken: String,
)

/** Outcome of a single [SessionVersionCache.check] call. */
enum class SvCheckResult {
    /** Session version is current; access is permitted. */
    OK,
    /** Token `sv` is below the server's `minSv` for this session; token was revoked. */
    REVOKED,
    /** Cache age exceeds [SessionVersionConfig.staleThresholdMs]; treat per `onStale`. */
    STALE,
    /** No `sv` claim in the token; skip validation (backward compatibility, RFC § 8.2). */
    SKIP,
}

// ── Private wire types ─────────────────────────────────────────────────────────

@Serializable
private data class SvSnapshotResponse(
    val realm: String,
    @SerialName("current_seq") val currentSeq: Long,
    val versions: Map<String, Long>,
)

@Serializable
private data class SvDeltaEntry(
    val seq: Long,
    @SerialName("session_id") val sessionId: String,
    @SerialName("min_sv") val minSv: Long,
    @SerialName("bumped_at") val bumpedAt: Long,
)

@Serializable
private data class SvDeltaResponse(
    val realm: String,
    @SerialName("next_seq") val nextSeq: Long,
    val deltas: List<SvDeltaEntry>,
)

/**
 * Client-side cache of per-session minimum accepted `sv` values.
 *
 * Polls `GET /oauth/session-versions/snapshot` once on [start], then polls
 * `GET /oauth/session-versions?since=N` at [SessionVersionConfig.pollIntervalMs]
 * intervals. Background poll errors are swallowed; the cache age grows and
 * eventually trips [SessionVersionConfig.staleThresholdMs] (fail-closed).
 *
 * Call [stop] when the client is no longer needed to release the coroutine.
 */
class SessionVersionCache(
    private val baseUrl: String,
    private val realmId: String,
    val cfg: SessionVersionConfig,
    httpTimeoutMs: Long = 10_000L,
) {
    private val httpClient: OkHttpClient = buildHttpClient(httpTimeoutMs)
    private val versions = ConcurrentHashMap<String, Long>()
    private val seq = AtomicLong(0)

    @Volatile
    private var lastRefreshedMs: Long = 0  // 0 = never seeded

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Starts the background poll loop: fetches the initial snapshot then polls
     * the delta feed at [SessionVersionConfig.pollIntervalMs] intervals.
     *
     * Snapshot and poll errors are swallowed — the cache age will trip the stale
     * threshold if the server is unreachable (fail-closed per § 8.1).
     */
    fun start() {
        scope.launch {
            try { fetchSnapshot() } catch (_: Exception) { }
            while (isActive) {
                delay(cfg.pollIntervalMs)
                try { poll() } catch (_: Exception) { }
            }
        }
    }

    /** Stops the background poll coroutine. Safe to call when [start] was never called. */
    fun stop() {
        scope.cancel()
    }

    /**
     * Returns milliseconds elapsed since the cache was last successfully refreshed.
     *
     * Returns [Long.MAX_VALUE] when the cache has never been seeded (i.e. before the
     * first successful [fetchSnapshot]). Use in health-check handlers to confirm freshness.
     */
    fun age(): Long =
        if (lastRefreshedMs == 0L) Long.MAX_VALUE
        else System.currentTimeMillis() - lastRefreshedMs

    /**
     * Validates the `sv` claim from an access token against the local cache.
     *
     * - [svPresent] = `false` → [SvCheckResult.SKIP] (no claim, backward compat).
     * - [age] > [SessionVersionConfig.staleThresholdMs] → [SvCheckResult.STALE].
     * - [sv] < `minSv` for [sessionId] → [SvCheckResult.REVOKED].
     * - [sv] >= `minSv` → [SvCheckResult.OK].
     *
     * Unknown session IDs default to `minSv = 1` (RFC § 3.2).
     */
    fun check(svPresent: Boolean, sv: Long, sessionId: String): SvCheckResult {
        if (!svPresent) return SvCheckResult.SKIP
        if (age() > cfg.staleThresholdMs) return SvCheckResult.STALE
        val minSv = versions[sessionId] ?: 1L
        return if (sv < minSv) SvCheckResult.REVOKED else SvCheckResult.OK
    }

    // ── Internal — exposed for testing ────────────────────────────────────────

    /** Fetches the full snapshot and rebuilds the local `{sessionId → minSv}` map. */
    internal suspend fun fetchSnapshot() {
        val url = "$baseUrl/oauth/session-versions/snapshot?realm=$realmId"
        val request = Request.Builder()
            .url(url)
            .get()
            .addHeader("Authorization", "Bearer ${cfg.serviceToken}")
            .build()
        httpClient.executeAsync(request).use { resp ->
            val body = resp.body?.string() ?: "{}"
            if (!resp.isSuccessful) {
                throw ApiError(resp.code, "SV snapshot failed: HTTP ${resp.code}")
            }
            val data = JSON.decodeFromString<SvSnapshotResponse>(body)
            versions.clear()
            data.versions.forEach { (sid, minSv) -> versions[sid] = minSv }
            seq.set(data.currentSeq)
            lastRefreshedMs = System.currentTimeMillis()
        }
    }

    /** Fetches delta entries since [seq] and merges them into the local map. */
    internal suspend fun poll() {
        val url = "$baseUrl/oauth/session-versions?since=${seq.get()}&realm=$realmId"
        val request = Request.Builder()
            .url(url)
            .get()
            .addHeader("Authorization", "Bearer ${cfg.serviceToken}")
            .build()
        httpClient.executeAsync(request).use { resp ->
            when (resp.code) {
                204 -> {
                    lastRefreshedMs = System.currentTimeMillis()
                }
                400 -> {
                    // Sequence predates retention window — re-seed from snapshot.
                    resp.body?.string()  // drain body
                    fetchSnapshot()
                }
                200 -> {
                    val body = resp.body?.string() ?: "{}"
                    val data = JSON.decodeFromString<SvDeltaResponse>(body)
                    data.deltas.forEach { versions[it.sessionId] = it.minSv }
                    seq.set(data.nextSeq)
                    lastRefreshedMs = System.currentTimeMillis()
                }
                else -> {
                    val body = resp.body?.string() ?: ""
                    throw ApiError(resp.code, "SV delta poll failed: HTTP ${resp.code}: $body")
                }
            }
        }
    }
}
