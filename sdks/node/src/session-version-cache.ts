/**
 * §8 — Managed session-version cache (C-20, RFC HEA-930).
 *
 * Brings the Node SDK to parity with the TS/Go/Kotlin managed caches: instead of
 * forcing callers to poll `svSnapshot`/`svDelta` by hand, this class owns a
 * background poll loop and an in-memory `Map<sessionId, bigint>`, and exposes a
 * zero-network `validateSv()` for the request hot path.
 *
 * Node is a resource server — it is the SDK that actually enforces revocation in
 * middleware — so the managed facade belongs here.
 */

import {
  SessionVersionCacheStaleError,
  SessionVersionRevokedError,
} from "./errors.js";

/** Configuration for the managed {@link SessionVersionCache}. */
export interface SessionVersionConfig {
  /** Whether session-version validation is enabled. */
  enabled: boolean;
  /** Delta feed poll interval in milliseconds. Recommended: 5_000. */
  pollIntervalMs: number;
  /**
   * Maximum cache age before it is considered stale, in milliseconds.
   * MUST be greater than `pollIntervalMs`. Recommended: `pollIntervalMs × 3`.
   */
  staleThresholdMs: number;
  /**
   * Action when the cache exceeds `staleThresholdMs`:
   * - `"reject"` — throw {@link SessionVersionCacheStaleError} (fail-closed).
   * - `"introspect"` — caller catches it and falls back to introspection.
   */
  onStale: "reject" | "introspect";
  /** Service token with `hearth.sv_feed` scope. Required when `enabled` is true. */
  serviceToken: string;
}

interface SnapshotResponse {
  realm: string;
  current_seq: number;
  versions: Record<string, number>;
}

interface DeltaEntry {
  seq: number;
  session_id: string;
  min_sv: number;
  bumped_at?: number;
}

interface DeltaFeedResponse {
  realm: string;
  next_seq: number;
  deltas: DeltaEntry[];
}

/**
 * Client-side cache of per-session minimum accepted `sv` values.
 *
 * Polls `GET /oauth/session-versions` at `cfg.pollIntervalMs` and applies delta
 * entries to an in-memory map. Background poll errors are swallowed; the cache
 * age then grows and eventually trips the stale threshold (fail-closed, §8.1).
 */
export class SessionVersionCache {
  private readonly baseUrl: string;
  private readonly realmId: string;
  private readonly cfg: SessionVersionConfig;
  private readonly versions = new Map<string, bigint>();
  private lastRefreshed = 0;
  private seq = 0;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(baseUrl: string, realmId: string, cfg: SessionVersionConfig) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.realmId = realmId;
    this.cfg = cfg;
  }

  /**
   * Kicks off the initial snapshot fetch (async, non-blocking) and starts the
   * background poll loop. Call once after construction.
   */
  start(): void {
    if (this.cfg.staleThresholdMs <= this.cfg.pollIntervalMs) {
      console.warn(
        "[hearth] sessionVersions.staleThresholdMs must be > pollIntervalMs " +
          `(stale=${this.cfg.staleThresholdMs}ms, poll=${this.cfg.pollIntervalMs}ms). ` +
          "Recommended: staleThresholdMs = pollIntervalMs × 3.",
      );
    }
    void this.fetchSnapshot().catch(() => undefined);
    this.schedulePoll();
  }

  /** Stops the background poll timer. Call when disposing the cache. */
  stop(): void {
    if (this.pollTimer !== null) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }

  /** Returns milliseconds since the cache was last successfully refreshed. */
  age(): number {
    if (this.lastRefreshed === 0) return Number.POSITIVE_INFINITY;
    return Date.now() - this.lastRefreshed;
  }

  /**
   * Validates the `sv` claim against the local cache.
   *
   * - Absent `sv` or absent `sessionId` → no-op (backward compat, §8.2).
   * - Cache age > `staleThresholdMs` → throws {@link SessionVersionCacheStaleError}.
   * - `sv < minSv` → throws {@link SessionVersionRevokedError}.
   */
  validateSv(sv: bigint | undefined, sessionId: string | undefined): void {
    if (sv === undefined || sessionId === undefined) return;

    const ageMs = this.age();
    if (ageMs > this.cfg.staleThresholdMs) {
      throw new SessionVersionCacheStaleError(
        Number.isFinite(ageMs) ? ageMs : -1,
        this.cfg.onStale,
      );
    }

    const minSv = this.versions.get(sessionId) ?? 1n;
    if (sv < minSv) {
      throw new SessionVersionRevokedError(sessionId, sv, minSv);
    }
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private async fetchSnapshot(): Promise<void> {
    const url = `${this.baseUrl}/oauth/session-versions/snapshot?realm=${encodeURIComponent(this.realmId)}`;
    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${this.cfg.serviceToken}` },
    });
    if (!resp.ok) {
      throw new Error(`SV snapshot fetch failed: HTTP ${resp.status}`);
    }
    const data = (await resp.json()) as SnapshotResponse;
    this.versions.clear();
    for (const [sid, minSv] of Object.entries(data.versions)) {
      this.versions.set(sid, BigInt(minSv));
    }
    this.seq = data.current_seq;
    this.lastRefreshed = Date.now();
  }

  private schedulePoll(): void {
    this.pollTimer = setTimeout(() => {
      void this.poll()
        .catch(() => undefined)
        .finally(() => this.schedulePoll());
    }, this.cfg.pollIntervalMs);
  }

  private async poll(): Promise<void> {
    const url =
      `${this.baseUrl}/oauth/session-versions?since=${this.seq}` +
      `&realm=${encodeURIComponent(this.realmId)}`;
    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${this.cfg.serviceToken}` },
    });
    if (resp.status === 204) {
      this.lastRefreshed = Date.now();
      return;
    }
    if (resp.status === 400) {
      // Sequence predates retention window — re-seed from snapshot.
      await this.fetchSnapshot();
      return;
    }
    if (!resp.ok) {
      throw new Error(`SV delta poll failed: HTTP ${resp.status}`);
    }
    const data = (await resp.json()) as DeltaFeedResponse;
    for (const delta of data.deltas) {
      this.versions.set(delta.session_id, BigInt(delta.min_sv));
    }
    this.seq = data.next_seq;
    this.lastRefreshed = Date.now();
  }
}
