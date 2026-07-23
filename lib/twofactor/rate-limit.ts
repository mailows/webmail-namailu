/**
 * Best-effort brute-force guard for TOTP verification (login gate + enrollment
 * re-auth).
 *
 * ⚠️ LIMITATION: this state is PER-PROCESS and IN-MEMORY only. It is NOT shared
 * across multiple workers / replicas and it resets on restart. It raises the
 * cost of online TOTP guessing for the common single-process deployment, but a
 * horizontally-scaled deployment would need a shared store (e.g. Redis) to make
 * the limit global. Tracked as a follow-up (M3) in FORK.md.
 *
 * Policy: after MAX_FAILURES wrong codes within WINDOW_MS for the same account,
 * lock that account's TOTP verification for LOCKOUT_MS. A success clears the
 * counter. With 6-digit codes and a ±1 step window, 5 tries per 15 min keeps
 * the online guessing probability negligible.
 */

const MAX_FAILURES = 5;
const WINDOW_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;

interface Entry {
  failures: number;
  firstAt: number;
  lockedUntil: number;
}

const attempts = new Map<string, Entry>();

/** Stable per-account key. Not identity-canonical, but stable per login route. */
export function totpRateLimitKey(serverUrl: string, username: string): string {
  return `${serverUrl}|${username}`;
}

/** True when this account is currently locked out from TOTP verification. */
export function isTotpLocked(key: string): boolean {
  const entry = attempts.get(key);
  if (!entry) return false;
  if (entry.lockedUntil > Date.now()) return true;
  // Lock (and stale window) expired — drop the entry so counting restarts fresh.
  if (entry.lockedUntil !== 0 && entry.lockedUntil <= Date.now()) {
    attempts.delete(key);
  }
  return false;
}

/** Record a failed TOTP attempt; may transition the account into a lockout. */
export function recordTotpFailure(key: string): void {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || now - entry.firstAt > WINDOW_MS) {
    attempts.set(key, { failures: 1, firstAt: now, lockedUntil: 0 });
    return;
  }
  entry.failures += 1;
  if (entry.failures >= MAX_FAILURES) {
    entry.lockedUntil = now + LOCKOUT_MS;
  }
}

/** Clear the failure counter after a successful verification. */
export function clearTotpFailures(key: string): void {
  attempts.delete(key);
}
