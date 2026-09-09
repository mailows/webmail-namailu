import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

// Block telemetry endpoints from pointing at internal/loopback addresses.
// Required because the admin UI lets an authenticated admin set an arbitrary
// URL; without this an attacker with a session (or a hostile admin in a
// multi-tenant deploy) could redirect heartbeats at internal hosts.
//
// Set BULWARK_TELEMETRY_ALLOW_PRIVATE=1 to bypass - useful only for local
// dev where the collector is on the loopback.

const PRIVATE_V4: RegExp[] = [
  /^0\./,                                          // 0.0.0.0/8
  /^10\./,                                         // 10.0.0.0/8
  /^127\./,                                        // loopback
  /^169\.254\./,                                   // link-local + cloud metadata
  /^172\.(1[6-9]|2\d|3[0-1])\./,                   // 172.16.0.0/12
  /^192\.168\./,                                   // 192.168.0.0/16
  /^192\.0\.0\./,                                  // IETF reserved
  /^198\.(1[8-9])\./,                              // benchmarking 198.18.0.0/15
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,      // 100.64.0.0/10 CGNAT
  /^22[4-9]\./,                                    // 224.0.0.0/4 multicast
  /^23\d\./,
  /^2[4-5]\d\./,                                   // 240.0.0.0/4 reserved
];

function isPrivateV4(ip: string): boolean {
  return PRIVATE_V4.some((re) => re.test(ip));
}

// Expand an IPv6 literal into its eight 16-bit groups. Accepts `::`
// compression, a trailing embedded dotted quad (`::ffff:127.0.0.1`) and a
// zone id suffix. Returns null when the string isn't a well-formed address.
//
// We parse structurally rather than regex-matching the textual form because
// the same address has several spellings: the WHATWG URL parser rewrites
// `[::ffff:127.0.0.1]` to `[::ffff:7f00:1]`, while dns.lookup returns the
// dotted form. A textual check that only knew one spelling let the other
// straight through (GHSA-m7j8-f5q4-vj7x).
export function parseV6Groups(ip: string): number[] | null {
  let s = ip.toLowerCase();
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);

  const v4 = s.match(/^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const o = v4.slice(2, 6).map(Number);
    if (o.some((n) => n > 255)) return null;
    s = `${v4[1]}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  if (halves.length === 2 && missing === 0) return null;

  const groups = [...head, ...new Array<string>(missing).fill('0'), ...tail]
    .map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  if (groups.some(Number.isNaN)) return null;
  return groups;
}

function v4FromGroups(hi: number, lo: number): string {
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

function isPrivateV6(ip: string): boolean {
  const g = parseV6Groups(ip);
  // Fail closed: isIP() said this is IPv6 but we can't make sense of it.
  if (!g) return true;

  const leadingZero = (n: number) => g.slice(0, n).every((x) => x === 0);

  if (leadingZero(7) && (g[7] === 0 || g[7] === 1)) return true;         // :: and ::1
  if ((g[0] & 0xff00) === 0xff00) return true;                            // ff00::/8 multicast
  if ((g[0] & 0xffc0) === 0xfe80) return true;                            // fe80::/10 link-local
  if ((g[0] & 0xfe00) === 0xfc00) return true;                            // fc00::/7 ULA
  if (g[0] === 0x2001 && g[1] === 0) return true;                         // 2001::/32 Teredo
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true;        // 64:ff9b:1::/48 local NAT64

  // Forms that embed an IPv4 address: judge them by the embedded address so
  // an IPv6-only host behind DNS64 can still reach a public collector.
  if (leadingZero(5) && g[5] === 0xffff) {                                // ::ffff:0:0/96 IPv4-mapped
    return isPrivateV4(v4FromGroups(g[6], g[7]));
  }
  if (leadingZero(6)) {                                                   // ::/96 IPv4-compatible (deprecated)
    return isPrivateV4(v4FromGroups(g[6], g[7]));
  }
  if (g[0] === 0x64 && g[1] === 0xff9b &&
      g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {             // 64:ff9b::/96 NAT64
    return isPrivateV4(v4FromGroups(g[6], g[7]));
  }
  if (g[0] === 0x2002) {                                                  // 2002::/16 6to4
    return isPrivateV4(v4FromGroups(g[1], g[2]));
  }
  return false;
}

export function isPrivateAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPrivateV4(ip);
  if (family === 6) return isPrivateV6(ip);
  return false;
}

const BAD_HOSTS = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
]);

function bypassEnabled(): boolean {
  return process.env.BULWARK_TELEMETRY_ALLOW_PRIVATE === '1';
}

export type EndpointCheck = { ok: true } | { ok: false; reason: string };

// Sync URL/host shape check. Catches the obvious cases without DNS.
export function validateEndpointUrl(raw: string): EndpointCheck {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid URL' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'must be http(s)://' };
  }
  if (bypassEnabled()) return { ok: true };

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return { ok: false, reason: 'host required' };
  if (BAD_HOSTS.has(host)) {
    return { ok: false, reason: 'localhost endpoints are not allowed' };
  }
  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localhost')) {
    return { ok: false, reason: 'private TLDs are not allowed' };
  }
  if (isIP(host) && isPrivateAddress(host)) {
    return { ok: false, reason: 'private/loopback IP is not allowed' };
  }
  return { ok: true };
}

// Async check that additionally resolves DNS hostnames. Use this on
// set-endpoint AND immediately before fetch to defeat DNS-rebinding tricks
// where a hostname resolves to a public IP at validation time and a private
// one at fetch time.
export async function resolveEndpointAllowed(raw: string): Promise<EndpointCheck> {
  const initial = validateEndpointUrl(raw);
  if (!initial.ok) return initial;
  if (bypassEnabled()) return { ok: true };

  const host = new URL(raw).hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (isIP(host)) return { ok: true };

  try {
    const addrs = await lookup(host, { all: true });
    for (const a of addrs) {
      if (isPrivateAddress(a.address)) {
        return { ok: false, reason: `host ${host} resolves to private address ${a.address}` };
      }
    }
    return { ok: true };
  } catch {
    // Don't block on transient DNS failures - fetch will fail loudly anyway,
    // and we don't want to lock admins out of their config when the resolver
    // is flaky. The literal-IP check above already covers the direct-attack
    // case.
    return { ok: true };
  }
}
