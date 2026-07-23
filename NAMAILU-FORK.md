# namailu.cz fork of Bulwark Webmail

This branch (`namailu-2fa`) forks Bulwark to make TOTP two-factor auth **self-contained in the
webmail** (secret stored in the user's mailbox via JMAP, verified in-app), instead of delegating to
Stalwart's `x:AccountPassword` OTP — which is a Stalwart **Enterprise** feature (returns HTTP 402 on a
community license and would lock the account out).

Full design, rationale, change-map and build/rebase instructions:
`server-runbook/webmail/FORK.md` (in the ops runbook).

Upstream: github.com/bulwarkmail/webmail (AGPL v3). Per AGPL, this fork is published before going live.
