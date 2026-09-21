# Security Policy

NeoShell handles SSH credentials and private keys, and it updates itself over
the network. Reports about either are taken seriously.

## Supported versions

Only the latest release gets fixes. There are no maintenance branches.

| Version | Supported |
|---|---|
| latest release | yes |
| anything older | no — upgrade first |

If you are on an older build, reproduce on the latest release before reporting.
If you cannot upgrade, say so and include your exact version.

## Reporting a vulnerability

Use **GitHub Private Vulnerability Reporting**:
<https://github.com/uk0/NeoShell/security/advisories/new>

That channel is private, it works without email, and it lets us share a draft
fix with you before anything is public. Please do not open a public issue for
anything affecting credential handling, the SSH transport, the vault, or the
updater.

> **Maintainer note:** this link only works once Private Vulnerability Reporting
> is switched on, at *Settings → Advanced Security → Private vulnerability
> reporting → Enable* (or `gh api -X PUT
> repos/uk0/NeoShell/private-vulnerability-reporting`). Leaving it off means a
> finished report has nowhere to go. Verify with
> `gh api repos/uk0/NeoShell/private-vulnerability-reporting`.

If the advisory form is unavailable to you, open a public issue that says only
"security report, need a private channel" — no details — and a channel will be
arranged within 72 hours.

What helps most, in rough order:

- The affected file **and function**. Line numbers shift between releases, so
  name the function too.
- The commit or release tag you read.
- What an attacker controls, and what they get. A reachability argument beats a
  severity label.
- A reproduction, if one is cheap. If it is not, say so — a well-argued report
  without a PoC is still welcome.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 72 hours |
| Initial assessment, with a severity call and a rough timeline | 7 days |
| Fix released, or a written explanation of why not | 90 days |

This is a single-maintainer project. If a deadline slips you will be told why,
not left waiting.

## Disclosure

Coordinated. We ask you to hold details until a fixed release ships or 90 days
pass from acknowledgement, whichever comes first. If a fix will take longer,
that will be negotiated with you rather than assumed.

Reporters are credited in the release notes and the advisory under whatever name
or handle they choose, including none. There is no bounty programme.

## Scope

In scope: the Rust workspace in this repository, the release artifacts published
under this repository's Releases, and the update manifest and libraries served
from <https://neoshell.wwwneo.com/updates/>.

Out of scope: the marketing pages under `website/`, vulnerabilities in
third-party crates that NeoShell does not expose (report those upstream), and
anything requiring an attacker who already has local code execution as your user
— at that point the vault's threat model has already been overtaken.

## Known areas

Stated plainly so nobody spends effort rediscovering them.

- **Update authenticity depends on the build.** Libraries served on the update
  channel carry a detached ed25519 signature, and both the core downloader and
  the launcher verify it against a public key compiled in at build time
  (`NEOSHELL_UPDATE_PUBKEY`). A build made without that key refuses to install
  any staged update rather than trusting it. Releases **up to and including
  0.6.27 verified an MD5 taken from the same document as the download URL**,
  which proves transport integrity only, never authenticity — if you are on one
  of those, reinstall from the Releases page instead of relying on the in-app
  updater.
- **Proxy and tunnel configuration is not yet in the vault.** Connection
  credentials live in the AES-256-GCM vault, but `proxies.json` and
  `tunnels.json` are plain JSON next to it. Do not put a password you care about
  on a bastion or tunnel entry until that migration lands.
- **macOS builds are signed but not notarized.** See the notarization
  requirements recorded at the top of `scripts/sign-macos.sh`. Until that is
  done, first launch needs the usual Gatekeeper override.

Reports that sharpen any of these — a concrete exploitation path, or a review of
a proposed fix — are especially useful.
