# Wave 11 validation

azuresim 0.2.0 uses checksum-pinned Floci-AZ 0.15.0 with an early authentication
and policy overlay; no upstream protocol handlers were changed.

## Native release matrix

[Release run 40993291701](https://github.com/lmctl-ai/azuresim/actions/runs/40993291701)
validates source commit `879ee6643fcde016633b7158f38a9177f4cd6e11`, tag `v0.2.0`.
All five platforms passed: Linux x64/arm64, macOS x64/arm64, and Windows x64.
Each job builds the simulator, fetches and verifies the pinned lmazure native
release, then runs the following suites against those actual executable files:

| Suite | Checks | Evidence |
| --- | ---: | --- |
| CLI | 12 | Version, help, invalid arguments and exit codes |
| Storage REST | 21 | Blob bytes, queue lifecycle, persistence restart, memory isolation |
| Auth/config | 42 | SharedKey, Bearer, missing/wrong/stale credentials, account binding, allow/deny/default-deny, wildcards, ambiguous paths, strict config, redaction |
| lmazure SDK | 18 | Native client → native emulator → blob/queue results and Azure error propagation |

The storage suite also checks occupied-port exit 3. Authentication tests include
both orders of matching Allow/Deny statements, case-insensitive action matching,
resource `*`/`?` wildcards, and principal constraints. SDK-signed requests provide
an independent check of canonicalization beyond the handwritten REST signer.

## Client dependency

[lmazure v0.1.5](https://github.com/lmctl-ai/lmazure/releases/tag/v0.1.5), source
commit `a71d950`, adds an explicit loopback-only simulator command. Its
[five-platform release run](https://github.com/lmctl-ai/lmazure/actions/runs/40991979034)
passed its existing client/DSL/comparison suites and 52 CLI checks. Public Azure
endpoint and live-write guards remain unchanged; simulator mode never invokes
DefaultAzureCredential or ARM clients.

`client.lock.json` pins all five binary SHA-256 values. They were checked against
the release's SHA256SUMS manifest. A real download and cached offline invocation
both passed verification; missing and corrupted offline caches were rejected.

Locally, both the JVM simulator and native ARM64 Linux simulator passed the auth
and integration suites. The native client was taken from the released, verified
artifact. No Azure subscription or production credentials were used.

## Scope and deferrals

Enforce mode supports the documented Blob/Queue operations and fails closed for
other routes. Bearer credentials are configured opaque test tokens. Full Entra
JWT verification, Azure role assignments, SAS/SharedKeyLite, TLS authentication,
and control-plane/other-service permissions are not implemented. See
[auth semantics and compatibility limits](auth.md) and the
[durable implementation notes](durable-memory/wave11-auth.md).
