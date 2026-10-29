# Validation evidence

2026-10-29: azuresim 0.1.0, Floci-AZ 0.15.0 pinned by commit and archive SHA-256.

[CI run 40975537919](https://github.com/lmctl-ai/azuresim/actions/runs/40975537919)
passed on commit `cffe62e9aa5a559209f8b6959d22ad79edb1cd7c`:

| Native platform | CLI | Storage REST |
| --- | --- | --- |
| Linux x64 | 12 passed | 21 passed |
| Linux arm64 | 12 passed | 21 passed |
| macOS x64 | 12 passed | 21 passed |
| macOS arm64 | 12 passed | 21 passed |
| Windows x64 | 12 passed | 21 passed |

Each storage run additionally asserts that starting on an occupied port returns
exit 3 and a JSON error envelope. Tests launch our standalone native executable
with temporary state and an ephemeral loopback port, without Java or Docker.

The JVM build also passed both suites before native compilation. The Linux arm64
artifact from the successful run was downloaded and independently passed both
suites on the local ARM64 Linux machine. Its SHA-256 is:
`e0c7e7181e6055b9a0e331ba7aacf195460600f1e1d0443353b056f3b62edb4f`.
The native executable is available locally at `target/azuresim` (ignored by Git).

Verified behavior:

- Version/help and invalid CLI arguments with exit 2 and a JSON error envelope.
- Occupied port produces exit 3 and a JSON error envelope.
- Container creation, blob upload/download with binary bytes, listing and 404s.
- Queue create, send, peek, receive, visibility, pop-receipt deletion and teardown.
- Persistent blob survives a process restart using the `start` alias.
- Memory storage is empty after restart.

Portability adjustments: Windows defers initialization of docker-java's unused
Unix DomainSocket transport; native-image uses a 4 GB compiler heap to fit smaller
hosted runners. Azure handlers remain unmodified.

The client is Python's standard-library HTTP stack. No requests target Azure.
.NET is absent locally; inspected lmazure currently requires public Azure HTTPS
storage endpoints, so this is REST evidence rather than lmazure SDK certification.
Other Azure services, Docker sidecars, and TLS remain outside this validation.
No release tag has been published; the tested binaries are available as CI
artifacts, and the configured `v*` tag workflow publishes release binaries.
