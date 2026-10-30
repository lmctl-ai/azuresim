# azuresim

A local Azure emulator in one native executable, built on
[Floci-AZ](https://github.com/floci-io/floci-az) 0.15.0. Blob and Queue Storage
run without Docker, Java, an Azure account, or network access at runtime.

## Quickstart

Prebuilt executables and SHA256SUMS are available in the
[v0.2.0 release](https://github.com/lmctl-ai/azuresim/releases/tag/v0.2.0).
Choose your platform, verify its checksum, and run `azuresim serve`. For opt-in
auth and a real SDK client example, see [storage auth](docs/auth.md).

Build on a machine with **GraalVM 25**, Maven 3.9+, Python 3.12+, and a C toolchain:

```bash
git clone https://github.com/lmctl-ai/azuresim.git
cd azuresim
python3 scripts/build.py --native
./target/azuresim --version
./target/azuresim serve
```

The emulator listens at `http://127.0.0.1:4577`; Ctrl-C stops it.
`start` is an alias for `serve`. Memory storage is the default. To persist data:

```bash
./target/azuresim serve --port 4577 --data-dir ./data
```

In another terminal, create a container, write a blob, then read it:

```bash
curl -f -X PUT 'http://127.0.0.1:4577/devstoreaccount1/demo?restype=container'
curl -f -X PUT -H 'x-ms-blob-type: BlockBlob' --data-binary 'hello Azure' \
  http://127.0.0.1:4577/devstoreaccount1/demo/hello.txt
curl -f http://127.0.0.1:4577/devstoreaccount1/demo/hello.txt
```

Queue requests use `http://127.0.0.1:4577/devstoreaccount1-queue`:

```bash
curl -f -X PUT http://127.0.0.1:4577/devstoreaccount1-queue/demo
curl -f -X POST -H 'Content-Type: application/xml' \
  --data '<QueueMessage><MessageText>hello</MessageText></QueueMessage>' \
  http://127.0.0.1:4577/devstoreaccount1-queue/demo/messages
curl -f http://127.0.0.1:4577/devstoreaccount1-queue/demo/messages
```

For Azure SDKs, use this development connection string:

```text
DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:4577/devstoreaccount1;QueueEndpoint=http://127.0.0.1:4577/devstoreaccount1-queue;
```

## CLI contract

`--version` prints `azuresim VERSION`; `--help` prints usage. Invalid arguments
return exit 2 and a JSON `{"ok":false,"error":"..."}` envelope. Emulator startup
failures return exit 3 with the same envelope. Normal completion returns 0.
`serve` is a foreground server; Azure HTTP responses retain Azure wire formats.
Upstream startup logs go to stderr. The first successful HTTP request is the
readiness signal; merely starting the process is not a readiness guarantee.

The distribution pins the HTTP bind address to IPv4 loopback, disables TLS,
Event Hubs startup and Service Bus boot sidecars.
Those choices prevent an idle Blob/Queue session from needing containers or
binding extra service ports. Other upstream services remain present and may
require Docker when explicitly used. Open mode preserves permissive upstream authentication. For opt-in SharedKey
signature validation, dummy Bearer tokens, and storage allow/deny policies, see
[authentication and permissions](docs/auth.md). This remains a development emulator.
CLI choices override matching upstream environment variables; other upstream
`FLOCI_AZ_*` settings are available, including service-specific storage overrides.

## Build and test

```bash
python3 scripts/build.py --native
python3 scripts/test-cli.py target/azuresim
python3 scripts/test-storage.py target/azuresim
python3 scripts/test-auth.py target/azuresim
python3 scripts/fetch-client.py
python3 scripts/test-lmazure.py target/azuresim target/lmazure
# After the first build caches source and Maven dependencies:
python3 scripts/build.py --native --offline
```

On Windows use `python` and `target/azuresim.exe`. For faster development,
`python3 scripts/build.py` produces a JVM build and prints the `quarkus-run.jar`
path; both test scripts also accept that path (Java 25 must be on PATH).
Tests use Python's standard library, ephemeral loopback ports and temporary data.
They verify binary blob round trips, missing resources, queue send/peek/receive,
visibility and deletion, persistent storage across a restart, and the `start` alias.
They launch the actual azuresim entrypoint, never an independently started upstream.

The lmazure client is pinned to v0.1.5 with per-platform SHA-256 hashes in
`client.lock.json`. `fetch-client.py` verifies cached and downloaded executables;
after one fetch, `--offline` forbids downloads. Windows uses `target/lmazure.exe`.

GitHub Actions builds and runs the CLI, storage, auth, and client integration suites on Linux x64/arm64, macOS x64/arm64,
and Windows x64 on every main push and PR. A `v*` tag matching VERSION publishes
the tested native binaries plus SHA256SUMS after all five jobs succeed.
[Version 0.2.0](https://github.com/lmctl-ai/azuresim/releases/tag/v0.2.0) passed all
five platforms in [release CI run 40993291701](https://github.com/lmctl-ai/azuresim/actions/runs/40993291701):
12 CLI, 21 storage, 42 auth/config, and 18 real lmazure SDK checks per platform.
See [Wave 11 validation evidence](docs/validation-wave11.md) for exact commits and scope.

## Design and limits

- **Build integration, not a fork mirror.** `upstream.lock.json` pins release
  0.15.0, commit `8b439a8ddf90df92315dfdbe95b0498e81384cc0`, and its source archive
  SHA-256. The build verifies the archive before extracting it and adds only our
  small Quarkus entrypoint. Azure handlers and upstream native metadata stay intact. Windows adds runtime
  initialization for docker-java's Unix DomainSocket class, whose libc symbols
  cannot be resolved during a Windows native build.
- **Source build instead of downloader.** This release of Floci-AZ publishes
  Docker images but no native release assets. Compiling it produces a standalone
  executable with no first-run download. Maven resolves the upstream dependency
  graph; the lock pins the source archive, not every transitive Maven artifact.
- **Real lmazure integration.** The 0.1.5 client adds an explicit loopback-only
  SDK command without relaxing its live-cloud guards. Our client integration
  suite tests Blob/Queue operations and auth errors against azuresim. See
  [auth setup and client quickstart](docs/auth.md).
- **Scope of validation.** Blob and Queue Storage are tested here. The other
  upstream services, Docker sidecars, TLS, and authentication parity are not
  independently certified by azuresim. See the pinned upstream documentation
  for service-specific fidelity limits.
- **Upgrades are deliberate.** Update the commit, version, and archive checksum
  together, review upstream configuration changes, and rerun native tests on all
  platforms. Do not silently substitute a floating tag or a locally installed server.

MIT; see LICENSE, FLOCI-AZ-LICENSE, and THIRD_PARTY_NOTICES.md.

### LMScript templates

[Template integration](docs/templates.md) uses `_json_` blocks for storage
payloads and auth policy, plus `expand()` for resource paths. Run
`scripts/test-templates.py` with the built simulator and pinned lmazure client;
all five native CI jobs exercise open and SharedKey enforcement modes.
