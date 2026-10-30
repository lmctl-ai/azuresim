# Template-driven Blob and Queue integration

`examples/templates.lms` authors JSON using `_json_` blocks: request parameters,
blob content with metadata fields, a queue message, and a SharedKey permission
configuration. Context includes quotes, a backslash, Unicode, numbers, lists,
and literal `${opaque}` text. Assertions verify the values survive SDK storage
and retrieval without double interpolation. `expand()` constructs policy resource
paths, never JSON.

Run from the repository root after building azuresim and fetching lmazure:

```bash
npm ci --ignore-scripts --prefix scripts/compiler
LMSCRIPT_BIN="$PWD/scripts/compiler/node_modules/@lmctl-ai/lmctl/bin/lmscript" \
  python3 scripts/test-templates.py target/azuresim target/lmazure
# Development validation with the fresh mono engine:
LMSCRIPT_BIN="$HOME/lmctl-mono/bin/lmscript" \
  python3 scripts/test-templates.py target/azuresim target/lmazure
```

Use `.exe` suffixes for native Windows executables. The Python runner launches
the JavaScript compiler with Node, avoiding platform-specific shell wrappers.
Node 24 and Python 3.12 are used in CI. The local npm lock pins compiler 0.2.444
and its integrity hash; installation does not change the global lmctl.

The runner first checks the script without effects, then runs its `prepare`
phase in a temporary directory. The exact generated `auth.json` is passed to
azuresim's `--auth-config` equivalent environment setting. Two fresh servers
exercise open mode without credentials and enforce mode with a dummy SharedKey.
The script performs container creation, blob upload/download, queue creation,
message send/peek, and an enforce-only denied container deletion. It asserts
client success/error envelopes and round-trip payload fields. The runner also
checks HTTP 200 and body content, and HTTP 403 plus XML/error headers for both
permission denial and missing authentication. Processes and temporary files are
cleaned up even after failed assertions.

This follows Wave 11's native `lmazure --simulator` interface, using array-valued
`system()` calls without shell interpolation. That interface is not exposed by
lmazure's cloud DSL schema, so this example does not pretend to import a simulator
host schema. JSON blob and message payloads reach the real Azure SDK; resource
parameters become CLI arguments. Metadata here is part of the stored JSON blob,
not Azure blob metadata headers. No mock client or Azure account is involved.

All five native CI jobs run the example alongside the existing suites. The
owned Java response templates use text blocks and value-boundary JSON/XML
escaping through `ResponseTemplates`; upstream response code is unchanged.
