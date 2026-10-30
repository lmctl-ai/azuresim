# Storage authentication and permissions

Open mode remains the default. Enforce mode is opt-in:

```bash
azuresim serve --auth enforce --auth-config examples/auth.json
# Equivalent environment configuration:
AZURESIM_AUTH=enforce AZURESIM_AUTH_CONFIG=examples/auth.json azuresim serve
```

CLI options take precedence over environment settings. The JSON file is read once
at startup, is limited to 1 MiB, and must contain at least one account key or token.
Invalid JSON, duplicate keys, unknown fields, invalid rule effects, and malformed
credentials fail startup with exit 2 and a redacted error. Supplying an auth config
in open mode is an error, preventing an accidentally unused policy file.

The example contains public dummy credentials; do not use Azure production secrets.

## Authentication

`accounts` maps a storage account name to a base64 HMAC key (at least 16 decoded bytes). SharedKey validation
uses HMAC-SHA256, constant-time signature comparison, account binding, all eleven
standard header fields, sorted lower-case `x-ms-*` headers, and the encoded URI
path plus sorted decoded query names/values. An emulator path repeats the account
in the canonical resource, matching the Azure SDK. Both path-style and Azure
Blob/Queue host-style requests are supported. Date/x-ms-date must be within 15
minutes of the server clock. The zero Content-Length and empty x-ms-header rules
honor the request's storage API version.

`tokens` maps exact opaque Bearer tokens to local principal names. These are dummy
AAD-style credentials, not JWT validation: no Entra issuer, audience, signature,
expiry, token acquisition, or credential discovery is implied.

Missing, malformed, stale, or incorrect credentials return HTTP 403, an
`x-ms-error-code: AuthenticationFailed` header, and Azure-shaped XML containing
`<Code>AuthenticationFailed</Code>`. Duplicate HTTP headers are rejected as an
authentication failure; Azure can use 400 for some duplicate-header cases.
Errors never echo credentials, canonical strings, configuration, or exceptions.

## Permissions

Optional `Statement` is an array of rules:

```json
{
  "Effect": "Allow",
  "Action": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
  "ResourceGlob": "/devstoreaccount1/blob/reports/*",
  "Principal": "reader"
}
```

`ActionGlob` is an alias for `Action`; specify exactly one. Action, ResourceGlob,
and Principal accept a string or a nonempty list. Principal defaults to `*`.
`*` matches any sequence (including `/`), and `?` matches one character. Action
matching is case-insensitive; storage resources and principal names are
case-sensitive. A SharedKey principal is its account name; a Bearer principal
comes from the configured token map.

When Statement is absent, authenticated requests to supported operations are
allowed. When present, including an empty array, the default is deny. Any matching
Deny wins over all Allows regardless of statement order. Denied permissions return
HTTP 403 with `AuthorizationPermissionMismatch` in the XML and error header.

Resource names are local, decoded, service-qualified paths:

- Blob: `/ACCOUNT/blob/CONTAINER/BLOB`, or `/ACCOUNT/blob/CONTAINER`.
- Queue: `/ACCOUNT/queue/QUEUE/messages/ID`, or `/ACCOUNT/queue/QUEUE`.
- Service roots: `/ACCOUNT/blob/` and `/ACCOUNT/queue/`.

A resource glob ending in `container*` also matches `container-other`; use exact
container and `container/*` entries when that distinction matters.

## Supported action mapping

| Operations | Action suffix after `Microsoft.Storage/storageAccounts/` |
| --- | --- |
| Container GET/HEAD, PUT, DELETE | `blobServices/containers/read`, `write`, `delete` |
| List containers | `blobServices/containers/read` |
| Blob GET/HEAD or container blob listing | `blobServices/containers/blobs/read` |
| Blob PUT, block/blocklist PUT, metadata PUT | `blobServices/containers/blobs/write` |
| Blob DELETE | `blobServices/containers/blobs/delete` |
| Queue GET/HEAD, PUT, DELETE, list queues | `queueServices/queues/read`, `write`, `delete` |
| Send message | `queueServices/queues/messages/add/action` |
| Peek message | `queueServices/queues/messages/read` |
| Receive message | `queueServices/queues/messages/process/action` |
| Update / delete message | `queueServices/queues/messages/write`, `delete` |

This is a boundary overlay, not Azure's complete RBAC role-assignment model. The
upstream policy engine implements ARM resource policies, not storage data-plane
RBAC, and its SharedKey verifier accepts arbitrary signatures. We therefore add
one early request filter without changing upstream handlers.

Enforce mode rejects all other services and unsupported storage operations,
including SAS/SharedKeyLite, Table, ARM, ACL operations, and TLS-specific auth.
Unsupported routes produce permission errors after Bearer authentication; a
SharedKey request without a recognized target produces AuthenticationFailed.
Ambiguous paths (encoded slash/backslash/percent, dot segments, semicolons, repeated
slashes, trailing slashes) are rejected in enforce mode to prevent policy alias
bypasses. These are deliberate compatibility limits. Open mode retains upstream
behavior. Payload-integrity checks beyond SharedKey's signed headers remain the
responsibility of the upstream storage handlers.

## Real client example

Requires lmazure 0.1.5 or later, which adds a dedicated loopback-only SDK command:

```bash
export LMAZURE_SIM_ENDPOINT=http://127.0.0.1:4577
export LMAZURE_SIM_KEY=YWp1c3QtbG9jYWwtZGV2ZWxvcG1lbnQta2V5IQ==
lmazure --simulator container-create demo-container
printf 'hello authenticated Azure' > input.txt
lmazure --simulator blob-put demo-container hello.txt input.txt
lmazure --simulator blob-get demo-container hello.txt output.txt
lmazure --simulator queue-create demo-queue
lmazure --simulator queue-send demo-queue hello
lmazure --simulator queue-receive demo-queue
```

For Bearer testing, unset LMAZURE_SIM_KEY and set
`LMAZURE_SIM_TOKEN=local-demo-token`. Wrong credentials and denied policy requests
surface as exit 3 with a redacted JSON error containing the Azure code and status.

References: [Azure SharedKey canonicalization](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key),
[Azure storage error codes](https://learn.microsoft.com/en-us/rest/api/storageservices/common-rest-api-error-codes).
