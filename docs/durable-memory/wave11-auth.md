# Wave 11: Azure storage auth and client lessons

- Floci-AZ 0.15.0's SharedKey verifier accepts signatures without validating them.
  Its ARM policy machinery is not a data-plane RBAC engine. Use an early
  `@ServerRequestFilter(preMatching=true, priority=1000)` overlay before its
  routing filter; no handler fork or proxy is necessary.
- Canonical resources must preserve the raw encoded URI path, including the
  emulator account prefix. The signing account is prepended separately. Sorting
  query values and using an empty zero Content-Length for modern API versions
  are required for actual Azure SDK signatures.
- Loopback-bound Quarkus rejects Azure Host headers unless
  `quarkus.http.host-validation.require-localhost=false`; binding remains 127.0.0.1.
- JAX-RS UriInfo normalizes repeated slashes before request filters. Use the
  original Vert.x HttpServerRequest URI for signing and alias rejection; otherwise
  a test of an ambiguous path can accidentally validate the normalized handler.
- Authentication identity must bind to the routed account. Policy resources use
  a service-qualified decoded path. Reject ambiguous aliases and unknown
  operations in enforcement mode; do not accidentally expose unprotected ARM
  or other service routes. Explicit Deny wins regardless of rule order.
- Parse configuration strictly, including unknown fields and duplicate JSON
  keys, and never include parser/crypto exception text in client errors.
- lmazure 0.1.4 only accepts public Azure endpoints. Added an explicit simulator
  command for 0.1.5 that uses the real Blob/Queue SDKs, literal IPv4 loopback only,
  no redirects/proxies, no DefaultAzureCredential, and redacted error envelopes.
  This leaves the existing live cloud endpoint/write gates untouched.
- Tests must use a real signed SDK request, not only a second handwritten signer.
  The integration suite exercises binary file content, queue message lifecycle,
  authentication rejection and policy denial through the client process.

## Azurite source cross-check

Reviewed Microsoft's MIT-licensed Azure/Azurite at commit
`41855fd41bfa4c9f1ab0cfa1f48b8330536299d4` after the 0.2.0 release:

- [BlobSharedKeyAuthenticator.ts](https://github.com/Azure/Azurite/blob/41855fd41bfa4c9f1ab0cfa1f48b8330536299d4/src/blob/authentication/BlobSharedKeyAuthenticator.ts)
  confirms standard header order, the empty Date field when x-ms-date exists,
  lowercase sorted storage headers, account-prefixed request path, sorted query
  names, plus-to-space query decoding, and HMAC-SHA256.
- [QueueSharedKeyAuthenticator.ts](https://github.com/Azure/Azurite/blob/41855fd41bfa4c9f1ab0cfa1f48b8330536299d4/src/queue/authentication/QueueSharedKeyAuthenticator.ts)
  lists Content-Language before Content-Encoding, unlike its Blob implementation
  and the documented SharedKey order. Keep encoding before language for both
  services; do not copy that source discrepancy.
- [getURLQueries](https://github.com/Azure/Azurite/blob/41855fd41bfa4c9f1ab0cfa1f48b8330536299d4/src/common/utils/utils.ts)
  stores query entries in an object and overwrites repeated names. Keep our
  decoded, sorted multivalue canonicalization. Azurite's header implementation
  trims leading whitespace without implementing all the whitespace folding
  described in its comments. It also unconditionally signs zero Content-Length
  as empty. Keep our documented whitespace and API-version rules.
- [BlobTokenAuthenticator.ts](https://github.com/Azure/Azurite/blob/41855fd41bfa4c9f1ab0cfa1f48b8330536299d4/src/blob/authentication/BlobTokenAuthenticator.ts)
  requires HTTPS and its basic mode decodes JWTs, checks lifetime, issuer and
  audience, but explicitly skips signature and scope validation. This is a
  different contract from our assigned opaque dummy Bearer tokens on loopback.
  Do not imply that either mode provides full Entra validation.

No source was copied or dependency added. The review found no required change
to the released implementation within our supported scope. Re-ran the 42 auth
checks and 18 real lmazure SDK checks against the published Linux ARM64 binaries.
