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
