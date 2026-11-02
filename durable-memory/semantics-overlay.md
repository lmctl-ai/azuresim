# Azure Blob & Queue Semantics Overlay

Pinned upstream: floci-az 0.15.0, commit
`8b439a8ddf90df92315dfdbe95b0498e81384cc0` (`upstream.lock.json`).

## 1. Why `scripts/build.py` Changed

In `--native` mode, `scripts/build.py` already copies the compiled runner binary into `target/azuresim[.exe]`.
However, in standard JVM mode (no `--native`), upstream `scripts/build.py` previously only printed the path inside the extracted build directory: `target/floci-az-<commit>/target/quarkus-app/quarkus-run.jar`. It did not populate a repo-root `dist/` directory.

The repository root `.gitignore` already includes `dist/`, and test harnesses, CI runners, and operator specifications expect the runnable JVM artifact at `dist/quarkus-app/quarkus-run.jar` (`java -jar dist/quarkus-app/quarkus-run.jar serve --port <PORT>`).
`scripts/build.py` was updated to copy `source / 'target/quarkus-app'` to `ROOT / 'dist/quarkus-app'` when packaging the JVM runner.

---

## 2. Files Copied into the Overlay

`scripts/build.py` extracts the pinned upstream archive (`target/floci-az-<commit>`) and recursively overlays any files present under `src/main/java/`.

This change overlays two upstream service handler classes under `src/main/java/io/floci/az/services/`:

1. `src/main/java/io/floci/az/services/blob/BlobServiceHandler.java`:
   Full copy of upstream `io.floci.az.services.blob.BlobServiceHandler` with container existence pre-checks added to container deletion, blob operations, and enumeration.
2. `src/main/java/io/floci/az/services/queue/QueueServiceHandler.java`:
   Full copy of upstream `io.floci.az.services.queue.QueueServiceHandler` with missing-queue guards on queue deletion and message clearance, strict metadata-aware queue creation idempotency, empty-body visibility update support in `updateMessage`, malformed XML handling, case-insensitive metadata header parsing, and `HEAD` query support for `comp=metadata`.

On an upstream version bump:
Re-copy both files from the newly extracted upstream source, then re-apply the hunks described below (3-way merge).

---

## 3. Exact Changes vs Upstream

### 3.1 `BlobServiceHandler.java`

- **`deleteContainer(request, containerName)`**:
  Upstream unconditionally deleted the container namespace key and its objects, returning `202 Accepted` even if the container never existed.
  *Fix:* Added existence check:
  ```java
  String cKey = nsKey(request.accountName(), containerName);
  if (store.get(cKey).isEmpty()) {
      return new AzureErrorResponse("ContainerNotFound", "The specified container does not exist.")
              .toXmlResponse(Response.Status.NOT_FOUND.getStatusCode());
  }
  ```
  Returns `404 ContainerNotFound` with `x-ms-error-code: ContainerNotFound` header and standard Azure XML error body when missing. Preserves upstream behavior of deleting non-empty containers with `202 Accepted` and sweeping all blob keys.

- **`listBlobs(request, containerName)`**:
  Upstream scanned blob prefix without checking whether the container existed, returning `200 OK` with an empty enumeration `<Blobs/>`.
  *Fix:* Added existence check: if `store.get(nsKey(account, containerName)).isEmpty()`, returns `404 ContainerNotFound` with XML error body.

- **`getBlob`, `deleteBlob`, `getBlobMetadata`, `setBlobMetadata`, `getBlobTags`, `setBlobTags`, `getBlockList`, `leaseBlob`**:
  Upstream returned `404 BlobNotFound` when the target blob key was absent, even when the enclosing container did not exist.
  *Fix:* When the blob object is absent, check whether the container namespace key exists. If the container does not exist, return `404 ContainerNotFound` instead of `BlobNotFound`.

### 3.2 `QueueServiceHandler.java`

- **`deleteQueue(request, queueName)`**:
  Upstream unconditionally deleted the queue key and returned `204 No Content`, even if the queue never existed.
  *Fix:* Added existence check:
  ```java
  String key = nsKey(request.accountName(), queueName);
  if (store.get(key).isEmpty()) {
      return queueNotFound();
  }
  store.delete(key);
  ```
  Returns `404 QueueNotFound` with `x-ms-error-code: QueueNotFound` header and XML error body when missing.

- **`createQueue(request, queueName)`**:
  Upstream unconditionally returned `204 No Content` if the queue existed, ignoring any metadata headers sent with the request.
  *Fix:* Azure Queue Storage REST specification requires comparing existing metadata with request metadata. If identical, returns `204 No Content`. If metadata differs, returns `409 QueueAlreadyExists`:
  ```java
  Optional<StoredObject> existing = store.get(key);
  if (existing.isPresent()) {
      Map<String, String> existingMeta = existing.get().metadata();
      Map<String, String> reqMeta = readMetadataHeaders(request);
      if (existingMeta.equals(reqMeta)) {
          return Response.status(Response.Status.NO_CONTENT).build();
      } else {
          return new AzureErrorResponse("QueueAlreadyExists", "The specified queue already exists.")
                  .toXmlResponse(Response.Status.CONFLICT.getStatusCode());
      }
  }
  ```

- **`updateMessage(request, queueName, messageId, popReceipt)`**:
  Upstream called `xmlMapper.readValue(request.bodyStream(), QueueModels.QueueMessageRequest.class)` unconditionally. When clients sent an empty request body (`Content-Length: 0` / empty stream) to update only visibility timeout (the official Azure REST specification for visibility renewal / nack), the parser threw an `EOFException` / `MismatchedInputException`, resulting in `500 Internal Server Error`.
  *Fix:* Read body bytes first. If empty, retain existing message payload (`existing.get().data()`) and update only `_visibleAt` and `PopReceipt`, returning `204 No Content` with `x-ms-popreceipt` and `x-ms-time-next-visible` headers. If body is non-empty XML, parse and update message text. If XML is malformed, return `400 InvalidXmlDocument` instead of 500.

- **`clearMessages(request, queueName)`**:
  Upstream swept queue message keys without checking if the queue existed, returning `204 No Content`.
  *Fix:* Check `if (store.get(nsKey(account, queueName)).isEmpty()) return queueNotFound();`.

- **`readMetadataHeaders(request)`**:
  Header names in HTTP requests can vary in casing (`x-ms-meta-Foo` vs `x-ms-meta-foo`). Upstream stored the substring with original case.
  *Fix:* Lowercase the metadata key name so metadata comparisons in `createQueue` are case-insensitive per Azure identifier rules.

- **`handle(request)`**:
  Allow both `GET` and `HEAD` requests on `comp=metadata` to return `getQueueMetadata` with `x-ms-approximate-messages-count` and `x-ms-meta-*` headers.

---

## 4. Redundancy of `lmazure` Workaround Probes

Reference: `/home/ubuntu/cloud/lmazure/durable-memory/go-port-findings.md`

| Finding | Workaround in `lmazure` | Behavior in New `azuresim` | Redundant Now? |
|---|---|---|---|
| **Finding 7** (Container DELETE returns 202 on missing) | `BucketDelete` probes existence via `ContainerClient.GetProperties` (HEAD) before deleting. | `DELETE /<account>/<container>?restype=container` now returns `404 ContainerNotFound` directly. | **YES.** `lmazure`'s existence pre-flight probe in `BucketDelete` is redundant (though its non-empty container check remains needed due to the lmcloud spec's `CONFLICT` requirement). |
| **Finding 8** (Queue DELETE returns 204 on missing) | `QueueDelete` probes existence via `QueueClient.GetProperties` before deleting. | `DELETE /<account>-queue/<queue>` now returns `404 QueueNotFound` directly. | **YES.** `QueueDelete` could issue `Delete` directly and handle `404 QueueNotFound`. |
| **Finding 9** (Queue Create 201 vs 204 suppression) | `QueueCreate` probes `QueueClient.GetProperties` before attempting creation. | `azuresim` now returns 201 on new, 204 on identical, 409 on different metadata. | **NO (SDK limitation).** The Go SDK `azqueue.Client.Create` suppresses 201 vs 204 HTTP status codes (returns `err == nil` for both). Until custom response inspection is used, the pre-flight probe remains necessary for `QueueCreate` to distinguish new vs existing. |
| **Finding 3** (Empty-body UpdateMessage 500) | `lmazure` encodes `rawB64` into composite receipt and echoes existing payload on `queue_nack` and visibility-0 receive. | `UpdateMessage` now supports empty request bodies without throwing 500. | **YES for raw REST callers.** Standard Azure REST callers can send empty body for visibility updates. `lmazure`'s payload echo is no longer required by the simulator, though safe to keep. |

---

## 5. Verification Summary

Toolchain: GraalVM JDK 25 + Maven 3.9 (`source /home/ubuntu/tools/env.sh`).
JVM package: `dist/quarkus-app/quarkus-run.jar`.

- `python3 scripts/test-cli.py dist/quarkus-app/quarkus-run.jar`: **PASS** (12 checks)
- `python3 scripts/test-storage.py dist/quarkus-app/quarkus-run.jar`: **PASS** (21 REST checks)
- `python3 scripts/test-auth.py dist/quarkus-app/quarkus-run.jar`: **PASS** (42 HTTP/config checks)
- `python3 scripts/test-semantics.py dist/quarkus-app/quarkus-run.jar`: **PASS** (51 REST checks covering all changed behaviors)
- `lmazure` conformance suite (`tests/run-conformance.sh /home/ubuntu/cloud/lmazure/bin/lmazure http://127.0.0.1:4577 all`): **PASS** (25/25 scenarios, 2 open-mode skips)
- `lmazure` auth-enforce conformance (`12-auth-enforced-denial.lms` & `13-queue-auth-enforced-denial.lms`): **PASS**
