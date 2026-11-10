# Threat model — railgate

**Scope.** Threat model for the settlement-rail enforcement component that sits at a central-bank settlement system (RIX-INST in the Swedish reference deployment; generalisable to TIPS, FedNow, FPS, NPP) and orchestrates deterministic cryptographic signature verification at settlement time. The companion repositories `hsm/` (financial-entity-side HSM attestation verification) and `gatekeeper/` (NCA-operated certificate-issuance gate and settlement-time signature verification endpoint) have their own threat models covering threats specific to those layers; this document focuses on what becomes new or different when verification is consumed at the central-bank settlement chokepoint.

**Assumptions out of scope.** The host platform (network, OS, JVM, container runtime) is not modelled here. Production deployments are operated by central-bank IT under that organisation's own platform-security regime; the threat model below treats those as sound and focuses on what the Java code itself can and cannot guarantee. The pacs.008 ingress integration with the settlement pipeline is similarly out of scope — railgate's contract is the abstracted `SettlementRequest` model.

**v1.7.0 scope.** railgate verifies the gatekeeper's signed settlement verdict, retrieves artefacts from the payment-network operator over a specified, signed interface (`http` mode), and allows each transaction reference and operator payout instruction id at most once (`ReplayGuard`). The statements below that changed with these are marked *(1.7.0)*.

**Framework.** STRIDE.

---

## Spoofing

### Assets at risk

- The identity of the calling settlement system (central bank).
- The identity of the supervisor's gatekeeper instance (target of railgate's outbound calls).
- The identity of the payment-network operator (target of railgate's artefact lookups in `http` mode).

### Attack vectors

- An adversary submits a fabricated `SettlementRequest` to railgate's `/api/v1/settle/precheck` endpoint, attempting to obtain `allow=true` for a transaction that has not actually been initiated by an authorised bank.
- An adversary impersonates the supervisor's gatekeeper, returning fraudulent `signatureValid=true, compliant=true` responses to railgate.
- An adversary impersonates the payment-network operator, returning artefacts of its choosing for a transaction reference.

### Mitigations

- `SecurityConfig` requires authentication on every path and ships HTTP Basic as the reference mechanism. mTLS is the mechanism a central-bank deployment should use, and wiring it is the deployer's work, not something this repo performs: a truststore via `server.ssl.trust-store-*` with `server.ssl.client-auth=need`, and `.x509(...)` in place of `.httpBasic(...)` on the filter chain. Until that is done, the caller is authenticated by a shared secret. railgate refuses to start without TLS on its own listener (`ListenerTlsGuard`; `railgate.server.allow-insecure-http=true` overrides it for local development only), so that secret and the verdicts are not sent in clear.
- Outbound, `GatekeeperClient` refuses a non-`https` base URL at start-up unless `railgate.gatekeeper.allow-insecure-http=true`, so the supervisor link cannot silently be plain text. The truststore and any client certificate come from the Spring Boot SSL bundle named by `railgate.gatekeeper.ssl-bundle`, or from the JVM defaults when that property is empty; the gatekeeper certificate is **not** pinned by railgate.
- The orchestrator never makes its decision on the basis of trust in the caller alone. Even when the caller is a properly authenticated settlement system, the verification result depends on the gatekeeper's response.
- **railgate verifies the gatekeeper's signed verdict** *(1.7.0)*. Until 1.6.0 `POST /api/v1/verify` returned plain JSON, railgate deserialised `signatureValid` and `compliant` from it directly, and an adversary who could present a TLS certificate railgate's truststore accepted, or who terminated the connection at a compromised proxy, could return `signatureValid=true, compliant=true` and have the settlement allowed. gatekeeper 1.7.0 signs every verdict over `sv1`, and `GatekeeperClient` verifies it under the certificates in `railgate.gatekeeper.trusted-keys`, over the `certSerial`, `issuerDn` and `digestHex` railgate sent, with `verifiedAt` within `railgate.gatekeeper.verdict-max-skew`; anything else is `VERDICT_SIGNATURE_INVALID` or `VERDICT_STALE`. A forged verdict now needs the gatekeeper's signing key, not only a position on the network. This is required by default (`require-signed-verdict=true`); the `dev` profile turns it off (WARN at start-up). The verdict covers the identifiers and the digest, not the signature bytes or a certificate added to the request. That an `OK` verdict means the certificate named by `certSerial` and `issuerDn` verified a signature over the digest therefore rests on how the gatekeeper finds the certificate: gatekeeper 1.8.0 or later looks it up under those identifiers in every case, while gatekeeper 1.7.0 looked a certificate supplied in the request up under that certificate's own serial and issuer, so an intermediary that added another, compliant certificate and a signature made with its key to railgate's request obtained a genuine `OK` verdict for the identifiers railgate had sent (gatekeeper `CHANGELOG.md`, 1.8.0).
- **Operator answers are signed** *(1.7.0, `http` mode)*. `HttpPaymentNetworkClient` accepts a 200 answer only if it is signed over `op1` by a certificate in `railgate.payment-network.trusted-keys`, for exactly the requested reference; otherwise `OPERATOR_SIGNATURE_INVALID` and no gatekeeper call. The connection is `https://` with an optional mTLS client certificate from `railgate.payment-network.ssl-bundle`.

### Residual risks

- Compromise of the central bank's mTLS client certificate would allow an attacker to submit settlement requests as if they were from the legitimate operator. This is a standard PKI operational risk and is addressed by the central bank's own certificate-management policies.
- **Verdict replay within the skew window** *(1.7.0)*. `sv1` carries no per-call nonce or request id, so a genuine verdict for an identical `(certSerial, issuerDn, digestHex)` can be presented again within `verdict-max-skew` (60 s by default). The replay record (Tampering) refuses a second allow for the same transaction reference regardless.
- **Pinned keys are trusted as configured** *(1.7.0)*. The certificates in both `trusted-keys` files are not chained to a CA and their validity and revocation are not checked; withdrawing one means removing it and restarting. With `require-signed-verdict=true` but no gatekeeper `trusted-keys`, railgate starts with a WARN and denies every settlement that reaches the gatekeeper — fail-closed, but an outage.
- With `require-signed-verdict=false` and no `trusted-keys` (the `dev` profile against a signing gatekeeper), a signed verdict is used unchecked (`UNVERIFIED`), and the TLS identity is again the whole of the assurance. That configuration must not be deployed.

---

## Tampering

### Assets at risk

- The cryptographic artefacts (digest, signature) supplied by the payment-network operator to railgate.
- The record of which transaction references and payout instruction ids railgate has allowed *(1.7.0)*.
- The verification result returned by the gatekeeper.
- The audit-log records of railgate decisions.

### Attack vectors

- An intermediary between railgate and the payment-network operator alters the digest or signature in transit, attempting to bypass verification.
- An intermediary between railgate and the gatekeeper alters the verification result.
- A compromised railgate operator alters the audit-log retroactively to hide a denied settlement that was nonetheless processed by an out-of-band channel.

### Mitigations

- TLS protects the integrity of communication between railgate and the gatekeeper, and `GatekeeperClient` will not start against a non-`https` base URL unless explicitly overridden. Since 1.7.0 the verdict is also signed and verified (Spoofing), so an altered verdict is denied rather than acted on. The payment-network operator link is covered in `http` mode *(1.7.0)*: `https://` (an `http://` base URL is refused unless `railgate.payment-network.allow-insecure-http=true`, which logs a WARN), optional mTLS, and the operator's `op1` signature over the artefacts, so an artefact changed in transit is `OPERATOR_SIGNATURE_INVALID`. The signature makes the operator accountable for its answer; it does not show that the artefacts are those the originating bank submitted. No operator offers this interface yet, and the client has been tested only against a reference operator. The other two implementations remain: `InMemoryPaymentNetworkClient` (the default) and `FilePaymentNetworkClient` (`railgate.payment-network.mode=file`), which reads the artefacts from a local file with no integrity protection of its own, so whoever can write that file controls the digest, signature and serial railgate submits; it is for local end-to-end runs only.
- Cryptographic verification at the gatekeeper is performed against the digest as supplied by railgate; if the digest has been tampered with in transit, the signature verification will fail and `signatureValid=false` will be returned. The orchestrator's default-deny behaviour blocks the settlement.
- `GatekeeperClient` rejects malformed cryptographic material before it is forwarded: the digest must be 128 hexadecimal characters, the signature must decode as base64 and be at most 4096 characters, the certificate serial must be hexadecimal (optional `0x`) and at most 128 characters, and the issuer DN must parse as an RFC 4514 name and be at most 512 characters — the formats and `@Size` limits of gatekeeper's `SignatureVerificationRequest`. The result is `INVALID_SIGNATURE_MATERIAL` and a deny, which the orchestrator passes through rather than reporting as `SIGNATURE_INVALID`. This does not detect substitution of *valid* material; it stops malformed material from consuming a supervisory call and from being reported as an accusation against the originating bank.
- For audit-log integrity, production deployments should back the in-memory `RailgateAuditLog` with a hash-chained append-only persistent log (cf. `AppendOnlyFileAuditLog` in the gatekeeper repo). This is documented as a known production extension point in the peer-review guide.

### Residual risks

- The reference implementation's in-memory audit log does not provide tamper-evidence across restarts. Production deployments must replace it; the in-memory adapter is reference-only.
- **Transaction-reference reuse** *(changed in 1.7.0)*. Until 1.6.0 railgate never recorded a reference as consumed, so a settlement that reused the reference of an earlier, genuinely signed payout was verified against that payout's artefacts and allowed, whoever submitted it. `ReplayGuard` now reserves the reference and the operator's `payoutInstructionId` atomically before the gatekeeper call, commits both on an allow and releases them on a deny; a second use, or one while the first is in flight, is `REFERENCE_ALREADY_SETTLED`. Residuals: the record is local to one railgate instance (several instances do not share it); without `railgate.replay.path` it is in memory and lost on restart; the journal is not tamper-evident (no hash chain, no signature, no file permissions set beyond the umask), so whoever can edit it can remove a reference and re-enable it after a restart; it is never pruned; and a reference railgate allowed whose settlement then failed downstream cannot be allowed again. In the `in-memory` and `file` modes there is no `payoutInstructionId`, so only the reference counts. Whether a reference can settle twice across instances is still decided by the settlement rail's duplicate detection. `DECLARED_CERT_MISMATCH` remains the cross-check against a serial the settlement message declares.

---

## Repudiation

### Assets at risk

- A settlement-rail operator denies that railgate returned `allow=true` for a specific transaction (claiming the transaction was processed despite a default-deny).
- A bank denies that railgate blocked a specific settlement (claiming the bank's transaction was processed when in fact it was not).

### Mitigations

- Every settlement decision is recorded in `RailgateAuditLog` with timestamp, transaction reference, decision (allow / deny), structured reason code, and, where the gatekeeper was called, two gatekeeper references. The two denials produced outside the orchestrator carry the reference as well since 1.8.0: `INVALID_REQUEST` the one the rejected request stated, and `INTERNAL_ERROR` the one of the request whose evaluation failed. An `INTERNAL_ERROR` for a body that could not be read as a settlement request has none, because none was read. Until 1.7.0 all of these were recorded without a reference.
- The first, `gatekeeperAuditEntryId`, is the gatekeeper's `auditEntryId`: the approval-registry `verificationId` the compliance verdict was read from. It does not identify a settlement decision. It is shared by every settlement against the same certificate and by that issuance's `VERIFY` and `CONFIRM` audit entries, and it is `null` when the gatekeeper found no registry entry (`CERT_NOT_FOUND`). Until 1.5.0 it was the only reference, and this document described it as referencing "the gatekeeper audit entry".
- The second, `gatekeeperAuditEntryHashHex` (since 1.5.0, from a gatekeeper at 1.5.0 or later), is the `thisEntryHashHex` of the `SETTLEMENT_VERIFY` entry the gatekeeper appended for this call, `CERT_NOT_FOUND` included. That entry is signed with the gatekeeper's seal and chained in its hash-chained log, and the hash names exactly one entry there, so each railgate decision can be matched to the gatekeeper's record of the same call in an audit export. Until 1.6.0 railgate stored the value without being able to check it, because the response was unsigned. Since 1.7.0 the hash is inside the gatekeeper's signed `sv1` form, so with a verified verdict (`verdictSignature=VERIFIED` in the audit entry) it is the gatekeeper's own statement; the supervisor's reconciliation with a gatekeeper export remains the way to show the entry exists, and a hash that appears in no gatekeeper export did not come from the gatekeeper. Triangulation across the two logs makes both repudiation directions difficult. Decisions taken without calling the gatekeeper (`NOT_REGULATED`, `DORA_32_AUDIT_MISSING`, `DECLARED_CERT_MISMATCH`, `INVALID_SIGNATURE_MATERIAL`, `NETWORK_ERROR`, and since 1.7.0 `OPERATOR_SIGNATURE_INVALID` and `REFERENCE_ALREADY_SETTLED`) carry neither reference, and neither do `VERDICT_SIGNATURE_INVALID` and `VERDICT_STALE`: the gatekeeper was called, but railgate discards the references of a verdict it did not accept.

### Residual risks

- The reference implementation's audit log is not signed by railgate itself. A production deployment may want to add per-entry signing using a railgate-operator key (analogous to gatekeeper's `EphemeralReceiptSigner` / `ConfiguredReceiptSigner` pattern) so that each audit entry is independently verifiable.
- The log is capped at 10 000 entries and discards its oldest records beyond that, so "every settlement decision is recorded" holds only within the retention window. `GET /api/v1/audit/health` reports the discarded count so that a gap is detectable rather than invisible, and the transaction reference, the message and the two gatekeeper references are stripped of CR and LF before they are stored or logged, as are the certificate serial and transport-error text `GatekeeperClient` logs, so an upstream value cannot forge additional lines in the operator's log. Until 1.5.0 the audit-entry identifier, the serial and the error text were logged raw. The same holds, since 1.8.0, for an exception `SettlementExceptionHandler` logs: it writes a copy in which every message has passed the same replacement and is cut to 512 characters, with the stack traces unchanged. Until 1.7.0 it logged the exception as it was, and the message of a JSON parse failure quotes the request, so an authenticated caller could start a line of its own choosing in the log.

---

## Information disclosure

### Assets at risk

- Transaction payload content (amounts, sender/receiver identity, business message).
- The signature artefacts and certificate identifiers.

### Attack vectors

- An adversary intercepting railgate's outbound call to the gatekeeper attempts to read transaction details.
- An adversary obtaining railgate's audit log attempts to reconstruct transaction history.

### Mitigations

- **Data minimisation by design.** The contract between railgate and the gatekeeper carries only `(certSerial, issuerDn, digestHex, signatureBase64)` — no transaction payload content. Even if an intercepting adversary obtains the full request body, they recover only the SHA-512 digest, which is one-way: the original transaction cannot be reconstructed from it.

- **Residual: the digest is supplied, not recomputed.** railgate verifies that the signature is valid over the digest it received; it cannot verify that the digest corresponds to the pacs.008 message being settled, because the settlement request carries a transaction reference rather than the signed fields, and because Swish aliases are resolved to IBAN by the payment-network operator before settlement. A substitution performed by that operator between signing and settlement is therefore outside what this component detects. Closing this requires the settlement message to carry the signed fields — a rail participation condition, not a change to this artefact.
- The audit log records only the transaction reference (a UETR), the binary decision, the reason code, the message, the two gatekeeper references (registry `verificationId` and settlement audit-entry hash) and, since 1.7.0, the verdict-signature status. No payment amounts, no sender/receiver identifiers, no business message content. An adversary reading the audit log learns only that a settlement attempt was decided, not what it was for.
- The replay journal *(1.7.0, when `railgate.replay.path` is set)* records, for every allowed regulated settlement, the transaction reference, the operator's payout instruction id (in `http` mode) and the time of the allow, without limit. It holds no amounts or parties, but it is a durable list of payout references at the rail; it is protected only by the host's file permissions (railgate sets none).
- This data-minimisation contract is enforced architecturally by the JSON wire format and by `GatekeeperClientTest.forwardsExactlyTheFourDataMinimisedFields`, which asserts against the outbound request body that it carries exactly those four fields and no fifth.

### Residual risks

- The transaction reference (UETR) does identify a specific transaction. An adversary with access to BOTH the railgate audit log AND a payment-network operator's transaction database could correlate decisions to specific transactions. This is unavoidable given railgate must reference the transaction it has decided on; mitigation belongs at the database-access-control layer of each operator.

---

## Denial of service

### Assets at risk

- railgate's availability to the central-bank settlement pipeline.
- The gatekeeper's availability as queried by railgate.

### Attack vectors

- Flooding railgate with synthetic settlement requests to overwhelm its verification throughput, causing legitimate settlements to time out.
- Causing railgate's outbound calls to the gatekeeper to time out, triggering `NETWORK_ERROR` and default-deny on legitimate settlements.

### Mitigations

- `/api/v1/**` requires authentication, so synthetic floods must first get past whatever mechanism the deployer wired in. With the shipped HTTP Basic that is a shared secret; with mTLS it is a client certificate. Either way the reduction in attack surface comes from the deployment, not from railgate.
- **railgate has no rate limiting.** gatekeeper enforces per-principal token buckets on its endpoints; railgate has no equivalent, so an authenticated caller can issue settlement prechecks at whatever rate it likes and each one becomes an outbound gatekeeper call. Rate limiting at the rail is a reverse-proxy or gateway concern in a central-bank deployment; it is not in this code.
- railgate's verification logic is computationally cheap (a single HTTP call to gatekeeper with a small body). Per-request resource consumption is bounded: request bodies are capped at `railgate.limits.max-http-request-size` (16 KB by default, `RequestSizeLimitFilter`), headers at 8 KB, the transaction reference at 36 characters and the other request fields at their ISO 20022 lengths, and every text field retained in the audit log at 128 characters (the message at 512). Until 1.6.0 neither the body nor the transaction reference was bounded, so this sentence did not hold.
- `GatekeeperClient` applies a connect timeout and a read timeout (`railgate.gatekeeper.connect-timeout`, `railgate.gatekeeper.read-timeout`; defaults PT2S and PT5S), so an unresponsive gatekeeper produces a `NETWORK_ERROR` deny rather than holding the calling thread. For gatekeeper-side availability, production deployments should run multiple gatekeeper replicas behind a load balancer. The operator client in `http` mode *(1.7.0)* has its own timeouts (`railgate.payment-network.connect-timeout`, `read-timeout`; PT2S and PT5S). *(Changed 1.8.0.)* For both clients the read timeout bounds the whole answer, from the request to its last byte, both must be positive, and at most 65 536 bytes of an answer are read; the exchange is abandoned when the time is up. Until 1.7.0 both used `HttpURLConnection`, whose read timeout bounds each read separately: a gatekeeper or operator that sent one byte before each one expired held the calling thread for as long as it chose, zero meant no timeout at all for the gatekeeper, and the gatekeeper's answer had no size limit. Both now use the JDK `HttpClient`, whose exchange can be cancelled as a whole (`OutboundHttp`).
- A second evaluation of a reference that is in flight is refused at once (`REFERENCE_ALREADY_SETTLED`) rather than queued, so concurrent duplicates cannot pile up behind one gatekeeper call *(1.7.0)*.
- The audit log is a bounded ring buffer (10 000 entries). Under sustained load it discards its oldest records, which is a loss of the supervisory record rather than a memory-exhaustion failure; discards are counted, reported at `GET /api/v1/audit/health`, and produce a WARN once per thousand.

### Residual risks

- Coordinated denial-of-service against the gatekeeper would cascade to railgate, blocking all regulated settlements until availability is restored. This is acceptable: blocking settlements until verification can be performed is the correct behaviour under default-deny. The same holds for the payment-network operator in `http` mode.
- The replay record grows without bound in memory and on disk, and start-up reads the whole journal *(1.7.0)*.
- A failed journal write makes every later allow `INTERNAL_ERROR` until restart *(1.7.0)*: a full disk stops regulated settlement rather than allowing without a record.

---

## Elevation of privilege

### Assets at risk

- Authorisation to invoke `/api/v1/settle/precheck` and to read the audit trail at `/api/v1/audit`.

### Attack vectors

- An adversary attempts to call `/api/v1/settle/precheck` without being an authorised settlement-rail caller, hoping to obtain `allow=true` or to read the audit trail.

### Mitigations

- `SecurityConfig` places every path, `/api/v1/**` included, behind one authenticated, stateless, CSRF-exempt filter chain. Until 1.4.0 there was no `SecurityFilterChain` bean at all, so Spring Boot's default applied: session-based and CSRF-protected, which a machine caller cannot satisfy, and form login, which it cannot follow.
- **No request creates a server session** *(changed 1.8.0)*. The chain covers the API and every other path (Swagger UI and the OpenAPI document under the `dev` profile, error paths, unknown paths) alike: HTTP Basic, no form login, no logout endpoint, and CSRF protection off, because the callers are machines without a browser session and nothing outside `/api/v1/**` changes state. From 1.4.0 to 1.7.0 the paths outside `/api/v1/**` were behind a second chain that reproduced Spring Boot's default, and every unauthenticated request to such a path — `GET /anything` — left a session in memory for the 30-minute session timeout (measured: 3,000 requests, 3,000 sessions of about 9 kB), so a caller without credentials could exhaust the heap of the settlement gate. `SecurityConfigStatelessTest` asserts 401, no redirect, no `Set-Cookie` and no session for requests with and without credentials, inside and outside `/api/v1/**`. The number of requests itself is still not limited by railgate; that is the fronting proxy's or the deployer's.
- **There is no role model at the railgate side.** Every authenticated caller of `/api/v1/**` may both submit prechecks and read the audit trail; there is no `SETTLEMENT_RAIL` role, and earlier revisions of this document claimed one that the reference configuration never contained. `SETTLEMENT_RAIL` exists at the *gatekeeper*, where it authorises railgate to call `POST /api/v1/verify`. A deployer who needs to separate submission from audit read at railgate adds path matchers and a principal-to-role mapping in the manner of gatekeeper's `RoleMappingProperties`.
- The authentication mechanism is the deployer's: HTTP Basic ships, mTLS with `.x509(...)` principal extraction is what a central-bank deployment should use.
- The audit trail endpoint is read-only and contains no payment payload content (see Information Disclosure above), so unauthorised read of the audit trail still does not leak transaction detail. It does leak transaction references and decisions to any authenticated caller.

### Residual risks

- Mis-configured role mappings could grant settlement-rail privilege to unintended principals. Operators must follow the central bank's existing mTLS-client-certificate-issuance procedures and audit role mappings periodically.

---

## Model coverage and what is explicitly not in scope

This threat model covers the railgate component as a software artefact. It does not model:

- The integrity of the central-bank settlement system itself (RIX-INST). That is the central bank's own threat-model concern and is governed by the central bank's existing operational security regime.
- The integrity of the payment-network operator's signature-retrieval endpoint. That belongs in Getswish AB's (or equivalent's) threat model.
- The integrity of the financial-entity's HSM attestation flow. That belongs in the `hsm/` threat model.
- The integrity of the supervisor's gatekeeper instance and its audit-log. That belongs in the `gatekeeper/` threat model.

The triadic-system threat surface is the union of these four documents (railgate, hsm, gatekeeper, plus the operational threat models maintained by the central bank and the payment-network operator).
