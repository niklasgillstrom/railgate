# Threat model — railgate

**Scope.** Threat model for the settlement-rail enforcement component that sits at a central-bank settlement system (RIX-INST in the Swedish reference deployment; generalisable to TIPS, FedNow, FPS, NPP) and orchestrates deterministic cryptographic signature verification at settlement time. The companion repositories `hsm/` (financial-entity-side HSM attestation verification) and `gatekeeper/` (NCA-operated certificate-issuance gate and settlement-time signature verification endpoint) have their own threat models covering threats specific to those layers; this document focuses on what becomes new or different when verification is consumed at the central-bank settlement chokepoint.

**Assumptions out of scope.** The host platform (network, OS, JVM, container runtime) is not modelled here. Production deployments are operated by central-bank IT under that organisation's own platform-security regime; the threat model below treats those as sound and focuses on what the Java code itself can and cannot guarantee. The pacs.008 ingress integration with the settlement pipeline is similarly out of scope — railgate's contract is the abstracted `SettlementRequest` model.

**Framework.** STRIDE.

---

## Spoofing

### Assets at risk

- The identity of the calling settlement system (central bank).
- The identity of the supervisor's gatekeeper instance (target of railgate's outbound calls).

### Attack vectors

- An adversary submits a fabricated `SettlementRequest` to railgate's `/api/v1/settle/precheck` endpoint, attempting to obtain `allow=true` for a transaction that has not actually been initiated by an authorised bank.
- An adversary impersonates the supervisor's gatekeeper, returning fraudulent `signatureValid=true, compliant=true` responses to railgate.

### Mitigations

- `SecurityConfig` requires authentication on `/api/v1/**` and ships HTTP Basic as the reference mechanism. mTLS is the mechanism a central-bank deployment should use, and wiring it is the deployer's work, not something this repo performs: a truststore via `server.ssl.trust-store-*` with `server.ssl.client-auth=need`, and `.x509(...)` in place of `.httpBasic(...)` on the `/api/v1/**` chain. Until that is done, the caller is authenticated by a shared secret.
- Outbound, `GatekeeperClient` refuses a non-`https` base URL at start-up unless `railgate.gatekeeper.allow-insecure-http=true`, so the supervisor link cannot silently be plain text. The truststore and any client certificate come from Spring Boot's standard SSL properties; the gatekeeper certificate is **not** pinned by railgate.
- The orchestrator never makes its decision on the basis of trust in the caller alone. Even when the caller is a properly authenticated settlement system, the verification result depends on the gatekeeper's response.
- **railgate does not verify a signature over the gatekeeper's response.** `POST /api/v1/verify` returns plain JSON and `GatekeeperClient` deserialises `signatureValid` and `compliant` from it directly. The gatekeeper signs its *receipts*, and the settlement-time verdict is not one of them. An auditor can independently verify the gatekeeper's own signed audit entry after the fact; railgate cannot verify anything about the verdict at the moment it acts on it. Earlier revisions of this document asserted that "the gatekeeper's signed response is what the orchestrator allows on" and that "a fraudulent unsigned response cannot mimic it". Neither is true of this code: an adversary who can present a TLS certificate railgate's truststore accepts, or who terminates the connection at a compromised proxy, can return `signatureValid=true, compliant=true` and railgate will allow the settlement.

### Residual risks

- Compromise of the central bank's mTLS client certificate would allow an attacker to submit settlement requests as if they were from the legitimate operator. This is a standard PKI operational risk and is addressed by the central bank's own certificate-management policies.
- Because the verdict is unsigned, the gatekeeper's TLS identity is the whole of railgate's assurance that it is talking to the gatekeeper. Closing this residual means signing the verification response — the gatekeeper already has the key material and the canonicalisation machinery for its receipts — and verifying it in `GatekeeperClient`. That is a cross-repo change to the wire contract and is not in this release.

---

## Tampering

### Assets at risk

- The cryptographic artefacts (digest, signature) supplied by the payment-network operator to railgate.
- The verification result returned by the gatekeeper.
- The audit-log records of railgate decisions.

### Attack vectors

- An intermediary between railgate and the payment-network operator alters the digest or signature in transit, attempting to bypass verification.
- An intermediary between railgate and the gatekeeper alters the verification result.
- A compromised railgate operator alters the audit-log retroactively to hide a denied settlement that was nonetheless processed by an out-of-band channel.

### Mitigations

- TLS protects the integrity of communication between railgate and the gatekeeper, and `GatekeeperClient` will not start against a non-`https` base URL unless explicitly overridden. TLS is the *only* integrity protection on that link: see Spoofing above on the unsigned verdict. The payment-network operator link is not covered — `InMemoryPaymentNetworkClient` is the only implementation that ships, and the production HTTP client is a deployment extension point with its own transport configuration.
- Cryptographic verification at the gatekeeper is performed against the digest as supplied by railgate; if the digest has been tampered with in transit, the signature verification will fail and `signatureValid=false` will be returned. The orchestrator's default-deny behaviour blocks the settlement.
- `GatekeeperClient` rejects malformed cryptographic material before it is forwarded: the digest must be 128 hexadecimal characters, the signature must decode as base64, and the certificate serial and issuer DN must be non-blank. The result is `INVALID_SIGNATURE_MATERIAL` and a deny, which the orchestrator passes through rather than reporting as `SIGNATURE_INVALID`. This does not detect substitution of *valid* material; it stops malformed material from consuming a supervisory call and from being reported as an accusation against the originating bank.
- For audit-log integrity, production deployments should back the in-memory `RailgateAuditLog` with a hash-chained append-only persistent log (cf. `AppendOnlyFileAuditLog` in the gatekeeper repo). This is documented as a known production extension point in the peer-review guide.

### Residual risks

- The reference implementation's in-memory audit log does not provide tamper-evidence across restarts. Production deployments must replace it; the in-memory adapter is reference-only.

---

## Repudiation

### Assets at risk

- A settlement-rail operator denies that railgate returned `allow=true` for a specific transaction (claiming the transaction was processed despite a default-deny).
- A bank denies that railgate blocked a specific settlement (claiming the bank's transaction was processed when in fact it was not).

### Mitigations

- Every settlement decision is recorded in `RailgateAuditLog` with timestamp, transaction reference, decision (allow / deny), structured reason code, and (where applicable) the gatekeeper audit-entry identifier.
- The audit record references the gatekeeper audit entry, which is itself signed by the supervisor and immutably recorded in the gatekeeper's hash-chained log. Triangulation across the two logs makes both repudiation directions difficult.

### Residual risks

- The reference implementation's audit log is not signed by railgate itself. A production deployment may want to add per-entry signing using a railgate-operator key (analogous to gatekeeper's `EphemeralReceiptSigner` / `ConfiguredReceiptSigner` pattern) so that each audit entry is independently verifiable.
- The log is capped at 10 000 entries and discards its oldest records beyond that, so "every settlement decision is recorded" holds only within the retention window. `GET /api/v1/audit/health` reports the discarded count so that a gap is detectable rather than invisible, and the transaction reference and message are stripped of CR and LF before they are stored or logged, so an upstream value cannot forge additional lines in the operator's log.

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
- The audit log records only the transaction reference (a UETR), the binary decision, the reason code, and the gatekeeper audit-entry identifier. No payment amounts, no sender/receiver identifiers, no business message content. An adversary reading the audit log learns only that a settlement attempt was decided, not what it was for.
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
- railgate's verification logic is computationally cheap (a single HTTP call to gatekeeper with a small body); per-request resource consumption is bounded.
- `GatekeeperClient` applies a connect timeout and a read timeout (`railgate.gatekeeper.connect-timeout`, `railgate.gatekeeper.read-timeout`; defaults PT2S and PT5S), so an unresponsive gatekeeper produces a `NETWORK_ERROR` deny rather than holding the calling thread. For gatekeeper-side availability, production deployments should run multiple gatekeeper replicas behind a load balancer.
- The audit log is a bounded ring buffer (10 000 entries). Under sustained load it discards its oldest records, which is a loss of the supervisory record rather than a memory-exhaustion failure; discards are counted, reported at `GET /api/v1/audit/health`, and produce a WARN once per thousand.

### Residual risks

- Coordinated denial-of-service against the gatekeeper would cascade to railgate, blocking all regulated settlements until availability is restored. This is acceptable: blocking settlements until verification can be performed is the correct behaviour under default-deny.

---

## Elevation of privilege

### Assets at risk

- Authorisation to invoke `/api/v1/settle/precheck` and to read the audit trail at `/api/v1/audit`.

### Attack vectors

- An adversary attempts to call `/api/v1/settle/precheck` without being an authorised settlement-rail caller, hoping to obtain `allow=true` or to read the audit trail.

### Mitigations

- `SecurityConfig` places `/api/v1/**` behind an authenticated, stateless, CSRF-exempt filter chain. Until 1.4.0 there was no `SecurityFilterChain` bean at all, so Spring Boot's default applied: session-based and CSRF-protected, which a machine caller cannot satisfy, and form login, which it cannot follow.
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
