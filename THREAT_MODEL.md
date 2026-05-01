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

- Production deployments require mTLS between railgate and its callers, and between railgate and the gatekeeper. Spring Security's mTLS configuration restricts access to authorised central-bank-side clients and pins the gatekeeper certificate at the railgate side.
- The orchestrator never makes its decision on the basis of trust in the caller alone. Even when the caller is a properly authenticated settlement system, the verification result depends on the gatekeeper's response, which is itself signed by the supervisor and can be independently verified by an auditor.
- The gatekeeper's signed response is what the orchestrator allows on; a fraudulent unsigned response cannot mimic it.

### Residual risks

- Compromise of the central bank's mTLS client certificate would allow an attacker to submit settlement requests as if they were from the legitimate operator. This is a standard PKI operational risk and is addressed by the central bank's own certificate-management policies.

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

- TLS protects the integrity of communication between railgate and both the payment-network operator and the gatekeeper.
- Cryptographic verification at the gatekeeper is performed against the digest as supplied by railgate; if the digest has been tampered with in transit, the signature verification will fail and `signatureValid=false` will be returned. The orchestrator's default-deny behaviour blocks the settlement.
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

---

## Information disclosure

### Assets at risk

- Transaction payload content (amounts, sender/receiver identity, business message).
- The signature artefacts and certificate identifiers.

### Attack vectors

- An adversary intercepting railgate's outbound call to the gatekeeper attempts to read transaction details.
- An adversary obtaining railgate's audit log attempts to reconstruct transaction history.

### Mitigations

- **Data minimisation by design.** The contract between railgate and the gatekeeper carries only `(certSerial, issuerDn, digestHex, signatureBase64, signingCertificatePem)` — no transaction payload content. Even if an intercepting adversary obtains the full request body, they recover only the SHA-512 digest, which is one-way: the original transaction cannot be reconstructed from it.
- The audit log records only the transaction reference (a UETR), the binary decision, the reason code, and the gatekeeper audit-entry identifier. No payment amounts, no sender/receiver identifiers, no business message content. An adversary reading the audit log learns only that a settlement attempt was decided, not what it was for.
- This data-minimisation contract is enforced architecturally by the JSON wire format and by the `SettlementOrchestratorTest` data-minimisation assertion.

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

- Production deployments at the central-bank rail receive only authenticated traffic via mTLS, dramatically reducing the attack surface for synthetic floods.
- railgate's verification logic is computationally cheap (a single HTTP call to gatekeeper with a small body); per-request resource consumption is bounded.
- For gatekeeper-side availability, production deployments should run multiple gatekeeper replicas behind a load-balancer; the `GatekeeperClient` connection-timeout and read-timeout values are configurable.

### Residual risks

- Coordinated denial-of-service against the gatekeeper would cascade to railgate, blocking all regulated settlements until availability is restored. This is acceptable: blocking settlements until verification can be performed is the correct behaviour under default-deny.

---

## Elevation of privilege

### Assets at risk

- Authorisation to invoke `/api/v1/settle/precheck` and to read the audit trail at `/api/v1/audit`.

### Attack vectors

- An adversary attempts to call `/api/v1/settle/precheck` without being an authorised settlement-rail caller, hoping to obtain `allow=true` or to read the audit trail.

### Mitigations

- Both endpoints are behind Spring Security mTLS in production deployments. The reference application configuration assumes a `SETTLEMENT_RAIL`-equivalent role at the railgate side; the deployer wires this role via mTLS principal-extraction matching the central bank's client-certificate convention.
- The audit trail endpoint is read-only and contains no payment payload content (see Information Disclosure above), so unauthorised read of the audit trail still does not leak transaction detail.

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
