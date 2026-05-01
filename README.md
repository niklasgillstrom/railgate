# railgate — Settlement-layer enforcement reference for DORA-compliant payment infrastructure

Reference implementation of the settlement-rail enforcement component
described in the companion academic article. railgate sits at the
central-bank settlement rail (RIX-INST in the Swedish reference
deployment, generalisable to TIPS, FedNow, FPS, NPP, etc.) and performs
deterministic cryptographic signature verification at settlement time.
Companion artefact to **hsm**
([DOI 10.5281/zenodo.19930310](https://doi.org/10.5281/zenodo.19930310))
and **gatekeeper**
([DOI 10.5281/zenodo.19930395](https://doi.org/10.5281/zenodo.19930395)).

## Why three components

The triple **hsm + gatekeeper + railgate** operationalises a
quadruple-triangulation model. Each component answers one specific
question:

| Component  | Question answered                                                            |
|------------|------------------------------------------------------------------------------|
| hsm        | Is the key HSM-bound and on-device generated?                                |
| gatekeeper | Is the certificate-issuance compliant, and does the signature verify?        |
| railgate   | Is settlement permitted, given the gatekeeper response and no circumvention? |

Each component is deployable independently. railgate's role is not
verification (gatekeeper does that). railgate's role is **enforcement at
the chokepoint where verification can no longer be bypassed** — the
central-bank settlement rail.

## Architecture overview

```
[Customer HSM] ─signs digest with private key
       ↓
[Bank Swish-API mottagande]
       ↓
[Bank → Getswish AB API call] ─Getswish stores {digest, signature, certSerial}
       ↓
[Bank → RIX-INST pacs.008 settlement initiation]
       ↓
[Riksbanken / settlement-layer] ─railgate intercepts pacs.008
       ↓
   railgate detects regulated payment via:
     • LclInstrm/Cd = "SWISH", or
     • OrgId(debtor) + PrvtId(creditor) → org → private = Swish utbetalning
       ↓
   railgate → Getswish.getSignature(transactionReference)
       ↓
   railgate → gatekeeper.verify(certSerial, issuerDn, digest, signature)
       ↓
   gatekeeper:
     1. Look up cert via (certSerial, issuerDn)
     2. Hash-verify: createVerify('sha512WithRSAEncryption').update(digest).verify(public_key, signature)
     3. Check compliance status of audit entry
     4. Return {signature_valid, compliant}
       ↓
   railgate decides: allow ↔ default-deny (block settlement)
       ↓
[Audit log entry recorded]
```

## Data minimisation

railgate **never** sees, transports, or stores transaction payload
content. It handles only:

- the SHA-512 **digest** (a 64-byte cryptographic hash, not the payload)
- the RSA **signature** over that digest
- the certificate **serial number** and issuer DN
- a binary **decision** (allow / deny) with a structured reason code

The supervisor (operating gatekeeper + railgate) never receives transaction
amounts, sender or receiver detail, business message content, or any
payload bytes. This satisfies GDPR Art 5(1)(c) data minimisation and the
proportionality requirement implicit in DORA Art 32 supervisory data
processing.

SHA-512 collision resistance ensures that a valid signature over the
digest cryptographically binds the signature to the exact transaction
that was performed. Verification is therefore cryptographically
deterministic — there is no semantic gap between "verifying the digest"
and "verifying the transaction".

## Default-deny

When verification cannot be completed, settlement is blocked. The
originating bank receives a structured reason code:

| Reason code              | Meaning                                                              |
|--------------------------|----------------------------------------------------------------------|
| ALLOWED                  | Verification passed; settlement may proceed.                         |
| NOT_REGULATED            | Settlement is not subject to railgate enforcement.                   |
| DORA_32_AUDIT_MISSING    | No signature artefacts found at the payment-network operator.        |
| SIGNATURE_INVALID        | Cryptographic verification failed at gatekeeper.                     |
| CERT_NON_COMPLIANT       | Certificate exists but was not issued through a compliant flow.      |
| NETWORK_ERROR            | gatekeeper or payment-network operator unreachable; default-deny.    |
| VERIFICATION_FAILED      | Verification result did not return positive without specific reason. |

The bank may resubmit the settlement with valid data. In the absence of
valid data, the transaction does not settle.

## Build and run

```bash
mvn -B clean verify   # build + tests + OWASP scan
mvn spring-boot:run   # start on port 8082
```

Configuration via `application.yml`:

| Property                                           | Default                        | Purpose                                           |
|----------------------------------------------------|--------------------------------|---------------------------------------------------|
| `railgate.payment-network.mode`                    | `in-memory`                    | Payment-network operator client implementation    |
| `railgate.gatekeeper.base-url`                     | `http://localhost:8080`        | Supervisor's gatekeeper instance URL              |
| `railgate.regulated.local-instrument-codes`        | `SWISH`                        | LclInstrm/Cd values that identify regulated payments |

## Endpoints

| Method | Path                          | Purpose                                          |
|--------|-------------------------------|--------------------------------------------------|
| POST   | `/api/v1/settle/precheck`     | Pre-settlement verification (returns allow/deny) |
| GET    | `/api/v1/audit`               | Audit trail of railgate decisions                |
| GET    | `/swagger-ui.html`            | OpenAPI documentation                            |

Sample precheck request:

```json
{
  "transactionReference": "UETR-12345",
  "localInstrumentCode": "SWISH",
  "debtorIsOrganization": true,
  "creditorIsPrivatePerson": true,
  "debtorBic": "ESSESESS",
  "creditorBic": "HANDSESS"
}
```

## Legal basis

See `pom.xml` `<description>` for the full list of Union and Swedish
national-law provisions on which this implementation is based.

## License

MIT — see [`LICENSE`](LICENSE).

## Citation

See [`CITATION.cff`](CITATION.cff). When citing, please cite all three
companion artefacts together where appropriate.
