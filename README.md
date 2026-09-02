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
     • LclInstrm/Cd = "SWISH" (case-insensitive, trimmed), or
     • OrgId(debtor) + PrvtId(creditor) → org → private = Swish utbetalning
     • either flag missing → treated as regulated
       ↓
   railgate → Getswish.getSignature(transactionReference)
       ↓
   railgate → gatekeeper.verify(certSerial, issuerDn, digest, signature)
       ↓
   gatekeeper:
     1. Look up cert via (certSerial, issuerDn)
     2. Signature.getInstance("SHA512withRSA")
          .initVerify(publicKey); update(digest); verify(signature)
     3. Check compliance status of audit entry
     4. Return {signatureValid, compliant, reason}
       ↓
   railgate decides: allow ↔ default-deny (block settlement)
       ↓
[Audit log entry recorded]
```

**What regulated-payment detection rests on.** Both party-type flags are
metadata. The settlement system derives them from `Dbtr/Id/OrgId` and
`Cdtr/Id/PrvtId` and hands them to railgate in `SettlementRequest`;
railgate does not receive the pacs.008, does not parse it, and cannot
recompute the derivation. Earlier versions of this documentation said the
structural path "cannot be circumvented by the originating bank". That
overstates what the code does. What holds is narrower: the structural path
is harder to suppress than the instrument code, because a payout has to
identify its creditor as a private person somewhere in the message for the
payment to reach one; both flags are mandatory, so omitting one is a 400
rather than a pass-through; and a request that reaches the detector without
them is treated as regulated. An absent classification produces
verification, never an allow.

## Data minimisation

railgate **never** sees, transports, or stores transaction payload
content — no amounts, no account or alias identifiers, no business message.

Two data sets have to be distinguished, because they are not the same set.

**What railgate receives** from the settlement rail, in
`SettlementRequest`:

- the **transaction reference** (pacs.008 EndToEndId or UETR)
- the **local instrument code**, when the originating bank populated it
- the **party-type flags** `debtorIsOrganization` and
  `creditorIsPrivatePerson`, derived by the settlement system from
  `Dbtr/Id/OrgId` and `Cdtr/Id/PrvtId`
- the **debtor and creditor BICs** — the originating and receiving banks
- optionally a **declared certificate serial**

The BICs and the party-type flags identify institutions and party
categories. They are not payload content and they are not personal data
about the payer or payee, but they are more than the digest, and the
earlier version of this section did not list them.

**What railgate forwards to the supervisor's gatekeeper**, which is the
boundary the data-minimisation claim is about:

- the SHA-512 **digest** (a 64-byte cryptographic hash, not the payload)
- the RSA **signature** over that digest
- the certificate **serial number** and issuer DN

Nothing else crosses that boundary. The test
`GatekeeperClientTest.forwardsExactlyTheFourDataMinimisedFields` asserts
that the outbound body carries exactly those four fields. The supervisor
never receives the BICs, the party-type flags, the transaction amounts,
sender or receiver detail, business message content, or any payload
bytes. This satisfies GDPR Art 5(1)(c) data
minimisation and the proportionality requirement implicit in DORA Art 32
supervisory data processing.

railgate's own audit log records the transaction reference, the decision,
the reason code and the gatekeeper audit-entry identifier — not the BICs
and not the flags.

SHA-512 collision resistance ensures that a valid signature over the
digest binds that signature to the payload the digest was taken over.
It does not, on its own, bind the signature to the pacs.008 message
being settled: railgate receives the digest from the payment-network
operator and does not recompute it, because `SettlementRequest` carries
what RIX-INST delivers — a transaction reference, an instrument code and
BICs — and not the amount, currency or counterparty identifiers the
signature was made over. Counterparty identity is in any case resolved
from Swish alias to IBAN by the payment-network operator before
settlement, so the identifier the customer signed is not the identifier
railgate sees.

The residual is therefore an assumption about the payment-network
operator, and it is not a property of the architecture. Closing it
requires the settlement message to carry the signed fields, which is a
participation condition for the rail rather than a change to this
artefact: RIX terms are set by the system owner, and ISO 20022 provides
the extension points. railgate implements what is verifiable given what
the rail delivers today.

## Default-deny

When verification cannot be completed, settlement is blocked. The
originating bank receives a structured reason code. This is the complete
set railgate can produce — no other value is reachable:

| Reason code                | HTTP | allow | Meaning                                                            |
|----------------------------|------|-------|--------------------------------------------------------------------|
| ALLOWED                    | 200  | true  | Signature verified and certificate compliant; settlement proceeds.  |
| NOT_REGULATED              | 200  | true  | Explicitly classified, and not organisation-to-private. Passed through without verification. |
| DORA_32_AUDIT_MISSING      | 403  | false | No signature artefacts found at the payment-network operator.       |
| CERT_NOT_FOUND             | 403  | false | Certificate matches no gatekeeper audit entry — issuance was circumvented, or the wrong certificate was used. |
| SIGNATURE_INVALID          | 403  | false | Cryptographic verification failed at the gatekeeper.                |
| CERT_NON_COMPLIANT         | 403  | false | Certificate exists but was not issued through a compliant flow.     |
| NETWORK_ERROR              | 403  | false | gatekeeper unreachable, timed out, or returned an unusable body.    |
| INVALID_SIGNATURE_MATERIAL | 403  | false | The artefacts from the payment-network operator are malformed (digest not 128 hex characters, signature not base64, blank certificate serial or issuer DN). The gatekeeper was not called. |
| INVALID_REQUEST            | 400  | false | The settlement request failed Bean Validation — a missing party-type flag, a blank transaction reference, an over-long instrument code. No verification was attempted. |
| INTERNAL_ERROR             | 403  | false | Any unhandled failure inside railgate. Default-deny; no detail about the failure is returned to the caller. |

`CERT_NOT_FOUND`, `CERT_NON_COMPLIANT`, `SIGNATURE_INVALID` and
`NETWORK_ERROR` are read from the gatekeeper's own `reason` field and
passed through unchanged; `INVALID_SIGNATURE_MATERIAL` is produced by
railgate's client before any call is made. Any other `reason` value falls
back to a derivation from the two booleans, which yields
`SIGNATURE_INVALID` when the signature did not verify and
`CERT_NON_COMPLIANT` otherwise.

**Known limitation.** The gatekeeper can also answer `MALFORMED_INPUT` and
`ALGORITHM_NOT_SUPPORTED`. Neither is in the pass-through set, so both
reach the originating bank as `SIGNATURE_INVALID` — a defect in the
supervisor-side input handling reported as a bad signature. This is the
same conflation the `NETWORK_ERROR` fix in 1.3.0 addressed, narrowed but
not eliminated.

The bank may resubmit the settlement with valid data. In the absence of
valid data, the transaction does not settle.

## Build and run

```bash
mvn -B clean verify                          # build + tests + OWASP scan
mvn spring-boot:run                          # start on port 8082
java -jar target/railgate-1.4.0.jar          # or run the built jar
```

Configuration via `application.yml`:

| Property                                    | Default                  | Purpose                                                                 |
|---------------------------------------------|--------------------------|-------------------------------------------------------------------------|
| `railgate.payment-network.mode`             | `in-memory`              | Payment-network operator client implementation                          |
| `railgate.gatekeeper.base-url`              | `https://localhost:8443` | Supervisor's gatekeeper instance URL. Must be `https://` unless the flag below is set. |
| `railgate.gatekeeper.allow-insecure-http`   | `false`                  | Permit a non-`https` base URL. Local development only — start-up fails without it, and logs a WARN with it. |
| `railgate.gatekeeper.connect-timeout`       | `PT2S`                   | TCP connect timeout for gatekeeper calls (ISO-8601 duration)            |
| `railgate.gatekeeper.read-timeout`          | `PT5S`                   | Response read timeout for gatekeeper calls (ISO-8601 duration). Exceeding either yields `NETWORK_ERROR` and a deny. |
| `railgate.regulated.local-instrument-codes` | `SWISH`                  | LclInstrm/Cd values that identify regulated payments. Matched case-insensitively, whitespace-trimmed. |

## Transport and authentication

**Outbound, railgate → gatekeeper.** The base URL must be `https://`;
`GatekeeperClient` throws `IllegalStateException` at start-up otherwise, so
a plain-HTTP supervisor link is a boot failure rather than a silent
downgrade. The TLS trust material is not configured by railgate: use Spring
Boot's standard SSL properties (`spring.ssl.bundle.jks.*` or
`javax.net.ssl.trustStore`) for the truststore, and the same bundle for the
client certificate where the gatekeeper requires mTLS — gatekeeper's
`SETTLEMENT_RAIL` role is bound to the client certificate's CN. A reverse
proxy or service mesh terminating mTLS in front of railgate is an equally
valid arrangement; in that case point `base-url` at the proxy.

**railgate does not verify signed gatekeeper responses.** The gatekeeper
signs its receipts, and the verdict railgate consumes is not one of them:
`POST /api/v1/verify` returns plain JSON, and `GatekeeperClient`
deserialises `signatureValid` and `compliant` without checking any
signature over them. The integrity of the verdict therefore rests entirely
on the transport and on the gatekeeper's own controls. An attacker who can
terminate or rewrite the TLS session can return `allow`. This is why the
`https://` requirement is enforced rather than recommended, and it is the
reason mTLS matters here beyond authentication. See `THREAT_MODEL.md`.

**Inbound, settlement rail → railgate.** `SecurityConfig` requires
authentication on `/api/v1/**` with CSRF disabled and sessions stateless;
everything else keeps Spring Boot's default posture. The mechanism is the
deployer's choice and is not fixed by this repo:

- **mTLS** (what a central-bank deployment should use). Configure
  `server.ssl.client-auth=need` with a truststore holding the settlement
  system's CA, then replace `.httpBasic(...)` on the `/api/v1/**` chain
  with `.x509(x509 -> x509.x509PrincipalExtractor(...))`. gatekeeper's
  `SecurityConfig` shows the full arrangement including principal
  extraction and role mapping.
- **HTTP Basic** (what ships). Usable immediately; Spring Boot generates a
  password at start-up unless `spring.security.user.*` is set.

railgate has no role model of its own — every caller of `/api/v1/**` is the
settlement rail — so the chain authenticates without authorising further.

## Endpoints

| Method | Path                          | Purpose                                          |
|--------|-------------------------------|--------------------------------------------------|
| POST   | `/api/v1/settle/precheck`     | Pre-settlement verification (returns allow/deny) |
| GET    | `/api/v1/audit`               | Audit trail of railgate decisions                |
| GET    | `/api/v1/audit/health`        | Retained, capped and discarded audit-entry counts |
| GET    | `/swagger-ui.html`            | OpenAPI documentation — `dev` profile only       |

`/swagger-ui.html` and `/v3/api-docs` are served only with
`--spring.profiles.active=dev` (`application-dev.yml`); every other profile
has `springdoc.api-docs.enabled=false` and `springdoc.swagger-ui.enabled=false`.

Sample precheck request. `transactionReference`, `debtorIsOrganization`
and `creditorIsPrivatePerson` are required; omitting either flag is a 400,
not a pass-through.

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
