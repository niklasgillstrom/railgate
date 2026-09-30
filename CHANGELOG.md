# Changelog — railgate

This file starts at 1.4.0. Earlier releases are documented in the git history, in `PEER_REVIEW_GUIDE.md` and in `CROSS_REFERENCE.md`.

## 1.5.0

**railgate 1.5.0 requires gatekeeper 1.5.0 or later.** Against gatekeeper 1.4.0 it denies every regulated settlement, exactly as railgate 1.4.0 did.

### Contract defect

- **Every regulated settlement was denied against the real gatekeeper.** railgate calls `POST /api/v1/verify` with four fields: `certSerial`, `issuerDn`, `digestHex`, `signatureBase64`. gatekeeper 1.4.0 required a fifth, `signingCertificatePem`, and answered any request without it with `signatureValid=false, reason=MALFORMED_INPUT` — which is every request railgate sends. `MALFORMED_INPUT` was not in railgate's pass-through set, so the orchestrator fell back to the booleans and reported `SIGNATURE_INVALID`. The result was not a degraded service but a closed one: no regulated settlement could be allowed, and every originating bank was told its signature was bad.

  It survived review because no test ever put the two sides together. `GatekeeperClientTest` drives railgate's client against `MockRestServiceServer` and asserts what railgate *sends*, never what gatekeeper *accepts*; `SettlementOrchestratorTest` mocks `GatekeeperClient` outright; gatekeeper's own tests of `/api/v1/verify` supply the PEM. Both suites were green and the contract between them was never exercised. The documentation did not help: `README.md`'s architecture diagram had gatekeeper "look up cert via (certSerial, issuerDn)", a step gatekeeper 1.4.0 did not have, and the "Known limitation" paragraph described the `MALFORMED_INPUT` → `SIGNATURE_INVALID` mapping as an edge case rather than as the outcome of every call.

  The fix is split across the two repositories and the request stays at four fields. gatekeeper 1.5.0 stores the issued certificate at Step 7 confirmation and resolves it from `(certSerial, issuerDn)`, answering `CERT_NOT_FOUND` when nothing matches. railgate 1.5.0 forwards both identifiers in the agreed form — `certSerial` hexadecimal, case-insensitive, optional `0x`, compared numerically; `issuerDn` an RFC 4514 string, compared by `X500Principal` equality — and checks them, together with gatekeeper's `@NotBlank` and `@Size` limits (128, 512, 256 and 4096 characters), before the call. A request that would fail those checks is answered locally with `INVALID_SIGNATURE_MATERIAL` instead of reaching the gatekeeper and coming back as a 400, which railgate would have reported as `NETWORK_ERROR`.

  `GatekeeperClientTest.requestBodyMatchesTheGatekeeperSignatureVerificationRequest` now pins the field names, the value formats and the absence of `signingCertificatePem` and `algorithm`, cross-checked by hand against gatekeeper's `SignatureVerificationRequest`; further tests pin values at and beyond each size limit. This is still a stub-transport test. It pins railgate's half of the contract as gatekeeper's model states it and would not notice a behavioural change on the gatekeeper side. An end-to-end test that runs both services does not exist yet.

- **`PaymentSignature.certSerial` was documented as a decimal serial.** Under the agreed contract it is hexadecimal. A decimal string is also valid hexadecimal and names a different certificate, so a payment-network client that follows the old javadoc produces `CERT_NOT_FOUND`, not an error. The javadoc and `README.md` now state the format; a `PaymentNetworkClient` implementation must supply the serial in hexadecimal.

### Correctness

- **Gatekeeper input errors are no longer reported as a bad signature.** `MALFORMED_INPUT` and `ALGORITHM_NOT_SUPPORTED` are added to the pass-through set. Both arrive with `signatureValid=false` and both describe a request the gatekeeper could not evaluate, not a signature that failed. With them, the pass-through set covers every non-positive reason gatekeeper's `SignatureVerificationResponse` documents. The 1.4.0 README called the remaining conflation a known limitation; it was the defect above.

- **`declaredCertSerial` was accepted and never read.** `SettlementRequest` took the serial the originating bank declares in pacs.008 `RgltryRptg`, and nothing used it. The documentation implied otherwise in three places: the field's javadoc ("May be null — railgate then queries the payment-network operator"), `SettlementDecision`, which told the bank to populate `RgltryRptg` to cure `DORA_32_AUDIT_MISSING`, and `PaymentNetworkClient`, which said the payment-network operator "cannot misreport the signature or cert serial without immediately producing detectable inconsistency". It is now used: when present, it is compared numerically with the operator's serial, and a difference — or a declared value that is not a hexadecimal serial — is denied as `DECLARED_CERT_MISMATCH` and audited, without a gatekeeper call. Absent or blank means no cross-check, and the operator's serial remains the one verified.

- **The gatekeeper reference in the audit record did not identify the gatekeeper's record of the decision.** `THREAT_MODEL.md` said the audit record "references the gatekeeper audit entry". What railgate stored was gatekeeper's `auditEntryId`, which is the approval-registry `verificationId` the verdict was read from: the same value for every settlement against a certificate, shared with the issuance's own audit entries, and `null` on `CERT_NOT_FOUND`. It survived because railgate's tests stub the gatekeeper with arbitrary identifiers (`ENTRY-X`, `AE-1`) and nothing compared them with what gatekeeper puts in the field. gatekeeper 1.5.0 now also returns `auditEntryHashHex`, the hash of the `SETTLEMENT_VERIFY` entry it wrote for the call, and railgate carries it into `SettlementDecision` and `RailgateAuditLog` next to `auditEntryId`. Against an older gatekeeper the field is absent and stays `null`. Tests: `GatekeeperClientTest.readsTheSettlementAuditEntryHashFromTheGatekeeperResponse`, `SettlementOrchestratorTest.gatekeeperSettlementAuditEntryHashIsCarriedIntoTheDecisionAndTheAuditLog`.

### Security

- **Log injection through values that were logged raw.** `THREAT_MODEL.md` stated that upstream values cannot forge lines in the operator's log. Three could: `GatekeeperClient` logged `certSerial` and the transport exception's message unmodified — and that message carries text from the failed exchange — and `RailgateAuditLog` logged and stored the gatekeeper's `auditEntryId` unmodified on every allowed settlement. All three now go through the existing CR/LF sanitiser (`RailgateAuditLog.sanitise`, now public), and the exception text is capped at 512 characters.

- **The documented TLS configuration had no effect.** `README.md` told deployers to configure the gatekeeper truststore and the mTLS client certificate with `spring.ssl.bundle.jks.*`. `GatekeeperClient` built its own `RestTemplate` on a plain `SimpleClientHttpRequestFactory` and never read a bundle, so a bundle configured as documented was ignored, and against a gatekeeper requiring mTLS every call would have failed as `NETWORK_ERROR`. Only the JVM-wide `javax.net.ssl.*` properties worked. New property `railgate.gatekeeper.ssl-bundle` names a Spring Boot SSL bundle; `GatekeeperClient` resolves it at start-up and sets its `SSLContext` on every gatekeeper connection. An unknown bundle name fails start-up, and so does a bundle that sets ciphers or enabled protocols, which `HttpURLConnection` cannot apply. `RestTemplateBuilder` was not used: in Spring Boot 4 it lives in `spring-boot-restclient`, which is not on this project's classpath. The https requirement, the timeouts and the test constructor are unchanged, and without a bundle the connection is configured exactly as in 1.4.0.

### Documentation

- **Transaction-reference reuse.** `README.md` and `PaymentNetworkClient` presented the residual left by the supplied digest as "an assumption about the payment-network operator". It is wider. railgate looks the artefacts up by transaction reference and never records a reference as consumed, so a settlement that reuses the reference of an earlier, genuinely signed payout verifies and is allowed, whoever submits it, the originating bank included. `README.md`, `PaymentNetworkClient` and `THREAT_MODEL.md` now say so. No replay store is added: to be correct it would have to survive restarts, be shared across instances and tell a replay from a legitimate resubmission after a deny, and an in-memory set does none of that.
- `CROSS_REFERENCE.md`: the rows for Art 2 §5.1 FR5, §5.3 STR3, §6.3 and §8.5 said the gatekeeper's hash chain and signed export were not implemented, while GAP item 3 of the same file said the audit log is hash-chained. The gatekeeper code has both (`AppendOnlyFileAuditLog`, `GET /v1/audit/export`); the rows now say so and keep forward security, COSE and RFC 3161 as open. The claim that the file is shipped identically across the three repositories was not true and is removed. The railgate row carries the new test counts.
- `README.md`: the gatekeeper step in the architecture diagram is marked as gatekeeper 1.5.0 or later; new wire-contract table; `DECLARED_CERT_MISMATCH`, `MALFORMED_INPUT` and `ALGORITHM_NOT_SUPPORTED` in the reason-code table; the "Known limitation" paragraph is replaced; transport section and configuration table cover `railgate.gatekeeper.ssl-bundle`; run instructions name `railgate-1.5.0.jar`.
- `CROSS_REFERENCE.md`: the gatekeeper rows on vendor support (Art 1 §4.3, Art 2 §5.2 NFR5), the Step-7 nonce and the approval-registry journal — which is persistent but not tamper-evident — are brought into line with gatekeeper 1.5.0.
- `THREAT_MODEL.md`, `PEER_REVIEW_GUIDE.md`, and the javadoc of `PaymentSignature`, `SettlementRequest`, `SettlementDecision`, `PaymentNetworkClient` and `SettlementOrchestrator` are brought into line with the above.

### API changes

- New reason code `DECLARED_CERT_MISMATCH`. `MALFORMED_INPUT` and `ALGORITHM_NOT_SUPPORTED` now reach the originating bank instead of `SIGNATURE_INVALID`.
- `INVALID_SIGNATURE_MATERIAL` is also returned for a certificate serial that is not hexadecimal or exceeds 128 characters, an issuer DN that is not an RFC 4514 name or exceeds 512 characters, and a signature over 4096 characters.
- `GatekeeperClient`: the `@Autowired` constructor additionally takes the SSL bundle name and an `ObjectProvider<SslBundles>`. The four-argument public constructor is retained and uses no bundle.
- New `PaymentSignature.MAX_CERT_SERIAL_LENGTH` and `PaymentSignature.parseCertSerial(String)`. `RailgateAuditLog.sanitise(String, int)` is public.
- `VerificationResult.auditEntryHashHex` and `SettlementDecision.auditEntryHashHex` added; `RailgateAuditLog.AuditEntry` gains a trailing `gatekeeperAuditEntryHashHex` component, so code constructing the record directly must pass it. The `Settlement ALLOWED` log line adds `gatekeeperEntryHash=`.

### Configuration

- New key `railgate.gatekeeper.ssl-bundle` (default empty).

### Tests

`mvn -B test` runs 62 tests, up from 39: including 2 from the documentation-versus-code review (the `auditEntryHashHex` entry under Correctness) and 4 in `FilePaymentNetworkClientTest` (Local end-to-end support). New: `RailgateAuditLogTest` (1); five cases in `SettlementOrchestratorTest` (gatekeeper `MALFORMED_INPUT` and `ALGORITHM_NOT_SUPPORTED`, declared-serial mismatch, non-hexadecimal declared serial, numerically equal declared serial); eleven in `GatekeeperClientTest` (the contract test, size limits at and beyond the boundary, non-hexadecimal serial, non-RFC 4514 issuer DN, log injection through a transport error, five for the SSL bundle). `forwardsExactlyTheFourDataMinimisedFields` is unchanged.

### Dependencies

- `tomcat.version` 11.0.25 → 11.0.26, which fixes CVE-2026-73581, -75973, -76183, -77756, -77762, -77791, -78383, -78437, -79677, -86248, -86350 and -87022. Boot 4.1.1 still manages 11.0.24.
- `springdoc-openapi-starter-webmvc-ui` 3.1.0 → 3.1.1. springdoc 3.1.1 ships swagger-ui 5.32.14; `org.webjars:swagger-ui` stays pinned, now at 5.32.15.
- `dependency-check-maven` stays at 12.2.2. 13.0.0 is the latest release, but it cannot update its NVD data without an API key (dependency-check/DependencyCheck#8715); the fix is merged for 13.0.1, which has not been released. gatekeeper and hsm stay on 12.2.2 for the same reason, so all three repositories build with `mvn verify` without a key.
- Unchanged: Spring Boot parent 4.1.1, Lombok 1.18.48, `maven-enforcer-plugin` 3.6.3. `maven-compiler-plugin` is not pinned in this POM and stays at the version the parent manages.

### Local end-to-end support

- **`railgate.payment-network.mode=file`.** `InMemoryPaymentNetworkClient` can only be filled from Java code, so a railgate started from its jar answered every regulated settlement with `DORA_32_AUDIT_MISSING` and never called gatekeeper; the settlement leg could not be exercised across real processes. `FilePaymentNetworkClient` reads signature artefacts from a tab-separated file named by `railgate.payment-network.file` (reference, certificate serial, issuer DN, digest, signature), re-read on every lookup. A missing file or malformed line yields no artefacts, so the orchestrator still denies. Not for production. Tests: `FilePaymentNetworkClientTest` (4). Used by the local end-to-end harness in the gatekeeper repository (`gatekeeper/e2e`).

## 1.4.0

Every item below is a defect that was present in 1.3.0. Where a defect had a reason for surviving review, that reason is stated rather than left out.

### Start-up blocker

- **1.3.0 could not start.** `GatekeeperClient` was given a package-private `GatekeeperClient(RestTemplate)` constructor as a test seam, alongside the public `@Value` constructor. Neither carried `@Autowired` and the class has no no-arg constructor, so Spring had two candidates and no way to choose: context refresh failed and the service did not boot.

  The seam and the defect arrived in the same commit. 1.3.0's headline fix was the connect and read timeout on the outbound gatekeeper call — an unresponsive gatekeeper had been blocking the calling thread instead of producing a deny — and `GatekeeperClientTest` was written at the same time to cover it. Adding the seam is what made the constructor ambiguous. **The timeout fix has therefore never executed in a deployed instance.** It was correct, it was tested, and it was unreachable, because the bean it lives on could not be created.

  Nothing caught this, because no test in the repository loaded the Spring context. `SettlementOrchestratorTest` constructs its collaborators with `new` and injects the detector's configuration by reflection; `GatekeeperClientTest` uses the seam and sets the base URL with `ReflectionTestUtils`. Neither reads `application.yml` and neither builds the bean graph, so a green suite said nothing about whether the application starts. `@Autowired` is now on the public constructor, the seam is retained, and `ApplicationContextLoadsTest` boots the real context from the real configuration so that this class of failure surfaces in CI rather than on a host.

### Security

- **A settlement with no party-type classification was passed through with `allow=true`.** `debtorIsOrganization` and `creditorIsPrivatePerson` were `boolean` primitives. A JSON payload that omitted them deserialised to `false, false`, which `RegulatedPaymentDetector` read as a private-to-private transfer — the one shape railgate does not verify. The minimal payload `{"transactionReference": "..."}` therefore produced `NOT_REGULATED`, `allow=true`, without any call to the gatekeeper. Both fields are now `Boolean` with `@NotNull`, so an omission fails validation; a request that reaches the detector without them is treated as regulated; and `SettlementOrchestrator` requires the classification to be present before it will take the pass-through path at all, so the invariant does not depend on the detector alone. `localInstrumentCode` is bounded at `@Size(max = 35)`, the ISO 20022 `Max35Text` length.

- **Local-instrument-code matching was exact and case-sensitive.** `"swish"` and `" SWISH"` did not match the configured `SWISH`. Matching is now case-insensitive and trimmed on both sides.

- **The documented claim that structural derivation "cannot be circumvented by the originating bank" was not true of the code,** and is corrected in `README.md`, `PEER_REVIEW_GUIDE.md`, `CROSS_REFERENCE.md` and the class javadoc. Both party-type flags are metadata: the settlement system derives them from `Dbtr/Id/OrgId` and `Cdtr/Id/PrvtId` and hands them to railgate in `SettlementRequest`. railgate does not receive the pacs.008, does not parse it, and cannot recompute the derivation. What is now true, and is what the documents say, is that the structural path is harder to suppress than the instrument code and that a missing classification is treated as regulated.

- **The gatekeeper base URL must be `https://`.** The default was `http://localhost:8080` and nothing checked the scheme, so a deployment that left the default in place sent the digest, signature and certificate identifiers in clear text and accepted the verdict back the same way. New key `railgate.gatekeeper.allow-insecure-http` (default `false`); a non-`https` URL without it is an `IllegalStateException` at start-up, and with it a WARN at every start-up. The default is now `https://localhost:8443`.

- **`THREAT_MODEL.md` claimed a protection the code does not implement.** It stated that "the gatekeeper's signed response is what the orchestrator allows on" and that "a fraudulent unsigned response cannot mimic it". `POST /api/v1/verify` returns plain JSON; `GatekeeperClient` deserialises `signatureValid` and `compliant` and verifies no signature over them. The gatekeeper signs its receipts, and the settlement-time verdict is not one of them. The Spoofing, Tampering, Denial-of-service and Elevation-of-privilege sections now describe what the code does — including that there is no role model at the railgate side, no certificate pinning and no rate limiting — and the unsigned verdict is written up as a residual with what closing it would require.

- **Cryptographic material is checked before it is forwarded.** `digestHex` must be exactly 128 hexadecimal characters, `signatureBase64` must decode with `Base64.getDecoder()`, and `certSerial` and `issuerDn` must be non-blank. Otherwise the gatekeeper is not called and the result is `signatureValid=false, compliant=false, reason=INVALID_SIGNATURE_MATERIAL`. Malformed artefacts from the payment-network operator previously consumed a supervisory call and came back as `SIGNATURE_INVALID`, which is an accusation against the originating bank for a defect that is not theirs.

- **An unhandled exception no longer produces an HTTP 500 with a body that is not a `SettlementDecision`.** New `SettlementExceptionHandler` (`@RestControllerAdvice`, scoped to `SettlementController`) returns 403 with `allow=false, reasonCode=INTERNAL_ERROR` for anything unhandled and 400 with `allow=false, reasonCode=INVALID_REQUEST` for a validation failure. Neither response carries the exception message, class name or field-level validation detail; the operator's log gets the stack trace. Both outcomes are written to the audit log, because a denied settlement that left no record is indistinguishable afterwards from one that was never submitted.

- **`/api/v1/**` has a security configuration.** `spring-boot-starter-security` was on the classpath with no `SecurityFilterChain` bean, so Boot's default applied to a stateless machine-to-machine JSON API: session-based, CSRF-protected, form login. New `SecurityConfig` gives `/api/v1/**` a stateless, CSRF-exempt, authenticated chain and reproduces the Boot default for everything else. The authentication mechanism is the deployer's choice — HTTP Basic ships, mTLS with `.x509(...)` is what a central-bank deployment should use — and `README.md` documents how to wire it. railgate has no role model: every authenticated caller of `/api/v1/**` can both submit prechecks and read the audit trail. `THREAT_MODEL.md` previously claimed a `SETTLEMENT_RAIL` role at the railgate side that the reference configuration never contained; `SETTLEMENT_RAIL` exists at the gatekeeper.

- **Log injection via `transactionReference` and `message`.** Both come from upstream and both are written to a line-oriented log, so an embedded CR or LF let the writer forge additional log lines in the supervisory record. They are flattened to spaces before the entry is stored or logged, and `message` is capped at 512 characters.

### Correctness

- **`CERT_NOT_FOUND` is reported as `CERT_NOT_FOUND`.** `reasonCodeFor` derived the code from `signatureValid` and `compliant`, testing only for `NETWORK_ERROR` before that. A gatekeeper answer of `CERT_NOT_FOUND` — the certificate matches no audit entry, i.e. issuance was circumvented, which is the case the whole triad exists to detect — arrived at the originating bank as `SIGNATURE_INVALID`. The gatekeeper's `reason` is now read first and passed through when it is one of `CERT_NOT_FOUND`, `CERT_NON_COMPLIANT`, `SIGNATURE_INVALID`, `NETWORK_ERROR` or railgate's own `INVALID_SIGNATURE_MATERIAL`; anything else falls back to the boolean derivation.

  `INVALID_SIGNATURE_MATERIAL` is in that set although it is not a gatekeeper value: it is produced by `GatekeeperClient` before any call, and mapping it to `SIGNATURE_INVALID` would reintroduce exactly the conflation the 1.3.0 `NETWORK_ERROR` fix removed.

- **The unreachable `VERIFICATION_FAILED` branch is removed.** `reasonCodeFor` is called only when `!isAllowed()`, so either the signature did not verify or it did and the certificate was not compliant. There is no third case and the branch could not be reached. `VERIFICATION_FAILED` no longer appears in `README.md`'s reason-code table either.

### Observability

- **Audit-log eviction is counted and reported.** The 10 000-entry ring buffer introduced in 1.3.0 discarded its oldest records silently, so a gap in the supervisory record was invisible from the snapshot. Discards are counted, a WARN is emitted once per thousand, and `GET /api/v1/audit/health` returns `{entryCount, maxEntries, evictedCount}`.

### Configuration

- **OpenAPI document and Swagger UI are off unless the `dev` profile is active.** `springdoc.api-docs.enabled` and `springdoc.swagger-ui.enabled` are `false` in every shipped configuration file; the new `application-dev.yml` turns them on for local use. Neither endpoint has a run-time function in this service, and swagger-ui is a third-party JavaScript application whose vulnerabilities (see Dependencies) would otherwise be part of the deployed surface.

- New key `railgate.gatekeeper.allow-insecure-http` (default `false`), set in `application.yml`.
- `railgate.gatekeeper.base-url` default changed from `http://localhost:8080` to `https://localhost:8443`.
- `railgate.gatekeeper.connect-timeout` and `railgate.gatekeeper.read-timeout` existed in 1.3.0 but were undocumented; both are now in the configuration tables in `README.md` and `PEER_REVIEW_GUIDE.md`.

### API changes

- `SettlementRequest.debtorIsOrganization` and `creditorIsPrivatePerson` change from `boolean` to `Boolean` and become `@NotNull`. The JSON property names are unchanged, but a payload that omitted them and previously succeeded now receives 400. Callers must supply both.
- `SettlementRequest.localInstrumentCode` gains `@Size(max = 35)`.
- `GatekeeperClient`'s public constructor takes the base URL and the insecure-HTTP flag in addition to the two timeouts. The base URL moved from an injected field to a constructor argument because the scheme check has to run at start-up rather than on the first settlement.
- New reason codes `INVALID_SIGNATURE_MATERIAL`, `INVALID_REQUEST`, `INTERNAL_ERROR`. `VERIFICATION_FAILED` removed.
- New endpoint `GET /api/v1/audit/health`.
- New `RailgateAuditLog.AuditLogHealth` record, `RailgateAuditLog.health()` and `RailgateAuditLog.getEvictedCount()`.

### Tests

`mvn -B test` runs 39 tests, up from 11. New: `ApplicationContextLoadsTest` (2), `OpenApiExposureDefaultProfileTest` (2), `OpenApiExposureDevProfileTest` (2), `SettlementRequestValidationTest` (4), `SettlementExceptionHandlerTest` (4), seven cases added to `SettlementOrchestratorTest` and seven to `GatekeeperClientTest`. `GatekeeperClientTest.forwardsExactlyTheFourDataMinimisedFields` now uses a 128-character digest, since a short one is rejected before the call.

### Dependencies

- Spring Boot parent 4.1.1 (Spring Framework 7, Spring Security 7), Lombok 1.18.48, springdoc-openapi 3.1.0.
- `org.webjars:swagger-ui` is pinned to 5.32.14. springdoc 3.1.0 ships 5.32.11, which bundles DOMPurify 3.4.12 (CVE-2026-75838). The earlier suppression for DOMPurify 3.3.2 (CVE-2026-41238/41239/41240) no longer matches anything and has been removed from `.owasp-suppressions.xml`; the file is now empty.
- `tomcat.version` is overridden to 11.0.25. Boot 4.1.1 manages 11.0.24, for which OWASP Dependency-Check reports eleven CVEs (CVE-2026-65182, -65183, -65637, -65905, -65927, -66299, -66422, -68525, -68569, -68763, -73180); all are listed as fixed in Tomcat 11.0.25 (2026-08-18). The override is to be removed once the parent manages 11.0.25 or later.
- `dependency-check-maven` stays at 12.2.2. 13.0.0 rejects an absent NVD API key as an invalid key of length 0 (jeremylong/DependencyCheck#8715), and this project is scanned without a key. The `<nvdApiKey>` configuration has been removed for the same reason.

### Documentation

- `README.md`: the architecture diagram's verification step was written in Node.js (`createVerify('sha512WithRSAEncryption')`) for a Java implementation that calls `Signature.getInstance("SHA512withRSA")`. The data-minimisation section listed four fields as everything railgate handles, omitting the debtor and creditor BICs and the two party-type flags that `SettlementRequest` also carries; the section now separates what railgate receives from what it forwards to the supervisor, which is the boundary the claim is actually about. The reason-code table is replaced with the complete reachable set and its HTTP statuses, new sections cover transport and authentication, the configuration table carries the timeouts and the new flag, and the run instructions name `railgate-1.4.0.jar`.
- `PEER_REVIEW_GUIDE.md`: expected test count, the seven-field `SettlementRequest` (documented as four), the extension-point list, the configuration knobs, the reason-code enumeration and the corrected non-circumventability claim.
- `CROSS_REFERENCE.md`: the two `[RG]` rows — corrected non-circumventability claim, updated test counts, and the unsigned gatekeeper verdict noted where the quadruple-triangulation claim is made.
- `THREAT_MODEL.md`: see under Security above.
