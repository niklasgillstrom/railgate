# Peer-review guide — railgate

This document is written for a peer reviewer of Article 1 (Gillström, in preparation; target venue: *Capital Markets Law Journal*) and Article 2 (Gillström, in preparation; target venue: *Computer Law & Security Review*) who wants to reproduce the central settlement-layer-enforcement claims those articles make. The companion repos `hsm/` and `gatekeeper/` complete the **triadic system** (since v1.2.0) described in Article 1 §4.3 and §6.2 and in Article 2 §6.1 and §9.3 (section numbers of the manuscripts revised on 2026-10-30):

- **hsm** carries the verifier core (financial-entity side).
- **gatekeeper** is the NCA-operated supervisory API; from v1.1.0 also exposes the settlement-time signature verification endpoint that railgate consumes.
- **railgate** (this repo) is the central-bank settlement-rail enforcement layer that calls gatekeeper's verification endpoint at settlement time (RIX-INST in Sweden; generalisable to TIPS, FedNow, FPS, NPP).

The three components together operationalise the data-minimised quadruple-triangulation model over four data sources — Getswish AB's allocation register, the gatekeeper audit log, the RIX-INST settlement log and the recipient-side transaction registration — of which the code produces the gatekeeper audit log; the other three, the RIX-INST settlement log included, are external (railgate's own decision log is not that log). Only digest, signature, and certificate identifiers traverse the supervisor boundary — no transaction payload content is exposed at any layer.

---

## Version 1.8.0 — what changed and what to verify

The corrections that followed a review of the 1.7.0 code on 2026-11-09 (`CHANGELOG.md`). The tests named are the ones that fail on the 1.7.0 behaviour.

- **No server session, for any request.** One stateless filter chain for every path: `SecurityConfigStatelessTest`, `ApplicationContextLoadsTest.theSecurityFilterChainIsBuilt`.
- **The time a client allows for an answer bounds the whole answer, and the answer has a size limit.** Both outbound clients use the JDK's `HttpClient` (`OutboundHttp`): `GatekeeperClientTest.anAnswerThatArrivesAByteAtATimeEndsInADenyWhenTheReadTimeoutIsUp`, `headersThatArriveAByteAtATimeEndInADenyAsWell`, `aGatekeeperThatAcceptsAndNeverAnswersEndsInADeny`, `anAnswerLargerThanTheLimitIsADenyAndOneWithinItIsRead`, `aTimeoutThatIsNotPositiveIsRefusedAtStartUp`; `HttpPaymentNetworkClientConnectionTest.anAnswerThatArrivesAByteAtATimeIsUnavailableWhenTheReadTimeoutIsUp` and `aBodyOfExactlyTheLimitIsReadAndOneByteMoreIsRefused`; `OutboundHttpTest` (8).
- **Only a 2xx answer from the gatekeeper is a verdict.** `GatekeeperClientTest.anAllowingBodyUnderAnyStatusOtherThan2xxIsADeny`.
- **A record whose sync failed is taken back.** `ReplayGuardDurabilityTest.aRecordWhoseSyncFailedIsCutOffAgainAndIsNotSettledAfterARestart`, `theFirstRecordOfANewJournalIsCutOffTheSameWay`, `whenTheRecordCannotBeCutOffEitherTheErrorSaysWhereToCutTheFile` (the sync failure is that of a channel that fails on request).
- **An exception cannot write a line of its own in the operator's log, and a denial names its settlement.** `SettlementExceptionHandlerTest.anExceptionMessageCannotStartALineInTheLog`, `aValidationFailureIsRecordedWithTheReferenceTheRequestStated`, `aFailedEvaluationIsA403DenyRecordedWithItsReference`.
- **A caller that does not accept JSON is answered 406 before anything is evaluated or recorded.** `SettlementControllerTest.aCallerThatDoesNotAcceptJsonIsAnswered406BeforeTheSettlementIsEvaluated`, `readingTheAuditTrailWithoutAcceptingJsonIsA406ThatRecordsNothing`.
- **`.` and `..` are not requested from the operator.** `HttpPaymentNetworkClientConnectionTest.aReferenceThatIsADotSegmentIsNotRequested`.
- **The swagger-ui package is not served.** `OpenApiExposureDefaultProfileTest.theSwaggerUiPackageIsNotServedAsAWebJarEither`; in `dev` the UI loads, `OpenApiExposureDevProfileTest.swaggerUiIsServed`.

Reviewers should start with `mvn -B test` (270 tests in 1.8.0, all passing). The dependency versions are those of 1.7.0; PIT's results are in the paragraph on mutation testing under "Build and test".

## Version 1.7.0 — what changed and what to verify

- **Signed gatekeeper verdict.** railgate verifies gatekeeper 1.7.0's signature over `sv1` before acting on a verdict, under the certificates in `railgate.gatekeeper.trusted-keys`, over the request it sent, and within `railgate.gatekeeper.verdict-max-skew`; required by default. Verify with `VerdictCanonicalizerTest.goldenExampleSharedWithTheGatekeeper` (the same golden string as gatekeeper's `SettlementVerdictCanonicalizerGoldenTest`), `GatekeeperClientSignedVerdictTest` (a verdict signed for another request is rejected even without echo fields; an untrusted key claiming the trusted fingerprint is rejected; a stale but badly signed verdict is reported as invalid, not stale) and `TrustedCertificatesTest` (the key fingerprint is the SHA-256 of the SubjectPublicKeyInfo, as on gatekeeper's `/v1/gatekeeper/keys`).
- **Payment-network operator interface** (`api/payment-network-operator.openapi.yaml`) and its client (`railgate.payment-network.mode=http`): answers signed over `op1` by a pinned operator key. `HttpPaymentNetworkClientTest` runs against a reference operator, including mTLS, and `theSpecificationDescribesThePathTheClientCalls` parses the YAML and checks the path, the allow-list and the `op1` hash. No operator offers the interface; nothing was tested against Getswish AB.
- **Replay protection** (`ReplayGuard`): each transaction reference and operator payout instruction id is allowed at most once. `ReplayGuardTest.ofManyConcurrentAttemptsOnOneReferenceExactlyOneCommits`, `SettlementOrchestratorHardeningTest.ofManyUnsynchronisedEvaluationsOfOneReferenceAtMostOneIsAllowed`, `SettlementPipelineIntegrationTest.aSignedPayoutIsAllowedOnceAndItsReplaysAreRefusedAcrossARestart`.
- **Lifecycle denials** of gatekeeper 1.7.0 (`CERT_SUPERSEDED`, `CERT_REVOKED`, `CERT_DECOMMISSIONED`) are passed through.

Reviewers should start with `mvn -B test` (206 tests in 1.7.0). Those results were obtained with the 1.7.0 dependency versions (2026-10-31); PIT kills every one of the 497 mutants of the 1.7.0 code.

---

## What this repo is / isn't

**Is:**

- A **reference implementation** of settlement-rail enforcement as described in Article 1 §4.3 and §6.2 and in Article 2 §6.1 and §9.3. Railgate sits at the central-bank settlement rail and performs deterministic cryptographic signature verification at settlement time, blocking any settlement that cannot be matched to a compliant gatekeeper audit entry.
- A **demonstration** of the data-minimisation contract: the supervisor never sees transaction payload content, only the SHA-512 digest, the signature, and the certificate identifiers. SHA-512 collision resistance binds the signature to the payload the digest was taken over — not, by itself, to the pacs.008 message being settled; see the note on the residual binding assumption in `README.md`.
- A **default-deny enforcement** prototype with structured reason codes returned to the originating bank. The complete set is `ALLOWED`, `NOT_REGULATED`, `DORA_32_AUDIT_MISSING`, `OPERATOR_SIGNATURE_INVALID`, `REFERENCE_ALREADY_SETTLED`, `DECLARED_CERT_MISMATCH`, `CERT_NOT_FOUND`, `SIGNATURE_INVALID`, `CERT_NON_COMPLIANT`, `CERT_EXPIRED`, `CERT_SUPERSEDED`, `CERT_REVOKED`, `CERT_DECOMMISSIONED`, `MALFORMED_INPUT`, `ALGORITHM_NOT_SUPPORTED`, `NETWORK_ERROR`, `VERDICT_SIGNATURE_INVALID`, `VERDICT_STALE`, `INVALID_SIGNATURE_MATERIAL`, `INVALID_REQUEST`, `INTERNAL_ERROR`; `README.md` tabulates each with its HTTP status. No other value is reachable.

**Isn't:**

- A production-ready integration with Sveriges Riksbank's RIX-INST or any other central-bank settlement system. Production deployment requires a payment-network operator that offers the artefact interface railgate's `http` mode calls (specified in `api/payment-network-operator.openapi.yaml` since 1.7.0; no operator offers it today), configuring the gatekeeper URL and its verdict-signing certificate for the supervisor's instance, and integrating with the central bank's pacs.008 processing pipeline. Only the client side of the first is part of this repo.
- An ISO 20022 parser. The `SettlementRequest` model abstracts the fields railgate needs (`transactionReference`, `localInstrumentCode`, debtor/creditor identification flags, BICs); a production deployment would receive the full pacs.008 message and parse the relevant fields. The abstraction here keeps the reference focused on the verification orchestration logic.

---

## Version 1.4.0 — what changed and what to verify

1.3.0 did not start. `GatekeeperClient` was given a package-private test-seam constructor alongside its `@Value` constructor and neither carried `@Autowired`, so Spring had two candidates, no no-arg fallback, and context refresh failed. Nothing caught it, because no test in the repository loaded the Spring context: every test constructed its collaborators directly or used the seam. The timeout fix that 1.3.0 was released for therefore never ran outside a unit test. `ApplicationContextLoadsTest` now boots the real context from the real `application.yml`.

Beyond that:

- **Missing party-type classification is no longer a pass-through.** `debtorIsOrganization` and `creditorIsPrivatePerson` were primitives, so an omitted field deserialised to `false` — read as private-to-private, the one shape railgate passes through with `allow=true`. They are `Boolean` with `@NotNull`; a missing flag is a 400, and a request that reaches the detector without one is treated as regulated.
- **The claim that structural derivation "cannot be circumvented by the originating bank" was wrong** and has been corrected here, in `README.md` and in `CROSS_REFERENCE.md`. The flags are metadata from the settlement system; railgate does not parse the pacs.008 and cannot recompute them.
- **The gatekeeper base URL must be `https://`,** enforced at start-up. railgate does not verify a signature over the gatekeeper's verdict, so the transport is the whole of the integrity guarantee — `THREAT_MODEL.md` now says so instead of claiming a signed response the code never checks. *(Superseded in 1.7.0: the verdict is signed by gatekeeper 1.7.0 and verified by railgate.)*
- **Exceptions produce a deny,** not an HTTP 500 with a non-`SettlementDecision` body. `SettlementExceptionHandler` returns 403 / `INTERNAL_ERROR` for anything unhandled and 400 / `INVALID_REQUEST` for a validation failure, carries no exception detail, and audits both.
- **`CERT_NOT_FOUND` reaches the bank as `CERT_NOT_FOUND`.** The orchestrator reads the gatekeeper's `reason` before deriving a code from the two booleans, which previously collapsed the circumvented-issuance case into `SIGNATURE_INVALID`. The unreachable `VERIFICATION_FAILED` branch is gone.
- **`/api/v1/**` has a security configuration.** There was no `SecurityFilterChain` bean, so Boot's session-and-CSRF default applied to a stateless machine API.
- **Audit-log eviction is visible.** Discards are counted, reported at `GET /api/v1/audit/health` and warned about once per thousand; `transactionReference` and `message` are stripped of CR/LF and the message is capped at 512 characters.

Reviewers should start with `mvn -B test` (39 tests).

---

## Version 1.3.0 — what changed and what to verify

A systematic check of the triad against its own documentation found places where a described protection was not implemented in the code. In summary:

- `GatekeeperClient` had no connect or read timeout, so an unresponsive gatekeeper blocked the calling thread instead of producing a deny. Timeouts are now configurable and bounded by default.
- A gatekeeper outage was reported to the originating bank as `SIGNATURE_INVALID`, because the `NETWORK_ERROR` branch was unreachable. Infrastructure failure and cryptographic failure are no longer conflated.
- The audit log copied its entire backing array on every settlement decision; it is now a bounded ring buffer.
- `GatekeeperClient` had no tests at all, which is where every fail-open risk in this repository lives. `GatekeeperClientTest` now drives the real client against a stubbed transport.
- The claim that SHA-512 collision resistance binds the signature to the settled transaction has been corrected throughout: it binds the signature to the payload the digest was taken over. See `README.md` for the residual assumption and what would close it.

Reviewers should start with `mvn -B test` (11 tests).

---

## Version 1.2.0 — what changed and what to verify

Reviewers approaching v1.2.0 should focus on the following:

1. **Settlement-time orchestration** (`SettlementOrchestrator`) — verify the flow: regulated-payment detection → payment-network signature retrieval → gatekeeper verification → allow/default-deny.
2. **Regulated-payment detection** (`RegulatedPaymentDetector`) — both paths must work: explicit `LclInstrm/Cd` matching (e.g. "SWISH"), and structural derivation (`OrgId(debtor)` + `PrvtId(creditor)` = organisation-to-private = Swish utbetalning). *Corrected in 1.4.0:* the claim that the structural path "cannot be circumvented by the originating bank" does not describe the code. Both flags are metadata handed to railgate by the settlement system, and railgate cannot recompute them from the pacs.008 it does not receive. What the code does provide is that a missing classification is treated as regulated and that an omitted flag fails validation.
3. **Data-minimisation contract** — the JSON wire format for `SettlementRequest`, `PaymentSignature`, and the gatekeeper-bound `SignatureVerificationRequest` must contain only digest, signature, and certificate identifiers. There must be no payload field. `GatekeeperClientTest.forwardsExactlyTheFourDataMinimisedFields` asserts this against the real outbound request body, including a field count so that a fifth field cannot be added without the test failing.
4. **Default-deny logic** — the orchestrator returns `allow = false` whenever (a) the payment-network operator has no record of the transaction, (b) the gatekeeper rejects the signature, (c) the gatekeeper marks the certificate non-compliant, or (d) the gatekeeper is unreachable. Paths (a)-(c) are covered by `SettlementOrchestratorTest`; path (d) is covered by `GatekeeperClientTest`, which drives the real client against a stubbed transport (server error, empty body, unparseable body, foreign JSON) and asserts a deny in every case. Note that a gatekeeper outage is reported as `NETWORK_ERROR`, not `SIGNATURE_INVALID` — the two must not be conflated, since the latter is an accusation against the originating bank.

---

## Requirements

- **Java 21 or later**: the build targets Java 21 (`java.version` in `pom.xml`), on the Spring Boot 4.1.2 parent (4.1.1 until 1.6.0).
- **Maven 3.8.1** or later (enforced by `maven-enforcer-plugin`)
- Access to a running gatekeeper instance for end-to-end testing (defaults to `https://localhost:8443`, and a non-`https` URL is refused at start-up unless `railgate.gatekeeper.allow-insecure-http=true`). No live gatekeeper is required for `mvn -B test`: the orchestrator tests mock `GatekeeperClient`, the client tests drive the real client against `MockRestServiceServer`, `ApplicationContextLoadsTest` constructs the client without calling it, and since 1.7.0 the operator and pipeline tests start a reference operator and a reference gatekeeper (`com.sun.net.httpserver`) on loopback.

---

## Build and test

```bash
mvn -B clean verify
```

Expected output:

```
[INFO] Tests run: 270, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

The 270 tests (206 in 1.7.0, 93 in 1.6.0) are distributed as follows.

`SettlementOrchestratorTest` (26):

1. `allowsSettlementWhenSignatureVerifiesAndCertCompliant` — happy path; gatekeeper returns `signatureValid=true, compliant=true`.
2. `deniesWhenSignatureMissingFromPaymentNetwork` — payment-network operator has no record → `DORA_32_AUDIT_MISSING`.
3. `deniesWhenSignatureInvalid` — gatekeeper returns `signatureValid=false` → `SIGNATURE_INVALID`.
4. `deniesWhenCertNonCompliant` — gatekeeper returns `compliant=false` → `CERT_NON_COMPLIANT`.
5. `identifiesSwishUtbetalningByStructuralDerivation` — `OrgId` + `PrvtId` flags trigger regulated-payment detection without explicit `LclInstrm` code.
6. `passesThroughNonRegulatedSettlements` — non-regulated settlements are not subject to railgate enforcement (returns `allow=true, NOT_REGULATED`).
7. `missingPartyTypeFlagsAreTreatedAsRegulated` — neither flag supplied → regulated, then `DORA_32_AUDIT_MISSING`. This is the case that used to pass through with `allow=true`.
8. `oneMissingPartyTypeFlagIsAlsoTreatedAsRegulated` — half a classification is not a classification.
9. `instrumentCodeMatchingIsCaseInsensitiveAndTrimmed` — `"  swish "` is `SWISH`.
10. `certNotFoundIsReportedAsCertNotFound` — the circumvented-issuance case is no longer reported as a bad signature.
11. `gatekeeperOutageIsReportedAsNetworkErrorThroughTheOrchestrator` — regression test for the 1.3.0 fix, at the layer that decides the code the bank receives.
12. `malformedSignatureMaterialIsNotReportedAsSignatureInvalid` — `INVALID_SIGNATURE_MATERIAL` passes through.
13. `unknownGatekeeperReasonFallsBackToTheBooleanDerivation` — an unrecognised reason does not become the reason code.
14. `malformedInputFromGatekeeperIsNotReportedAsSignatureInvalid` — gatekeeper's `MALFORMED_INPUT` passes through.
15. `algorithmNotSupportedFromGatekeeperIsNotReportedAsSignatureInvalid` — gatekeeper's `ALGORITHM_NOT_SUPPORTED` passes through.
16. `declaredCertSerialThatDiffersFromTheOperatorSerialIsDeniedAndAudited` — `DECLARED_CERT_MISMATCH`, no gatekeeper call, one audit entry.
17. `declaredCertSerialThatIsNotHexadecimalIsDenied` — an unparseable declared serial is a mismatch.
18. `declaredCertSerialNumericallyEqualToTheOperatorSerialIsNotAMismatch` — `" 0X0012345 "` equals `12345`; settlement proceeds.
19. `gatekeeperSettlementAuditEntryHashIsCarriedIntoTheDecisionAndTheAuditLog` — the gatekeeper's `auditEntryHashHex` reaches the decision and `RailgateAuditLog` on an allow and on a `CERT_NOT_FOUND` deny, where the registry `auditEntryId` is `null`.
20. `anExpiredCertificateIsReportedAsCertExpired` — gatekeeper's `CERT_EXPIRED` (signature valid, certificate outside its validity period) passes through.
21. `aSettlementWithoutInstrumentCodeThatIsNotOrganisationToPrivatePassesThrough` — no instrument code and a classification other than organisation-to-private → `NOT_REGULATED`.
22. `aDenialWithoutAReasonIsReportedAsSignatureInvalidWithTheDefaultMessage` — a gatekeeper deny without a reason becomes `SIGNATURE_INVALID` with the fixed message.
23. `anOperatorSerialThatIsNotHexadecimalIsLeftToTheMaterialCheck` — an unparseable operator serial is not a `DECLARED_CERT_MISMATCH`; the gatekeeper client's material check answers.
24. `aBlankInstrumentCodeIsNotARegulatedCode` — `"   "` does not match a configured code.
25. `theDetectorTreatsAnAbsentRequestAsRegulated` — `RegulatedPaymentDetector.isRegulated(null)` is true.
26. `aCertificateMovedOnByAKeyLifecycleEventIsReportedWithTheGatekeepersReason` *(1.7.0)* — gatekeeper's `CERT_SUPERSEDED`, `CERT_REVOKED` and `CERT_DECOMMISSIONED` pass through.

`GatekeeperClientTest` (49): the five transport tests from 1.3.0 (data-minimisation contract, server error, empty body, unparseable body, foreign JSON), three start-up tests for the `https://` requirement and its override, and four for the cryptographic-material checks (short digest, non-hex digest, non-base64 signature, blank certificate serial or issuer DN) — each asserting that no call to the gatekeeper is made. Added in 1.5.0: the contract test against gatekeeper's `SignatureVerificationRequest` (`requestBodyMatchesTheGatekeeperSignatureVerificationRequest`), values at and beyond the gatekeeper's `@Size` limits, a non-hexadecimal certificate serial, an issuer DN that is not an RFC 4514 name, a transport error whose message carries CR/LF, and five tests for the SSL bundle (none configured, blank name, bundle applied to the connection, unknown bundle, bundle with cipher or protocol options). Added after the 1.5.0 review: `readsTheSettlementAuditEntryHashFromTheGatekeeperResponse`, the gatekeeper's `auditEntryHashHex` deserialised next to `auditEntryId`. Added in 1.6.0: the configured connect and read timeouts bound the gatekeeper connection, and each malformed artefact is logged by the field it concerns and never with its value. Added in 1.8.0: an allowing body under any status other than 2xx is a deny (eleven statuses, the 3xx ones among them) and under 2xx it is read (three), and the refused status is logged without the body; a timeout that is null, zero or negative, and a bundle name without a registry, stop start-up; the connection is HTTP/1.1 and follows no redirect; a body arriving a byte at a time, headers arriving a byte at a time and a gatekeeper that accepts and never answers each end in a `NETWORK_ERROR` deny when the read timeout is up (against a local server that keeps sending); an answer of 65 536 bytes is read and one byte more is a deny; and the bounded response is the gatekeeper's in every other respect.

`FilePaymentNetworkClientTest` (4): artefacts are found by transaction reference, entries written after start-up are visible, unknown references and malformed lines yield nothing, and file mode without a file is refused at start-up.

`RailgateAuditLogTest` (5): a gatekeeper audit-entry identifier carrying CR/LF is flattened before it is stored or logged; fields from the gatekeeper are bounded and carry no control characters; the sanitiser keeps ordinary text and honours the limit; the log keeps the newest 10 000 entries, counts the discarded ones and warns once per thousand; an allow is logged at INFO and a denial at WARN.

`SettlementControllerTest` (8): an allow is answered 200 and a denial 403 with the orchestrator's decision as body; the audit endpoints return the log and its health. Added in 1.8.0: a failed evaluation is rethrown with the transaction reference and answered, over HTTP, with a deny that names it; a caller that does not accept JSON is answered 406 before the settlement is evaluated, and one that reads the audit trail that way 406 with nothing recorded; a caller that accepts JSON or anything is answered with the decision.

`RequestSizeLimitFilterTest` (6): a declared length above the cap is a 413 with the JSON error body before the body is read; a length at the cap and an empty body pass unwrapped; an undeclared length is counted while read; the counting stream forwards `available`, `isFinished`, `isReady`, `setReadListener` and `close` to the stream it wraps; a non-positive cap is refused.

`ListenerTlsGuardTest` (6) and `ListenerTlsStartUpTest` (2): railgate does not start without TLS key material (switched-off SSL, missing material and a blank bundle included) unless the development override is set; with a certificate the listener speaks TLS, requires Basic authentication under `/api/v1` and outside it, and answers an oversized authenticated request with 413.

`SettlementRequestValidationTest` (6): a payload carrying only `transactionReference` is rejected on both party-type flags; a fully classified request validates; a blank reference and an over-35-character instrument code are rejected; the transaction reference is bounded at 36 characters, the declared certificate serial at 128 and the BICs at 11.

`SettlementExceptionHandlerTest` (11): an unexpected exception becomes a 403 deny; the response carries nothing from the exception; a validation failure becomes a 400 deny; both are audited. Added in 1.8.0: a validation failure and a failed evaluation are recorded with the transaction reference, cut to 128 characters and stripped of control characters, and a request that was never read without one; an exception message with line breaks reaches the log on one line, with its stack trace; the logged copy keeps each stack trace and bounds messages (512 characters) and causes (eight).

`ApplicationContextLoadsTest` (2): the context boots from the shipped configuration, and the one filter chain is built.

`SecurityConfigStatelessTest` (12, added in 1.8.0): a `GET` and a `POST` without credentials to nine paths inside and outside `/api/v1/**` (`/login`, `/logout`, an unknown path and the OpenAPI paths among them) are answered 401 with a Basic challenge, no redirect, no `Set-Cookie` and no server session; with credentials, three paths leave no session or cookie either. Nine of the twelve fail against 1.7.0.

`OutboundHttpTest` (8, added in 1.8.0): what the two outbound clients share — a timeout must be greater than zero; without a bundle name there is no SSL context and the registry is not consulted; the client is HTTP/1.1, follows no redirect and uses the context it is given; a stream of exactly the limit is read and one byte more fails, also byte by byte; a body within the limit is collected in order, one that passes it is abandoned there and is null, and one that fails on its way fails the result.

`OpenApiExposureDefaultProfileTest` (3) and `OpenApiExposureDevProfileTest` (2): `/v3/api-docs` and `/swagger-ui.html` are 404 under the shipped configuration and served only with the `dev` profile. Since 1.8.0 the first also requests the swagger-ui package at its `/webjars/**` paths, found on the class path, and expects 404, and the second expects the page `/swagger-ui.html` redirects to, which fails if the version in `application-dev.yml` differs from the WebJar `pom.xml` pins.

New in 1.7.0:

`GatekeeperClientSignedVerdictTest` (25): a signed verdict over the request is verified and a signed denial keeps its reason; the gatekeeper may normalise what it signs and echoes; unknown response fields are ignored; a bad signature, a verdict changed after signing, an untrusted key, an untrusted key claiming the trusted fingerprint, an algorithm outside the allow-list, tampered echo fields, a verdict signed for another request, an unsigned verdict when one is required, incomplete signature fields and an unparseable `verifiedAt` are `VERDICT_SIGNATURE_INVALID`; a verdict outside the skew in either direction is `VERDICT_STALE`, but a stale one with a bad signature is invalid; the three modes without a requirement (`UNSIGNED`, checked when a key is trusted, `UNVERIFIED`); the test seam behaves as before; configuration read at start-up; a required signature without a trusted key starts with a WARN; the verdict names its key by the `/keys` fingerprint, a verdict naming it by the certificate hash is rejected, and another certificate for the same key verifies.

`HttpPaymentNetworkClientTest` (22): a signed answer from a trusted operator key is accepted, with RSA and ECDSA; the reference is percent-encoded and echoed decoded; unknown properties are ignored; a bad signature, an artefact changed after signing, an untrusted key, an untrusted key claiming a trusted fingerprint, an answer for another reference, an algorithm outside the allow-list, malformed answers, a property that is not a string and an answer naming the key by the certificate hash are rejected; 404 is not-found, any other status, a read timeout and a refused connection are unavailable; the SSL bundle supplies the mTLS client certificate; plain HTTP is refused unless allowed and then warned; missing base URL, trust or timeout and an SSL bundle with options are start-up failures; the specification describes the path the client calls.

`ReplayGuardTest` (11), `SettlementOrchestratorHardeningTest` (15) and `SettlementPipelineIntegrationTest` (4): the replay record, its journal across a restart, concurrency (32 threads × 50 attempts; 64 evaluations on 16 threads; exactly one allow), the order lookup → replay check → gatekeeper, release on deny and on exception, and the end-to-end pipeline with a reference operator, a reference gatekeeper and a journal on disk.

`VerdictCanonicalizerTest` (4), `OperatorArtefactsCanonicalizerTest` (3), `TrustedCertificatesTest` (4): the `sv1` and `op1` golden strings and their escaping, and the key fingerprint. `HttpModeContextLoadsTest` (1), `DefaultProfileHardeningDefaultsTest` (1), `DevProfileHardeningDefaultsTest` (1): the hardened configuration loads; by default a signed verdict is required and the replay record is in memory; the `dev` profile does not require a signed verdict.

Added in 1.7.0 for mutation testing: `ReplayGuardDurabilityTest` (8 then, 11 since 1.8.0; the directory sync of a new journal, a sync per commit, the truncation of an incomplete record, a journal longer than one read, the lock released when opening fails, every commit denied after a failed write, printable ASCII lines; since 1.8.0 also a record whose sync failed cut off again and not settled after a restart, the same for the first record of a new journal, and the error that says where to cut the file when the record cannot be removed), `HttpPaymentNetworkClientConnectionTest` (6 then, rewritten for the JDK `HttpClient` in 1.8.0 and now 11; one GET with a JSON `Accept` over a connection that follows no redirect, every status other than 200 and 404 unavailable and named, a failed exchange named by its exception, an answer not complete within the read timeout unavailable and abandoned, an interrupted lookup, a body abandoned at the limit, a base URL that cannot be called, the references `.` and `..` never requested, and over a real connection the body limit at its boundary and an answer arriving a byte at a time; the percent-encoding), `VerdictVerifierTest` (4; the request fields and their echoes in a signed verdict, a blank signature field counted as missing) and `SignedStatementVerifierTest` (3; the signature value's presence, length and base64 before it is verified).

**Mutation testing.** `mvn -B -Ppit clean test-compile org.pitest:pitest-maven:mutationCoverage -Dpit.threads=$(getconf _NPROCESSORS_ONLN)` runs PIT (1.30.2 since 1.8.0) with the JUnit 5 plugin over every production class, one worker thread per core (reports in `target/pit-reports/`; without `-Dpit.threads` the profile uses 4, settable since 1.7.0; `getconf _NPROCESSORS_ONLN` works on macOS and Linux). In 1.8.0 as released every one of the 502 mutants is killed, none by timeout (PIT 1.30.2 on the build machine, run on 2026-11-10). On the 1.8.0 code as it stood before the corrections that followed the review of 2026-11-09, every one of the 484 mutants was killed, none by timeout (PIT 1.30.2, build machine, 2026-11-10). In 1.7.0 every one of the 497 mutants was killed, the code added in 1.7.0 (signed verdicts, the operator client, the replay record) included; in 1.6.0 every one of the 185 mutants was killed. Neither total can be set against the 497: run again on the 1.7.0 code, PIT 1.30.1 generates 485 mutants (OpenJDK 21), and on the code before the corrections the same number in every class as the 1.30.2 run, so the first corrections of 1.8.0 removed one mutant and those that followed the review added a net 18. The run of 2026-10-31 counted 12 more. The PIT version is not the reason: on the build machine 1.30.1 and 1.30.2 generate the same 484 mutants. Two differences are known and neither is confirmed for that run: the build machine's JDK was upgraded between the two dates (JDK 27 on 2026-11-10), and which compiler had written `target/classes` on 2026-10-31 is not recorded. PIT generates other mutants in classes an IDE has rebuilt with the Eclipse compiler than in javac's (`CROSS_REFERENCE.md`, item 17), so run it with `clean` in the same command and with the IDE closed. The profile fails below 100 % (`mutationThreshold`). Three mutants of the first run could not be killed because the mutated code behaved identically; the constructs behind them were redundant and are gone: an explicit `Content-Type` that Jackson's converter sets anyway (still asserted by `forwardsExactlyTheFourDataMinimisedFields`), a truncation guard whose boundary returned the same string (`sanitise` now takes `substring(0, min(length, max))`), and an early return for a zero-byte read in the counting stream. In 1.8.0 a fourth: once the filter chain for the paths outside `/api/v1/**` had been made stateless, removing the `/api/v1/**` chain changed nothing a request could observe, and `SecurityConfig` now has one chain for every path.

OWASP Dependency-Check runs with the `owasp` profile (`mvn -B -Powasp verify`; not in the default build since 1.6.0); in 1.6.0 it passed without suppressions (`.owasp-suppressions.xml` is empty). Since 1.7.0 the plugin is 13.0.0, which does not run without an NVD API key (dependency-check/DependencyCheck#8715); the `owasp` profile reads it from `NVD_API_KEY`. For 1.7.0 the scan ran on 2026-10-31 with NVD and Sonatype OSS Index (token in `OSS_INDEX_TOKEN`): no finding at CVSS 7 or higher after two Spring Security suppressions in `.owasp-suppressions.xml` (CVE-2026-47838 and CVE-2026-47842, both outside the affected ranges in Spring's advisories), and logback-classic 1.5.38 reports CVE-2026-19880 and CVE-2026-104721 (CVSS 6.3, not applicable: no MDC-based discriminator is configured). For 1.8.0 the scan ran on 2026-11-10 with the same result: the two logback-classic findings and nothing else, with the two suppressions unchanged. The earlier DOMPurify finding inside swagger-ui was resolved by pinning `org.webjars:swagger-ui` (5.34.1 since 1.7.0); Tomcat is no longer overridden, because Spring Boot 4.1.2 manages 11.0.27 (see `CHANGELOG.md`, Dependencies). Swagger UI itself is served only under the `dev` profile.

---

## Reproducible assertions

The following assertions are reproducible by running `mvn -B test`:

- The orchestrator's data-minimisation contract holds for the JSON wire format. (Test 1 + 4 — neither request nor response contains a transaction payload field.)
- Default-deny returns the correct structured reason code for each failure mode. (Tests 2, 3, 4.)
- Structural derivation identifies regulated payments from the two party-type flags, which are metadata the settlement system derives and supplies (see `README.md`, "What regulated-payment detection rests on"). (Test 5.)
- Non-regulated settlements are passed through without verification. (Test 6.)

---

## Configuration knobs

| Property | Default | Purpose |
|---|---|---|
| `railgate.payment-network.mode` | `in-memory` | Selects the `PaymentNetworkClient` implementation. The in-memory implementation is used by `mvn -B test` and by the reference demonstration flow; `file` for local end-to-end runs; `http` *(1.7.0)* for the operator interface in `api/payment-network-operator.openapi.yaml`. |
| `railgate.payment-network.base-url`, `allow-insecure-http`, `ssl-bundle`, `connect-timeout`, `read-timeout`, `trusted-keys` *(1.7.0)* | empty, `false`, empty, `PT2S`, `PT5S`, empty | `http` mode: the operator's base URL (`https://`), its mTLS bundle and timeouts, and the PEM of its signing certificates (required). |
| `railgate.gatekeeper.trusted-keys` *(1.7.0)* | empty | PEM of the gatekeeper's verdict-signing certificates (the one `/v1/gatekeeper/keys` publishes). |
| `railgate.gatekeeper.require-signed-verdict` *(1.7.0)* | `true` (`false` in `dev`) | Require a signed verdict. |
| `railgate.gatekeeper.verdict-max-skew` *(1.7.0)* | `PT60S` | Accepted distance between `verifiedAt` and railgate's clock. |
| `railgate.replay.path` *(1.7.0)* | empty | Journal of allowed references; empty means in memory only. |
| `railgate.gatekeeper.base-url` | `https://localhost:8443` | URL of the supervisor's gatekeeper instance. Must be `https://`; `GatekeeperClient` throws `IllegalStateException` at start-up otherwise. |
| `railgate.gatekeeper.allow-insecure-http` | `false` | Permits a non-`https` base URL for a local development run. Logs a WARN at every start-up when set. |
| `railgate.gatekeeper.connect-timeout` | `PT2S` | TCP connect timeout for gatekeeper calls; must be positive. |
| `railgate.gatekeeper.read-timeout` | `PT5S` | Time allowed for the gatekeeper's whole answer, from the request to its last byte; must be positive (until 1.7.0: each read, and zero meant none). Exceeding either timeout yields `NETWORK_ERROR` and a deny. |
| `railgate.gatekeeper.ssl-bundle` | *(empty)* | Spring Boot SSL bundle (`spring.ssl.bundle.*`) used for the gatekeeper connection's trust and key material. Empty means the JVM default SSL context; an unknown name fails start-up. |
| `railgate.regulated.local-instrument-codes` | `SWISH` | Comma-separated list of `LclInstrm/Cd` values that identify regulated payments. Matched case-insensitively and whitespace-trimmed. |

---

## Known limitations and their scope

### No payment-network operator offers the artefact interface (Critical for production)

Since 1.7.0 the interface is specified (`api/payment-network-operator.openapi.yaml`) and railgate's `http` mode implements the client, with the operator's `op1` signature verified under pinned keys. No operator, Getswish AB included, offers the endpoint today, the client has been tested only against a reference operator, and which field of Swish's payout API corresponds to `payoutInstructionId` is not established. Until an operator offers it, a deployment has only the in-memory (code-filled) and file (local, unprotected) modes. The operator's signature makes it accountable for its answer; it does not show that the artefacts are the ones the bank submitted.

### The replay record is per instance (Medium)

`ReplayGuard` refuses a second allow for a reference or payout instruction id within one railgate instance and its journal. It is not shared across instances, is lost on restart without `railgate.replay.path`, is never pruned, is not tamper-evident, and has no release for a settlement that fails downstream after `ALLOWED`.

### Verdict binding has no nonce (Low)

`sv1` binds the verdict to the request's serial, issuer and digest and to the gatekeeper's audit entry, but carries no per-call nonce, so a genuine verdict for an identical request can be presented again within `railgate.gatekeeper.verdict-max-skew`. The validity and revocation of the pinned gatekeeper and operator certificates are not checked.

### `SettlementRequest` is an abstraction, not a pacs.008 parser (High for production)

The reference accepts a Java DTO with the seven fields railgate actually needs: `transactionReference`, `localInstrumentCode`, `declaredCertSerial`, `debtorIsOrganization`, `creditorIsPrivatePerson`, `debtorBic`, `creditorBic`. A production integration with RIX-INST would receive the full pacs.008 message via SWIFT or the central-bank API and parse the relevant fields (`PmtTpInf/LclInstrm`, `Dbtr/Id`, `Cdtr/Id`, `RmtInf` etc.) before calling the orchestrator. Because railgate consumes the parsed result rather than the message, the two party-type flags are that pipeline's output and not something railgate can check.

### Refunds of Swish Handel payments are denied (High for production)

A refund of a Swish Handel payment goes from organisation to private person, so the structural path classifies it as regulated; it carries no payout signature, so railgate answers `DORA_32_AUDIT_MISSING`. `SettlementRequest` cannot tell a refund from a payout, and a refund label set on Swish's instruction would not be a control. The resolution, a reference to the original payment checked against settled RIX-INST payments and required under DORA Article 9(2) and 9(3)(c), is described in `README.md` ("Refunds of Swish Handel payments are denied") and not implemented.

### Regulatory deployment integration is the central-bank's responsibility (Inherent)

Railgate is operated by the central-bank settlement-rail operator (Sveriges Riksbank for RIX-INST), not by the supervisor (FI). The reference implementation does not attempt to model the deployment integration with a specific central bank; the central bank's IT and operational teams own that work. What this repo demonstrates is that the architecture is implementable using public standards (ISO 20022, RSA-PKCS#1 v1.5 + SHA-512) and existing supervisory mandates (DORA Art 32 oversight forum).

---

## Regulatory mapping

| DORA provision | What railgate addresses |
|---|---|
| Art 6.4 / 6.6 (operational separation) | Settlement-rail enforcement is structurally separate from the certificate-issuing bank, providing the external-actor link required by structural-independence analysis. |
| Art 6.10 (verification of compliance) | Per-settlement verification at the rail makes the verification continuous, complementing the one-time attestation verification at issuance. |
| Art 9 (ICT security) | Cryptographic signature verification (RSA-PKCS#1 v1.5 + SHA-512) of every regulated payment. |
| Art 28.4(e) (intra-group arrangements) | Default-deny prevents settlement of payments whose certificates were not issued through the structurally compliant gatekeeper flow. |
| Art 32 (oversight forum) | Provides the formal coordination basis between supervisor (gatekeeper-operator) and central bank (railgate-operator). |
| Art 35–42 (supervisory powers) | Audit-log of railgate decisions supports the supervisory record. |

| GDPR provision | What railgate addresses |
|---|---|
| Art 5(1)(c) (data minimisation) | The supervisor's verification chain receives only digest, signature, and certificate identifiers — never transaction payload content. SHA-512 collision resistance binds the digest to the signed payload; binding it to the settled message would require the rail to carry the signed fields (see `README.md`). |

---

## How to extend

For a production deployment, the following extension points must be addressed:

1. **Payment-network operator** — since 1.7.0 the client is `railgate.payment-network.mode=http` against the interface in `api/payment-network-operator.openapi.yaml`; what remains is an operator that offers it (a participation condition), its signing certificate in `railgate.payment-network.trusted-keys`, and an mTLS client certificate in `railgate.payment-network.ssl-bundle`. An operator with a different interface needs its own `PaymentNetworkClient` bean.
2. **pacs.008 ingress** — wire the `SettlementController.precheck` endpoint into the central-bank settlement pipeline. The pipeline must extract the seven fields modelled by `SettlementRequest` from the incoming pacs.008 and synchronously block the settlement based on the orchestrator's response. Both party-type flags are required; omitting them is a 400, not a pass-through.
3. **mTLS configuration** — production deployments require mTLS in both directions. *Outbound:* railgate → gatekeeper, where the `SETTLEMENT_RAIL` role authorises the call to `/api/v1/verify`; define the truststore and client key as a Spring Boot SSL bundle and name it in `railgate.gatekeeper.ssl-bundle`. *Inbound:* settlement rail → railgate, where `SecurityConfig`'s filter chain ships HTTP Basic and the deployer substitutes `.x509(...)` together with `server.ssl.client-auth=need`. Since 1.7.0 railgate also verifies the gatekeeper's signed verdict, which needs the gatekeeper's verdict-signing certificate in `railgate.gatekeeper.trusted-keys`; the outbound TLS configuration still protects the confidentiality of the request and the authentication of railgate to the gatekeeper.
5. **Shared replay record** — for several railgate instances, back `ReplayGuard` with a store they share, with a defined release for settlements that fail downstream.
4. **Persistent audit log** — the `RailgateAuditLog` reference uses an in-memory list. Production deployments must back this with a tamper-evident persistent log (a hash-chained append-only file in the manner of `AppendOnlyFileAuditLog` in the gatekeeper repo would be a suitable starting point).

---

## How to cite

See `CITATION.cff`. When citing, please cite all three companion artefacts together where appropriate (hsm, gatekeeper, railgate).
