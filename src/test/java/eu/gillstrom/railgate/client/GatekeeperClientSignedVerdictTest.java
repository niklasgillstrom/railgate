package eu.gillstrom.railgate.client;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerdictSignatureStatus;
import eu.gillstrom.railgate.model.VerificationResult;
import eu.gillstrom.railgate.signing.TrustedCertificates;
import eu.gillstrom.railgate.testsupport.TestKeys;
import eu.gillstrom.railgate.testsupport.VerdictSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The gatekeeper's verdict signature ({@code sv1}), checked by
 * {@link GatekeeperClient} through {@link VerdictVerifier}, against verdicts
 * signed with a test gatekeeper key ({@link VerdictSigner}).
 */
class GatekeeperClientSignedVerdictTest {

    private static final String BASE_URL = "https://gatekeeper.test";
    private static final String VERIFY_URL = BASE_URL + "/api/v1/verify";
    private static final Instant NOW = Instant.parse("2026-10-30T12:00:30Z");

    /** What railgate sends: un-normalised spellings on purpose. */
    private static final PaymentSignature SENT = PaymentSignature.builder()
            .certSerial("0x00C0FFEE")
            .issuerDn("CN=Example CA, O=Example Bank, C=SE")
            .digestHex("AB".repeat(64))
            .signatureBase64("c2lnbmF0dXJl")
            .build();

    private RestTemplate restTemplate;
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
    }

    private static TrustedCertificates gatekeeperTrust() {
        return TrustedCertificates.of(List.of(TestKeys.certificate(TestKeys.GATEKEEPER_CERT)));
    }

    private GatekeeperClient client(boolean requireSigned, TrustedCertificates trusted) {
        GatekeeperClient client = new GatekeeperClient(restTemplate,
                new VerdictVerifier(trusted, requireSigned, Duration.ofSeconds(60), Clock.fixed(NOW, ZoneOffset.UTC)));
        ReflectionTestUtils.setField(client, "gatekeeperBaseUrl", BASE_URL);
        return client;
    }

    private GatekeeperClient requiring() {
        return client(true, gatekeeperTrust());
    }

    private static VerdictSigner signer() {
        return new VerdictSigner(SENT.getCertSerial(), SENT.getIssuerDn(), SENT.getDigestHex());
    }

    private VerificationResult respond(GatekeeperClient client, String body) {
        server.reset();
        server.expect(requestTo(VERIFY_URL))
                .andExpect(jsonPath("$.length()").value(4))
                .andRespond(withSuccess(body, MediaType.APPLICATION_JSON));
        VerificationResult result = client.verify(SENT);
        server.verify();
        return result;
    }

    private VerificationResult respond(GatekeeperClient client, Map<String, Object> body) {
        return respond(client, VerdictSigner.json(body));
    }

    private static Map<String, Object> edited(Map<String, Object> body, Consumer<Map<String, Object>> edit) {
        Map<String, Object> copy = new LinkedHashMap<>(body);
        edit.accept(copy);
        return copy;
    }

    private static void assertRejected(VerificationResult result, String reason) {
        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
        assertThat(result.isAllowed()).isFalse();
        assertThat(result.getReason()).isEqualTo(reason);
        assertThat(result.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.INVALID);
        assertThat(result.getAuditEntryId()).as("nothing from a rejected verdict is kept").isNull();
        assertThat(result.getAuditEntryHashHex()).isNull();
    }

    // ---------------------------------------------------------------
    // Verified
    // ---------------------------------------------------------------

    @Test
    void aSignedVerdictOverTheRequestIsVerified() {
        VerdictSigner signer = signer();
        signer.verifiedAt = "2026-10-30T12:00:00Z";

        VerificationResult result = respond(requiring(), signer.json());

        assertThat(result.isAllowed()).isTrue();
        assertThat(result.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.VERIFIED);
        assertThat(result.getAuditEntryId()).isEqualTo("AE-SIGNED");
        assertThat(result.getAuditEntryHashHex()).isEqualTo("ab".repeat(32));
    }

    @Test
    void aSignedDenialKeepsItsReason() {
        VerdictSigner signer = signer();
        signer.signatureValid = false;
        signer.compliant = false;
        signer.reason = "CERT_NOT_FOUND";
        signer.auditEntryId = null;

        VerificationResult result = respond(requiring(), signer.json());

        assertThat(result.isAllowed()).isFalse();
        assertThat(result.getReason()).isEqualTo("CERT_NOT_FOUND");
        assertThat(result.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.VERIFIED);
    }

    @Test
    void theGatekeeperMayNormaliseTheFieldsItSignsAndEchoes() {
        VerdictSigner signer = new VerdictSigner("c0ffee", "CN=Example CA,O=Example Bank,C=SE", "ab".repeat(64));
        Map<String, Object> body = signer.body();
        body.put("certSerial", "C0FFEE");
        body.put("issuerDn", "CN=Example CA,O=Example Bank,C=SE");
        body.put("digestHex", "ab".repeat(64));

        assertThat(respond(requiring(), body).getVerdictSignature()).isEqualTo(VerdictSignatureStatus.VERIFIED);
    }

    @Test
    void unknownResponseFieldsAreIgnored() {
        Map<String, Object> body = signer().body();
        body.put("someFutureField", Map.of("nested", 1));
        body.put("anotherOne", "x");

        VerificationResult signed = respond(requiring(), body);
        VerificationResult unsigned = respond(client(false, TrustedCertificates.none()),
                "{\"signatureValid\":true,\"compliant\":true,\"auditEntryId\":\"AE-1\",\"extra\":[1,2]}");

        assertThat(signed.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.VERIFIED);
        assertThat(signed.isAllowed()).isTrue();
        assertThat(unsigned.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.UNSIGNED);
        assertThat(unsigned.isAllowed()).isTrue();
    }

    /** SHA-256 of the test gatekeeper key's DER SubjectPublicKeyInfo (OpenSSL), as gatekeeper's /keys has it. */
    private static final String GATEKEEPER_KEY_FINGERPRINT =
            "90c3bfc9e07a6ba10a166140b32b98effc7d6aab6de6e6f37cf3507a614046d8";

    @Test
    void theVerdictNamesItsKeyByTheFingerprintGatekeeperPublishesOnKeys() {
        Map<String, Object> body = signer().body();

        assertThat(body.get("signingKeyFingerprintHex")).isEqualTo(GATEKEEPER_KEY_FINGERPRINT);
        assertThat(respond(requiring(), body).getVerdictSignature()).isEqualTo(VerdictSignatureStatus.VERIFIED);
    }

    @Test
    void aVerdictNamingItsKeyByTheHashOfTheCertificateIsRejected() {
        // SHA-256 of the DER certificate (OpenSSL): railgate's convention
        // before it was aligned with gatekeeper's /keys. It selects no key.
        Map<String, Object> body = edited(signer().body(), b -> b.put("signingKeyFingerprintHex",
                "512df98f330ad29f29f6af4a5b723e044602297f07492603568bb10cc6a994c1"));

        assertRejected(respond(requiring(), body), "VERDICT_SIGNATURE_INVALID");
    }

    @Test
    void aVerdictVerifiesUnderAnotherTrustedCertificateForTheSameKey() {
        GatekeeperClient client = client(true, TrustedCertificates.of(List.of(
                TestKeys.certificate("signing/gatekeeper-cert-reissued.pem"))));

        assertThat(respond(client, signer().json()).getVerdictSignature())
                .isEqualTo(VerdictSignatureStatus.VERIFIED);
    }

    // ---------------------------------------------------------------
    // VERDICT_SIGNATURE_INVALID
    // ---------------------------------------------------------------

    @Test
    void aBadSignatureIsRejected() {
        Map<String, Object> body = signer().body();
        byte[] signature = Base64.getDecoder().decode((String) body.get("verdictSignatureBase64"));
        signature[signature.length / 2] ^= 0x01;
        body.put("verdictSignatureBase64", Base64.getEncoder().encodeToString(signature));

        assertRejected(respond(requiring(), body), "VERDICT_SIGNATURE_INVALID");
    }

    @Test
    void aVerdictChangedAfterSigningIsRejected() {
        VerdictSigner signer = signer();
        signer.compliant = false;
        signer.reason = "CERT_NON_COMPLIANT";
        Map<String, Object> signed = signer.body();

        List<Map<String, Object>> tampered = List.of(
                edited(signed, b -> b.put("compliant", true)),
                edited(signed, b -> { b.put("compliant", true); b.put("reason", "OK"); }),
                edited(signed, b -> b.put("auditEntryId", "AE-OTHER")),
                edited(signed, b -> b.put("auditEntryHashHex", "cd".repeat(32))),
                edited(signed, b -> b.put("verifiedAt", "2026-10-30T12:00:01Z")),
                edited(signed, b -> b.put("signatureValid", false)));
        for (Map<String, Object> body : tampered) {
            assertRejected(respond(requiring(), body), "VERDICT_SIGNATURE_INVALID");
        }
    }

    @Test
    void anUntrustedKeyIsRejected() {
        VerdictSigner signer = signer();
        signer.key = TestKeys.privateKey(TestKeys.UNTRUSTED_KEY);
        signer.certificate = TestKeys.certificate(TestKeys.UNTRUSTED_CERT);
        signer.algorithm = "SHA256withRSA";

        assertRejected(respond(requiring(), signer.json()), "VERDICT_SIGNATURE_INVALID");
    }

    @Test
    void anUntrustedKeyClaimingTheTrustedFingerprintIsRejected() {
        VerdictSigner signer = signer();
        signer.key = TestKeys.privateKey(TestKeys.UNTRUSTED_KEY);
        signer.algorithm = "SHA256withRSA";

        assertRejected(respond(requiring(), signer.json()), "VERDICT_SIGNATURE_INVALID");
    }

    @Test
    void anAlgorithmOutsideTheAllowListIsRejected() {
        VerdictSigner signer = signer();
        signer.algorithm = "SHA1withECDSA";

        assertRejected(respond(requiring(), signer.json()), "VERDICT_SIGNATURE_INVALID");
    }

    @Test
    void tamperedEchoFieldsAreRejected() {
        Map<String, Object> signed = signer().body();

        assertRejected(respond(requiring(), edited(signed, b -> b.put("certSerial", "0x00C0FFEF"))),
                "VERDICT_SIGNATURE_INVALID");
        assertRejected(respond(requiring(), edited(signed, b -> b.put("issuerDn", "CN=Other CA,O=Example Bank,C=SE"))),
                "VERDICT_SIGNATURE_INVALID");
        assertRejected(respond(requiring(), edited(signed, b -> b.put("digestHex", "cd".repeat(64)))),
                "VERDICT_SIGNATURE_INVALID");
        assertRejected(respond(requiring(), edited(signed, b -> b.put("certSerial", "not hex"))),
                "VERDICT_SIGNATURE_INVALID");
    }

    @Test
    void aVerdictSignedForAnotherRequestIsRejectedEvenWithoutEchoFields() {
        // A genuine verdict for a different digest, serial or issuer, replayed
        // against this request. Nothing is echoed; the canonical bytes are built
        // from what railgate sent, so the signature does not verify.
        VerdictSigner otherDigest = signer();
        otherDigest.digestHex = "cd".repeat(64);
        VerdictSigner otherSerial = signer();
        otherSerial.certSerial = "0x00C0FFEF";
        VerdictSigner otherIssuer = signer();
        otherIssuer.issuerDn = "CN=Other CA,O=Example Bank,C=SE";

        for (VerdictSigner signer : List.of(otherDigest, otherSerial, otherIssuer)) {
            assertRejected(respond(requiring(), signer.json()), "VERDICT_SIGNATURE_INVALID");
        }
    }

    @Test
    void anUnsignedVerdictIsRejectedWhenASignatureIsRequired() {
        String unsigned = "{\"signatureValid\":true,\"compliant\":true,\"auditEntryId\":\"AE-1\","
                + "\"verdictSignature\":\"VERIFIED\"}";

        assertRejected(respond(requiring(), unsigned), "VERDICT_SIGNATURE_INVALID");
        assertRejected(respond(client(true, TrustedCertificates.none()), signer().json()),
                "VERDICT_SIGNATURE_INVALID");
    }

    @Test
    void incompleteSignatureFieldsAreRejected() {
        Map<String, Object> signed = signer().body();

        assertRejected(respond(requiring(), edited(signed, b -> b.remove("signingKeyFingerprintHex"))),
                "VERDICT_SIGNATURE_INVALID");
        assertRejected(respond(client(false, gatekeeperTrust()), edited(signed, b -> b.put("verdictSignatureAlgorithm", " "))),
                "VERDICT_SIGNATURE_INVALID");
    }

    @Test
    void aSignedVerdictWithAnUnparseableTimestampIsRejected() {
        VerdictSigner signer = signer();
        signer.verifiedAt = "30 October 2026";

        assertRejected(respond(requiring(), signer.json()), "VERDICT_SIGNATURE_INVALID");
    }

    // ---------------------------------------------------------------
    // VERDICT_STALE
    // ---------------------------------------------------------------

    @Test
    void aVerdictOutsideTheSkewIsStaleInEitherDirection() {
        VerdictSigner past = signer();
        past.verifiedAt = NOW.minusSeconds(61).toString();
        VerdictSigner future = signer();
        future.verifiedAt = NOW.plusSeconds(61).toString();
        VerdictSigner edge = signer();
        edge.verifiedAt = NOW.minusSeconds(60).toString();

        assertRejected(respond(requiring(), past.json()), "VERDICT_STALE");
        assertRejected(respond(requiring(), future.json()), "VERDICT_STALE");
        assertThat(respond(requiring(), edge.json()).getVerdictSignature()).isEqualTo(VerdictSignatureStatus.VERIFIED);
    }

    @Test
    void aStaleVerdictWithABadSignatureIsReportedAsInvalidNotStale() {
        VerdictSigner signer = signer();
        signer.verifiedAt = NOW.minusSeconds(3600).toString();
        Map<String, Object> body = edited(signer.body(), b -> b.put("compliant", false));

        assertRejected(respond(requiring(), body), "VERDICT_SIGNATURE_INVALID");
    }

    // ---------------------------------------------------------------
    // require-signed-verdict=false
    // ---------------------------------------------------------------

    @Test
    void anUnsignedVerdictIsUsedAndMarkedUnsignedWhenNoSignatureIsRequired() {
        String unsigned = "{\"signatureValid\":true,\"compliant\":true,\"auditEntryId\":\"AE-1\","
                + "\"verdictSignature\":\"VERIFIED\"}";

        VerificationResult result = respond(client(false, gatekeeperTrust()), unsigned);

        assertThat(result.isAllowed()).isTrue();
        assertThat(result.getAuditEntryId()).isEqualTo("AE-1");
        assertThat(result.getVerdictSignature())
                .as("the status is railgate's, never the gatekeeper's").isEqualTo(VerdictSignatureStatus.UNSIGNED);
    }

    @Test
    void withoutARequirementASignedVerdictIsStillCheckedWhenAKeyIsTrusted() {
        Map<String, Object> tampered = edited(signer().body(), b -> b.put("auditEntryId", "AE-OTHER"));

        assertRejected(respond(client(false, gatekeeperTrust()), tampered), "VERDICT_SIGNATURE_INVALID");
        assertThat(respond(client(false, gatekeeperTrust()), signer().json()).getVerdictSignature())
                .isEqualTo(VerdictSignatureStatus.VERIFIED);
    }

    @Test
    void withoutARequirementOrATrustedKeyASignedVerdictIsUsedUnverified() {
        VerificationResult result = respond(client(false, TrustedCertificates.none()), signer().json());

        assertThat(result.isAllowed()).isTrue();
        assertThat(result.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.UNVERIFIED);
    }

    @Test
    void theTestSeamWithoutAVerifierBehavesAsBeforeSignedVerdicts() {
        GatekeeperClient legacy = new GatekeeperClient(restTemplate);
        ReflectionTestUtils.setField(legacy, "gatekeeperBaseUrl", BASE_URL);

        assertThat(respond(legacy, "{\"signatureValid\":true,\"compliant\":true}").getVerdictSignature())
                .isEqualTo(VerdictSignatureStatus.UNSIGNED);
        assertThat(respond(legacy, signer().json()).getVerdictSignature())
                .isEqualTo(VerdictSignatureStatus.UNVERIFIED);
    }

    // ---------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------

    @Test
    void theConfigurationIsReadAtStartUp() {
        @SuppressWarnings("unchecked")
        ObjectProvider<SslBundles> noBundles = mock(ObjectProvider.class);

        assertThatCode(() -> new GatekeeperClient("https://gatekeeper.test:8443", Duration.ofSeconds(2),
                Duration.ofSeconds(5), false, "", noBundles, "classpath:" + TestKeys.GATEKEEPER_CERT, true,
                Duration.ofSeconds(60))).doesNotThrowAnyException();
        assertThatThrownBy(() -> new GatekeeperClient("https://gatekeeper.test:8443", Duration.ofSeconds(2),
                Duration.ofSeconds(5), false, "", noBundles, "classpath:signing/absent.pem", true,
                Duration.ofSeconds(60)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("railgate.gatekeeper.trusted-keys");
        assertThatThrownBy(() -> new GatekeeperClient("https://gatekeeper.test:8443", Duration.ofSeconds(2),
                Duration.ofSeconds(5), false, "", noBundles, "", true, Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("verdict-max-skew");
    }

    @Test
    void requiringASignatureWithoutATrustedKeyStartsButWarns() {
        Logger logger = (Logger) LoggerFactory.getLogger(VerdictVerifier.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            VerdictVerifier required = VerdictVerifier.fromConfiguration("", true, Duration.ofSeconds(60), Clock.systemUTC());
            VerdictVerifier notRequired = VerdictVerifier.fromConfiguration(" ", false, Duration.ofSeconds(60), Clock.systemUTC());

            assertThat(required.isSignatureRequired()).isTrue();
            assertThat(notRequired.isSignatureRequired()).isFalse();
            assertThat(appender.list).hasSize(2).allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.WARN));
            assertThat(appender.list.get(0).getFormattedMessage()).contains("every settlement");
            assertThat(appender.list.get(1).getFormattedMessage()).contains("MUST NOT be deployed");
        } finally {
            logger.detachAppender(appender);
        }
    }
}
