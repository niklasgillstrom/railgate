package eu.gillstrom.railgate.client;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.signing.TrustedCertificates;
import eu.gillstrom.railgate.testsupport.ReferenceOperator;
import eu.gillstrom.railgate.testsupport.ReferenceOperator.Artefacts;
import eu.gillstrom.railgate.testsupport.TestKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.core.io.ClassPathResource;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link HttpPaymentNetworkClient} against {@link ReferenceOperator}, an
 * operator implementing {@code api/payment-network-operator.openapi.yaml} that
 * signs with a test key.
 */
class HttpPaymentNetworkClientTest {

    private static final String DIGEST = "c0de".repeat(32);
    private static final Artefacts ARTEFACTS = new Artefacts("UETR-HTTP-1", "PAYOUT-1", "0x00C0FFEE",
            "CN=Example CA, O=Example Bank, C=SE", DIGEST, "c2lnbmF0dXJl", "2026-10-30T12:00:00Z");

    private ReferenceOperator operator;
    private HttpPaymentNetworkClient client;

    @BeforeEach
    void setUp() throws Exception {
        operator = ReferenceOperator.start();
        operator.register(ARTEFACTS);
        client = client(operator.baseUrl(), operatorTrust());
    }

    @AfterEach
    void tearDown() {
        operator.close();
    }

    private static TrustedCertificates operatorTrust() {
        return TrustedCertificates.of(List.of(TestKeys.certificate(TestKeys.OPERATOR_CERT)));
    }

    private static HttpPaymentNetworkClient client(String baseUrl, TrustedCertificates trusted) {
        return new HttpPaymentNetworkClient(baseUrl, true, null, null,
                Duration.ofSeconds(2), Duration.ofSeconds(2), trusted);
    }

    private static String invalidDetail(PaymentNetworkLookup lookup) {
        assertThat(lookup).isInstanceOf(PaymentNetworkLookup.OperatorSignatureInvalid.class);
        return ((PaymentNetworkLookup.OperatorSignatureInvalid) lookup).detail();
    }

    // ---------------------------------------------------------------
    // Accepted
    // ---------------------------------------------------------------

    @Test
    void aSignedAnswerFromATrustedOperatorKeyIsAccepted() {
        PaymentNetworkLookup lookup = client.lookup("UETR-HTTP-1");

        assertThat(lookup).isInstanceOf(PaymentNetworkLookup.Found.class);
        PaymentSignature signature = ((PaymentNetworkLookup.Found) lookup).signature();
        assertThat(signature.getCertSerial()).as("as the operator sent it").isEqualTo("0x00C0FFEE");
        assertThat(signature.getIssuerDn()).isEqualTo("CN=Example CA, O=Example Bank, C=SE");
        assertThat(signature.getDigestHex()).isEqualTo(DIGEST);
        assertThat(signature.getSignatureBase64()).isEqualTo("c2lnbmF0dXJl");
        assertThat(signature.getPayoutInstructionId()).isEqualTo("PAYOUT-1");
        assertThat(client.getSignature("UETR-HTTP-1")).contains(signature);
        assertThat(operator.rawPaths()).containsOnly("/v1/payout-artefacts/UETR-HTTP-1");
    }

    @Test
    void rsaAndEcdsaAlgorithmsOnTheAllowListAreAccepted() {
        operator.algorithm = "SHA512withRSA";
        assertThat(client.lookup("UETR-HTTP-1")).isInstanceOf(PaymentNetworkLookup.Found.class);

        operator.signingKey = TestKeys.privateKey(TestKeys.GATEKEEPER_KEY);
        operator.signingCertificate = TestKeys.certificate(TestKeys.GATEKEEPER_CERT);
        operator.algorithm = "SHA384withECDSA";
        HttpPaymentNetworkClient ecClient = client(operator.baseUrl(), TrustedCertificates.of(List.of(
                TestKeys.certificate(TestKeys.OPERATOR_CERT), TestKeys.certificate(TestKeys.GATEKEEPER_CERT))));
        assertThat(ecClient.lookup("UETR-HTTP-1")).isInstanceOf(PaymentNetworkLookup.Found.class);
    }

    @Test
    void theReferenceIsPercentEncodedAsAPathSegmentAndEchoedDecoded() {
        String reference = "E2E|ID%01/x y;+\u00c5~";
        operator.register(new Artefacts(reference, "PAYOUT-2", "0a", "CN=I,C=SE", DIGEST, "c2ln", "2026-10-30T12:00:00Z"));

        assertThat(client.lookup(reference)).isInstanceOf(PaymentNetworkLookup.Found.class);
        assertThat(operator.rawPaths()).containsExactly("/v1/payout-artefacts/E2E%7CID%2501%2Fx%20y%3B%2B%C3%85~");
    }

    @Test
    void unknownPropertiesInTheAnswerAreIgnored() {
        operator.tamper = body -> {
            Map<String, String> extended = new java.util.LinkedHashMap<>(body);
            extended.put("operatorNote", "not signed, not used");
            return extended;
        };

        assertThat(client.lookup("UETR-HTTP-1")).isInstanceOf(PaymentNetworkLookup.Found.class);
    }

    // ---------------------------------------------------------------
    // Rejected: OPERATOR_SIGNATURE_INVALID
    // ---------------------------------------------------------------

    @Test
    void aBadOperatorSignatureIsRejected() {
        operator.tamper = body -> {
            Map<String, String> copy = new java.util.LinkedHashMap<>(body);
            byte[] signature = java.util.Base64.getDecoder().decode(copy.get("operatorSignatureBase64"));
            signature[signature.length - 1] ^= 0x01;
            copy.put("operatorSignatureBase64", java.util.Base64.getEncoder().encodeToString(signature));
            return copy;
        };

        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("does not verify");
        assertThat(client.getSignature("UETR-HTTP-1")).isEmpty();
    }

    @Test
    void anArtefactChangedAfterSigningIsRejected() {
        for (String property : List.of("digestHex", "certSerial", "issuerDn", "signatureBase64", "issuedAt",
                "payoutInstructionId")) {
            operator.tamper = body -> {
                Map<String, String> copy = new java.util.LinkedHashMap<>(body);
                copy.put(property, switch (property) {
                    case "digestHex" -> "d0de".repeat(32);
                    case "certSerial" -> "0x00C0FFEF";
                    case "issuerDn" -> "CN=Other CA,O=Example Bank,C=SE";
                    case "issuedAt" -> "2026-10-30T12:00:01Z";
                    default -> copy.get(property) + "X";
                });
                return copy;
            };
            assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).as(property).contains("does not verify");
        }
    }

    @Test
    void aSignatureByAnUntrustedKeyIsRejected() {
        operator.signingKey = TestKeys.privateKey(TestKeys.UNTRUSTED_KEY);
        operator.signingCertificate = TestKeys.certificate(TestKeys.UNTRUSTED_CERT);

        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("matches no trusted certificate");
    }

    @Test
    void anAnswerNamingTheOperatorKeyByTheHashOfTheCertificateIsRejected() {
        // operatorKeyFingerprintHex is the SHA-256 of the DER SubjectPublicKeyInfo
        // (gatekeeper's /keys convention); the SHA-256 of the DER certificate
        // (OpenSSL) selects no trusted certificate.
        operator.tamper = body -> {
            Map<String, String> copy = new java.util.LinkedHashMap<>(body);
            assertThat(copy.get("operatorKeyFingerprintHex"))
                    .isEqualTo("345f117f9e4af2d32ccc66d4f7a6a92631f15afa657a8ee28dcc4bcc7230e878");
            copy.put("operatorKeyFingerprintHex", "a60f8ad2fe7bef00a5bc12ca70454d69270c7957376589911010a949837ca274");
            return copy;
        };

        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("matches no trusted certificate");
    }

    @Test
    void anUntrustedKeyClaimingATrustedFingerprintIsRejected() {
        // The fingerprint only selects a certificate; the signature must verify under it.
        operator.signingKey = TestKeys.privateKey(TestKeys.UNTRUSTED_KEY);

        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("does not verify");
    }

    @Test
    void anAnswerForAnotherReferenceIsRejectedEvenWhenValidlySigned() {
        operator.register(new Artefacts("UETR-HTTP-OTHER", "PAYOUT-9", "0a", "CN=I,C=SE", DIGEST, "c2ln", "t"));
        operator.echoedReference = "UETR-HTTP-OTHER";

        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("transactionReference");
    }

    @Test
    void anAlgorithmOutsideTheAllowListIsRejected() {
        operator.algorithm = "SHA1withRSA";

        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("allow-list");
    }

    @Test
    void malformedAnswersAreRejected() {
        for (String body : List.of("not json", "[]", "{\"transactionReference\":\"UETR-HTTP-1\"}",
                "{\"a\":1,\"a\":2}")) {
            operator.rawBody = body;
            assertThat(client.lookup("UETR-HTTP-1")).as(body)
                    .isInstanceOf(PaymentNetworkLookup.OperatorSignatureInvalid.class);
        }
        operator.rawBody = null;
        operator.tamper = body -> {
            Map<String, String> copy = new java.util.LinkedHashMap<>(body);
            copy.put("payoutInstructionId", "has space");
            return copy;
        };
        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("payoutInstructionId");
        operator.tamper = body -> {
            Map<String, String> copy = new java.util.LinkedHashMap<>(body);
            copy.put("certSerial", "not-hex");
            return copy;
        };
        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("canonicalised");
        operator.tamper = java.util.function.UnaryOperator.identity();
        operator.rawBody = "{\"pad\":\"" + "x".repeat(HttpPaymentNetworkClient.MAX_RESPONSE_BYTES) + "\"}";
        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("exceeds");
    }

    @Test
    void aPropertyThatIsNotAJsonStringIsRejected() {
        Map<String, String> signed = operator.signedResponse(ARTEFACTS);
        String json = tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(signed)
                .replace("\"payoutInstructionId\":\"PAYOUT-1\"", "\"payoutInstructionId\":[\"PAYOUT-1\"]");
        operator.rawBody = json;

        assertThat(invalidDetail(client.lookup("UETR-HTTP-1"))).contains("not a string");
    }

    // ---------------------------------------------------------------
    // 404 and transport
    // ---------------------------------------------------------------

    @Test
    void anUnknownReferenceIsNotFound() {
        assertThat(client.lookup("UETR-UNKNOWN")).isInstanceOf(PaymentNetworkLookup.NotFound.class);
        assertThat(client.getSignature("UETR-UNKNOWN")).isEmpty();
        assertThat(client.lookup(" ")).isInstanceOf(PaymentNetworkLookup.NotFound.class);
    }

    @Test
    void anyOtherStatusIsUnavailable() {
        for (int status : new int[] {500, 503, 401, 403, 302, 204}) {
            operator.status = status;
            assertThat(client.lookup("UETR-HTTP-1")).as("HTTP " + status)
                    .isInstanceOf(PaymentNetworkLookup.Unavailable.class);
        }
    }

    @Test
    void aReadTimeoutIsUnavailable() {
        operator.delayMillis = 2_000;
        HttpPaymentNetworkClient impatient = new HttpPaymentNetworkClient(operator.baseUrl(), true, null, null,
                Duration.ofSeconds(1), Duration.ofMillis(200), operatorTrust());

        assertThat(impatient.lookup("UETR-HTTP-1")).isInstanceOf(PaymentNetworkLookup.Unavailable.class);
    }

    @Test
    void aRefusedConnectionIsUnavailable() {
        String baseUrl = operator.baseUrl();
        operator.close();

        assertThat(client(baseUrl, operatorTrust()).lookup("UETR-HTTP-1"))
                .isInstanceOf(PaymentNetworkLookup.Unavailable.class);
    }

    // ---------------------------------------------------------------
    // mTLS through an SSL bundle
    // ---------------------------------------------------------------

    @Test
    void theSslBundleSuppliesTheClientCertificateForMutualTls() throws Exception {
        SslBundle bundle = SslBundle.of(new PemSslStoreBundle(
                PemSslStoreDetails.forCertificate("classpath:tls/test-cert.pem").withPrivateKey("classpath:tls/test-key.pem"),
                PemSslStoreDetails.forCertificate("classpath:tls/test-cert.pem")));
        SslBundles bundles = mock(SslBundles.class);
        when(bundles.getBundle("operator")).thenReturn(bundle);

        try (ReferenceOperator https = ReferenceOperator.startMutualTls(bundle.createSslContext())) {
            https.register(ARTEFACTS);
            HttpPaymentNetworkClient withBundle = new HttpPaymentNetworkClient(https.baseUrl(), false, "operator",
                    bundles, Duration.ofSeconds(2), Duration.ofSeconds(2), operatorTrust());
            HttpPaymentNetworkClient withoutBundle = new HttpPaymentNetworkClient(https.baseUrl(), false, null,
                    null, Duration.ofSeconds(2), Duration.ofSeconds(2), operatorTrust());

            SslBundle trustOnly = SslBundle.of(new PemSslStoreBundle(null,
                    PemSslStoreDetails.forCertificate("classpath:tls/test-cert.pem")));
            SslBundles trustOnlyBundles = mock(SslBundles.class);
            when(trustOnlyBundles.getBundle("trust-only")).thenReturn(trustOnly);
            HttpPaymentNetworkClient withoutClientCertificate = new HttpPaymentNetworkClient(https.baseUrl(), false,
                    "trust-only", trustOnlyBundles, Duration.ofSeconds(2), Duration.ofSeconds(2), operatorTrust());

            assertThat(withBundle.lookup("UETR-HTTP-1")).isInstanceOf(PaymentNetworkLookup.Found.class);
            assertThat(withoutBundle.lookup("UETR-HTTP-1"))
                    .as("no client certificate and no trust in the operator's certificate")
                    .isInstanceOf(PaymentNetworkLookup.Unavailable.class);
            assertThat(withoutClientCertificate.lookup("UETR-HTTP-1"))
                    .as("the operator is trusted, but the operator requires a client certificate")
                    .isInstanceOf(PaymentNetworkLookup.Unavailable.class);
            assertThat(https.rawPaths()).as("only the mutually authenticated request got through")
                    .containsExactly("/v1/payout-artefacts/UETR-HTTP-1");
        }
    }

    // ---------------------------------------------------------------
    // Start-up
    // ---------------------------------------------------------------

    @Test
    void plainHttpIsRefusedUnlessExplicitlyAllowedAndThenWarned() {
        assertThatThrownBy(() -> new HttpPaymentNetworkClient("http://operator.test", false, null, null,
                Duration.ofSeconds(2), Duration.ofSeconds(5), operatorTrust()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("https://")
                .hasMessageContaining("railgate.payment-network.allow-insecure-http");

        Logger logger = (Logger) LoggerFactory.getLogger(HttpPaymentNetworkClient.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            assertThatCode(() -> new HttpPaymentNetworkClient("http://operator.test", true, null, null,
                    Duration.ofSeconds(2), Duration.ofSeconds(5), operatorTrust())).doesNotThrowAnyException();
            assertThat(appender.list).anySatisfy(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage()).contains("MUST NOT be deployed");
            });
        } finally {
            logger.detachAppender(appender);
        }
        assertThatThrownBy(() -> new HttpPaymentNetworkClient("ftp://operator.test", true, null, null,
                Duration.ofSeconds(2), Duration.ofSeconds(5), operatorTrust()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aMissingBaseUrlTrustOrTimeoutIsAStartUpFailure() {
        assertThatThrownBy(() -> new HttpPaymentNetworkClient(" ", false, null, null,
                Duration.ofSeconds(2), Duration.ofSeconds(5), operatorTrust()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("base-url");
        assertThatThrownBy(() -> new HttpPaymentNetworkClient("https://operator.test", false, null, null,
                Duration.ofSeconds(2), Duration.ofSeconds(5), TrustedCertificates.none()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("trusted-keys");
        assertThatThrownBy(() -> new HttpPaymentNetworkClient("https://operator.test", false, null, null,
                Duration.ofSeconds(2), Duration.ZERO, operatorTrust()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("read-timeout");
        ObjectProviderStub providers = new ObjectProviderStub();
        assertThatThrownBy(() -> new HttpPaymentNetworkClient("https://operator.test", false, "", Duration.ofSeconds(2),
                Duration.ofSeconds(5), "", providers))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("trusted-keys");
        assertThatCode(() -> new HttpPaymentNetworkClient("https://operator.test", false, "", Duration.ofSeconds(2),
                Duration.ofSeconds(5), "classpath:" + TestKeys.OPERATOR_CERT, providers)).doesNotThrowAnyException();
    }

    @Test
    void anSslBundleWithOptionsTheConnectionCannotApplyIsAStartUpFailure() {
        SslBundle bundle = mock(SslBundle.class);
        when(bundle.getOptions()).thenReturn(SslOptions.of(new String[] {"TLS_AES_256_GCM_SHA384"}, null));
        SslBundles bundles = mock(SslBundles.class);
        when(bundles.getBundle("operator")).thenReturn(bundle);

        assertThatThrownBy(() -> new HttpPaymentNetworkClient("https://operator.test", false, "operator", bundles,
                Duration.ofSeconds(2), Duration.ofSeconds(5), operatorTrust()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("operator");
    }

    // ---------------------------------------------------------------
    // The specification's own example
    // ---------------------------------------------------------------

    @Test
    void theSpecificationDescribesThePathTheClientCalls() throws Exception {
        Path spec = Path.of("api/payment-network-operator.openapi.yaml");
        Map<String, Object> document;
        try (InputStream in = Files.newInputStream(spec)) {
            document = new Yaml().load(in);
        }
        assertThat(document.get("openapi")).isEqualTo("3.0.3");
        @SuppressWarnings("unchecked")
        Map<String, Object> paths = (Map<String, Object>) document.get("paths");
        assertThat(paths).containsOnlyKeys(HttpPaymentNetworkClient.PATH + "{transactionReference}");
        String text = Files.readString(spec, StandardCharsets.UTF_8);
        for (String algorithm : eu.gillstrom.railgate.signing.SignedStatementVerifier.ALLOWED_ALGORITHMS) {
            assertThat(text).as("the allow-list is published").contains("- " + algorithm + "\n");
        }
        assertThat(text).contains("4a6ac4f4b5f085aaa27d79539d073cece820ae854d17bcb85b77133f545b038d");
        assertThat(new ClassPathResource(TestKeys.OPERATOR_CERT).exists()).isTrue();
    }

    /** Minimal ObjectProvider for the Spring-facing constructor. */
    private static final class ObjectProviderStub implements org.springframework.beans.factory.ObjectProvider<SslBundles> {
        @Override
        public SslBundles getObject() {
            return null;
        }

        @Override
        public SslBundles getObject(Object... args) {
            return null;
        }

        @Override
        public SslBundles getIfAvailable() {
            return null;
        }

        @Override
        public SslBundles getIfUnique() {
            return null;
        }
    }
}
