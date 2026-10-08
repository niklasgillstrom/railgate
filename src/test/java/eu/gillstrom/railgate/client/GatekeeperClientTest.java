package eu.gillstrom.railgate.client;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ssl.NoSuchSslBundleException;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.matchesPattern;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for the layer where every fail-open risk in railgate actually lives.
 *
 * <p>The existing orchestrator tests mock {@link GatekeeperClient} entirely, so
 * they exercise only the code that was already correct. These tests drive the
 * real client against a stubbed transport and assert that every abnormal
 * gatekeeper response ends in a deny rather than an allow.</p>
 */
class GatekeeperClientTest {

    private static final String BASE_URL = "http://gatekeeper.test";
    private static final String VERIFY_URL = BASE_URL + "/api/v1/verify";

    /** 128 hex characters — the shape of a SHA-512 digest. */
    private static final String DIGEST_HEX = "a1b2c3d4".repeat(16);

    private RestTemplate restTemplate;
    private MockRestServiceServer server;
    private GatekeeperClient client;

    @BeforeEach
    void setUp() {
        restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        client = new GatekeeperClient(restTemplate);
        ReflectionTestUtils.setField(client, "gatekeeperBaseUrl", BASE_URL);
    }

    private static PaymentSignature signature() {
        return PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("0123456789")
                .issuerDn("CN=SEB Customer CA3 v1 for BankID")
                .build();
    }

    @Test
    void forwardsExactlyTheFourDataMinimisedFields() {
        server.expect(requestTo(VERIFY_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.certSerial").value("0123456789"))
                .andExpect(jsonPath("$.issuerDn").value("CN=SEB Customer CA3 v1 for BankID"))
                .andExpect(jsonPath("$.digestHex").value(DIGEST_HEX))
                .andExpect(jsonPath("$.signatureBase64").value("c2lnbmF0dXJl"))
                .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers
                        .header("Content-Type", org.hamcrest.Matchers.startsWith("application/json")))
                .andExpect(jsonPath("$.length()").value(4))
                .andRespond(withSuccess(
                        "{\"signatureValid\":true,\"compliant\":true,\"auditEntryId\":\"AE-1\"}",
                        MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        server.verify();
        assertThat(result.isSignatureValid()).isTrue();
        assertThat(result.isCompliant()).isTrue();
        assertThat(result.getAuditEntryId()).isEqualTo("AE-1");
    }

    @Test
    void readsTheSettlementAuditEntryHashFromTheGatekeeperResponse() {
        String hash = "ab".repeat(32);
        server.expect(requestTo(VERIFY_URL))
                .andRespond(withSuccess(
                        "{\"signatureValid\":true,\"compliant\":true,\"auditEntryId\":\"AE-3\","
                                + "\"reason\":\"OK\",\"auditEntryHashHex\":\"" + hash + "\"}",
                        MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        server.verify();
        assertThat(result.getAuditEntryId()).isEqualTo("AE-3");
        assertThat(result.getAuditEntryHashHex()).isEqualTo(hash);
    }

    @Test
    void serverErrorYieldsNetworkErrorDeny() {
        server.expect(requestTo(VERIFY_URL)).andRespond(withServerError());

        VerificationResult result = client.verify(signature());

        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
        assertThat(result.getReason()).isEqualTo("NETWORK_ERROR");
    }

    @Test
    void emptyBodyYieldsNetworkErrorDeny() {
        server.expect(requestTo(VERIFY_URL))
                .andRespond(withSuccess("", MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
        assertThat(result.getReason()).isEqualTo("NETWORK_ERROR");
    }

    @Test
    void unparseableBodyYieldsDeny() {
        server.expect(requestTo(VERIFY_URL))
                .andRespond(withSuccess("<html>not json</html>", MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
    }

    @Test
    void foreignJsonDeserialisesToDenyRatherThanAllow() {
        // A response shaped for some other API must not default to true on any
        // field. Jackson fills the missing booleans with false, which is the
        // fail-closed outcome — this test pins that behaviour.
        server.expect(requestTo(VERIFY_URL))
                .andRespond(withSuccess("{\"status\":\"OK\",\"approved\":true}",
                        MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
    }

    // ---------------------------------------------------------------
    // Transport (1.4.0)
    // ---------------------------------------------------------------

    @Test
    void plainHttpBaseUrlIsRejectedAtStartUp() {
        assertThatThrownBy(() -> new GatekeeperClient(
                        "http://gatekeeper.test",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(5),
                        false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("https://")
                .hasMessageContaining("allow-insecure-http");
    }

    @Test
    void plainHttpBaseUrlIsAllowedOnlyWhenExplicitlyOverridden() {
        assertThatCode(() -> new GatekeeperClient(
                        "http://gatekeeper.test",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(5),
                        true))
                .doesNotThrowAnyException();
    }

    @Test
    void httpsBaseUrlConstructsWithoutTheOverride() {
        assertThatCode(() -> new GatekeeperClient(
                        "https://gatekeeper.test:8443",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(5),
                        false))
                .doesNotThrowAnyException();
    }

    // ---------------------------------------------------------------
    // Input validation of cryptographic material (1.4.0)
    // ---------------------------------------------------------------

    @Test
    void digestThatIsNotAFullSha512IsRejectedWithoutCallingGatekeeper() {
        // No server.expect(...) — a call would fail verification below.
        VerificationResult result = client.verify(PaymentSignature.builder()
                .digestHex("a1b2c3")
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("0123456789")
                .issuerDn("CN=SEB Customer CA")
                .build());

        server.verify();
        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
        assertThat(result.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
    }

    @Test
    void nonHexDigestOfCorrectLengthIsRejected() {
        VerificationResult result = client.verify(PaymentSignature.builder()
                .digestHex("z".repeat(128))
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("0123456789")
                .issuerDn("CN=SEB Customer CA")
                .build());

        server.verify();
        assertThat(result.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
    }

    @Test
    void signatureThatIsNotBase64IsRejectedWithoutCallingGatekeeper() {
        VerificationResult result = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("not base64 ***")
                .certSerial("0123456789")
                .issuerDn("CN=SEB Customer CA")
                .build());

        server.verify();
        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
    }

    @Test
    void blankCertSerialOrIssuerDnIsRejectedWithoutCallingGatekeeper() {
        VerificationResult blankSerial = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("   ")
                .issuerDn("CN=SEB Customer CA")
                .build());

        VerificationResult blankIssuer = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("0123456789")
                .issuerDn(null)
                .build());

        server.verify();
        assertThat(blankSerial.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
        assertThat(blankIssuer.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
    }


    @Test
    void requestBodyMatchesTheGatekeeperSignatureVerificationRequest() {
        String certSerial = "0x00C0FFEE";
        String issuerDn = "CN=SEB Customer CA3 v1 for BankID,O=Skandinaviska Enskilda Banken AB (publ),C=SE";

        server.expect(requestTo(VERIFY_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.length()").value(4))
                .andExpect(jsonPath("$.certSerial", matchesPattern("(0[xX])?[0-9a-fA-F]{1,126}")))
                .andExpect(jsonPath("$.certSerial").value(certSerial))
                .andExpect(jsonPath("$.issuerDn").value(issuerDn))
                .andExpect(jsonPath("$.digestHex", matchesPattern("[0-9a-fA-F]{128}")))
                .andExpect(jsonPath("$.signatureBase64", matchesPattern("[A-Za-z0-9+/]+={0,2}")))
                .andExpect(jsonPath("$.signingCertificatePem").doesNotExist())
                .andExpect(jsonPath("$.algorithm").doesNotExist())
                .andRespond(withSuccess(
                        "{\"signatureValid\":true,\"compliant\":true,\"auditEntryId\":\"AE-2\",\"reason\":\"OK\"}",
                        MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial(certSerial)
                .issuerDn(issuerDn)
                .build());

        server.verify();
        assertThat(result.isAllowed()).isTrue();
    }

    @Test
    void valuesAtTheGatekeeperSizeLimitsAreForwarded() {
        String certSerial = "0x" + "f".repeat(126);
        String issuerDn = "CN=" + "a".repeat(509);
        String signatureBase64 = "AAAA".repeat(1024);

        server.expect(requestTo(VERIFY_URL))
                .andExpect(jsonPath("$.certSerial").value(certSerial))
                .andExpect(jsonPath("$.issuerDn").value(issuerDn))
                .andExpect(jsonPath("$.signatureBase64").value(signatureBase64))
                .andRespond(withSuccess(
                        "{\"signatureValid\":false,\"compliant\":false,\"reason\":\"CERT_NOT_FOUND\"}",
                        MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64(signatureBase64)
                .certSerial(certSerial)
                .issuerDn(issuerDn)
                .build());

        server.verify();
        assertThat(certSerial).hasSize(128);
        assertThat(issuerDn).hasSize(512);
        assertThat(signatureBase64).hasSize(4096);
        assertThat(result.getReason()).isEqualTo("CERT_NOT_FOUND");
    }

    @Test
    void valuesBeyondTheGatekeeperSizeLimitsAreRejectedWithoutCallingGatekeeper() {
        VerificationResult longSerial = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("f".repeat(129))
                .issuerDn("CN=SEB Customer CA")
                .build());

        VerificationResult longIssuer = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("0123456789")
                .issuerDn("CN=" + "a".repeat(510))
                .build());

        VerificationResult longSignature = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("AAAA".repeat(1025))
                .certSerial("0123456789")
                .issuerDn("CN=SEB Customer CA")
                .build());

        server.verify();
        assertThat(longSerial.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
        assertThat(longIssuer.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
        assertThat(longSignature.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
    }

    @Test
    void certSerialThatIsNotHexadecimalIsRejectedWithoutCallingGatekeeper() {
        for (String certSerial : List.of("12:34:56", "0x", "-1f", "serial 1", "0123456789\n")) {
            VerificationResult result = client.verify(PaymentSignature.builder()
                    .digestHex(DIGEST_HEX)
                    .signatureBase64("c2lnbmF0dXJl")
                    .certSerial(certSerial)
                    .issuerDn("CN=SEB Customer CA")
                    .build());

            assertThat(result.getReason()).as(certSerial).isEqualTo("INVALID_SIGNATURE_MATERIAL");
        }
        server.verify();
    }

    @Test
    void issuerDnThatIsNotADistinguishedNameIsRejectedWithoutCallingGatekeeper() {
        VerificationResult result = client.verify(PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("0123456789")
                .issuerDn("SEB Customer CA")
                .build());

        server.verify();
        assertThat(result.getReason()).isEqualTo("INVALID_SIGNATURE_MATERIAL");
    }


    @Test
    void transportErrorDetailCannotForgeLogLines() {
        Logger logger = (Logger) LoggerFactory.getLogger(GatekeeperClient.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            server.expect(requestTo(VERIFY_URL)).andRespond(request -> {
                throw new IOException("connection reset\r\nWARN forged entry");
            });

            VerificationResult result = client.verify(signature());

            assertThat(result.getReason()).isEqualTo("NETWORK_ERROR");
            assertThat(appender.list).isNotEmpty();
            assertThat(appender.list).allSatisfy(event ->
                    assertThat(event.getFormattedMessage()).doesNotContain("\r", "\n"));
        } finally {
            logger.detachAppender(appender);
        }
    }


    @Test
    void withoutAnSslBundleTheGatekeeperConnectionUsesTheJvmDefault() throws Exception {
        GatekeeperClient plain = new GatekeeperClient(
                "https://gatekeeper.test:8443",
                Duration.ofSeconds(2),
                Duration.ofSeconds(5),
                false);

        assertThat(connectionOf(plain).getSSLSocketFactory())
                .isSameAs(HttpsURLConnection.getDefaultSSLSocketFactory());
    }

    @Test
    void theConfiguredTimeoutsBoundTheGatekeeperConnection() throws Exception {
        // Without them a gatekeeper that accepts the connection and never
        // answers would hold the settlement indefinitely.
        GatekeeperClient plain = new GatekeeperClient(
                "https://gatekeeper.test:8443", Duration.ofMillis(1234), Duration.ofMillis(4321), false);
        HttpsURLConnection connection = connectionOf(plain);
        assertThat(connection.getConnectTimeout()).isEqualTo(1234);
        assertThat(connection.getReadTimeout()).isEqualTo(4321);
    }

    @Test
    void aBlankSslBundleNameDoesNotConsultTheRegistry() throws Exception {
        SslBundles bundles = mock(SslBundles.class);

        GatekeeperClient plain = new GatekeeperClient(
                "https://gatekeeper.test:8443",
                Duration.ofSeconds(2),
                Duration.ofSeconds(5),
                false,
                "",
                bundles);

        verifyNoInteractions(bundles);
        assertThat(connectionOf(plain).getSSLSocketFactory())
                .isSameAs(HttpsURLConnection.getDefaultSSLSocketFactory());
    }

    @Test
    void theConfiguredSslBundleIsAppliedToTheGatekeeperConnection() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        SslBundle bundle = mock(SslBundle.class);
        when(bundle.getOptions()).thenReturn(SslOptions.NONE);
        when(bundle.createSslContext()).thenReturn(sslContext);
        SslBundles bundles = mock(SslBundles.class);
        when(bundles.getBundle("gatekeeper")).thenReturn(bundle);

        GatekeeperClient withBundle = new GatekeeperClient(
                "https://gatekeeper.test:8443",
                Duration.ofSeconds(2),
                Duration.ofSeconds(5),
                false,
                "gatekeeper",
                bundles);

        verify(bundles).getBundle("gatekeeper");
        verify(bundle).createSslContext();
        assertThat(connectionOf(withBundle).getSSLSocketFactory())
                .isNotNull()
                .isNotSameAs(HttpsURLConnection.getDefaultSSLSocketFactory());
        assertThat(connectionOf(withBundle).getReadTimeout()).as("the bundle keeps the timeouts").isEqualTo(5000);
        assertThat(connectionOf(withBundle).getConnectTimeout()).isEqualTo(2000);
    }

    @Test
    void anUnknownSslBundleFailsAtStartUp() {
        SslBundles bundles = mock(SslBundles.class);
        when(bundles.getBundle("missing"))
                .thenThrow(new NoSuchSslBundleException("missing", "SSL bundle name 'missing' cannot be found"));

        assertThatThrownBy(() -> new GatekeeperClient(
                        "https://gatekeeper.test:8443",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(5),
                        false,
                        "missing",
                        bundles))
                .isInstanceOf(NoSuchSslBundleException.class);
    }

    @Test
    void anSslBundleWithOptionsTheConnectionCannotApplyFailsAtStartUp() {
        SslBundle bundle = mock(SslBundle.class);
        when(bundle.getOptions()).thenReturn(
                SslOptions.of(new String[] {"TLS_AES_256_GCM_SHA384"}, new String[] {"TLSv1.3"}));
        SslBundles bundles = mock(SslBundles.class);
        when(bundles.getBundle("gatekeeper")).thenReturn(bundle);

        assertThatThrownBy(() -> new GatekeeperClient(
                        "https://gatekeeper.test:8443",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(5),
                        false,
                        "gatekeeper",
                        bundles))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("gatekeeper");
    }

    private static HttpsURLConnection connectionOf(GatekeeperClient client) throws IOException {
        RestTemplate template = (RestTemplate) ReflectionTestUtils.getField(client, "restTemplate");
        ClientHttpRequest request = template.getRequestFactory()
                .createRequest(URI.create("https://gatekeeper.test:8443/api/v1/verify"), HttpMethod.POST);
        return (HttpsURLConnection) ReflectionTestUtils.getField(request, "connection");
    }

    private static PaymentSignature.PaymentSignatureBuilder valid() {
        return PaymentSignature.builder()
                .digestHex(DIGEST_HEX)
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("0123456789")
                .issuerDn("CN=SEB Customer CA3 v1 for BankID");
    }

    /**
     * Each malformed artefact is logged with the field it concerns, and never
     * with the value: the values come from the payment-network operator.
     */
    @Test
    void eachMaterialProblemIsLoggedByFieldWithoutItsValue() {
        String secret = "SECRETVALUE";
        java.util.Map<String, PaymentSignature> cases = new java.util.LinkedHashMap<>();
        cases.put("no signature artefacts supplied", null);
        cases.put("digestHex is not 128 hexadecimal characters (SHA-512)", valid().digestHex(secret).build());
        cases.put("signatureBase64 is blank", valid().signatureBase64(" ").build());
        cases.put("signatureBase64 exceeds 4096 characters", valid().signatureBase64("A".repeat(4097)).build());
        cases.put("signatureBase64 is not valid base64", valid().signatureBase64(secret + "!").build());
        cases.put("certSerial is blank", valid().certSerial(" ").build());
        cases.put("certSerial is not a hexadecimal serial of at most 128 characters",
                valid().certSerial(secret).build());
        cases.put("issuerDn is blank", valid().issuerDn(" ").build());
        cases.put("issuerDn exceeds 512 characters", valid().issuerDn("CN=" + secret + "a".repeat(510)).build());
        cases.put("issuerDn is not an RFC 4514 distinguished name", valid().issuerDn(secret).build());

        Logger logger = (Logger) LoggerFactory.getLogger(GatekeeperClient.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            cases.forEach((problem, material) -> {
                appender.list.clear();
                VerificationResult result = client.verify(material);
                assertThat(result.getReason()).as(problem).isEqualTo("INVALID_SIGNATURE_MATERIAL");
                assertThat(appender.list).as(problem).hasSize(1);
                assertThat(appender.list.get(0).getFormattedMessage()).as(problem)
                        .isEqualTo("Rejecting verification request without calling gatekeeper: " + problem)
                        .doesNotContain(secret);
            });
        } finally {
            logger.detachAppender(appender);
        }
        server.verify();
    }
}
