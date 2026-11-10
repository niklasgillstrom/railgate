package eu.gillstrom.railgate.client;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerificationResult;
import eu.gillstrom.railgate.testsupport.SilentServer;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ssl.NoSuchSslBundleException;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
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
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
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

        assertThat(httpClientOf(plain).sslContext()).isSameAs(SSLContext.getDefault());
    }

    @Test
    void theConfiguredTimeoutsBoundTheGatekeeperConnection() throws Exception {
        // Without them a gatekeeper that accepts the connection and never
        // answers would hold the settlement indefinitely.
        GatekeeperClient plain = new GatekeeperClient(
                "https://gatekeeper.test:8443", Duration.ofMillis(1234), Duration.ofMillis(4321), false);
        assertThat(httpClientOf(plain).connectTimeout()).contains(Duration.ofMillis(1234));
        assertThat(readTimeoutOf(plain)).isEqualTo(Duration.ofMillis(4321));
    }

    @Test
    void theGatekeeperConnectionIsHttp11AndFollowsNoRedirect() throws Exception {
        GatekeeperClient plain = new GatekeeperClient(
                "https://gatekeeper.test:8443", Duration.ofSeconds(2), Duration.ofSeconds(5), false);
        assertThat(httpClientOf(plain).followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
        assertThat(httpClientOf(plain).version()).isEqualTo(HttpClient.Version.HTTP_1_1);
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
        assertThat(httpClientOf(plain).sslContext()).isSameAs(SSLContext.getDefault());
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
        assertThat(httpClientOf(withBundle).sslContext()).isSameAs(sslContext);
        assertThat(readTimeoutOf(withBundle)).as("the bundle keeps the timeouts").isEqualTo(Duration.ofSeconds(5));
        assertThat(httpClientOf(withBundle).connectTimeout()).contains(Duration.ofSeconds(2));
    }

    @Test
    void aBundleNameWithoutARegistryFailsAtStartUp() {
        assertThatThrownBy(() -> new GatekeeperClient(
                        "https://gatekeeper.test:8443",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(5),
                        false,
                        " gatekeeper ",
                        null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("railgate.gatekeeper.ssl-bundle is 'gatekeeper' but no SSL bundle registry is available.");
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
                .hasMessage("SSL bundle 'gatekeeper' (railgate.gatekeeper.ssl-bundle) sets ciphers or enabled "
                        + "protocols. railgate does not apply them to its outbound connections; remove the "
                        + "bundle's options or use a bundle without them.");
    }

    private static Object requestFactoryOf(GatekeeperClient client) {
        RestTemplate template = (RestTemplate) ReflectionTestUtils.getField(client, "restTemplate");
        return ReflectionTestUtils.getField(template, "requestFactory");
    }

    private static HttpClient httpClientOf(GatekeeperClient client) {
        return (HttpClient) ReflectionTestUtils.getField(requestFactoryOf(client), "httpClient");
    }

    private static Duration readTimeoutOf(GatekeeperClient client) {
        return (Duration) ReflectionTestUtils.getField(requestFactoryOf(client), "readTimeout");
    }

    // ---------------------------------------------------------------
    // Status, duration and size of the answer (1.8.0)
    // ---------------------------------------------------------------

    private static final String ALLOWING_VERDICT =
            "{\"signatureValid\":true,\"compliant\":true,\"auditEntryId\":\"AE-1\",\"reason\":\"OK\"}";

    /**
     * Until 1.7.0 only 4xx and 5xx were errors, and the body of a 3xx answer
     * was read as the verdict.
     */
    @ParameterizedTest
    @ValueSource(ints = {300, 301, 302, 303, 307, 308, 100, 199, 400, 404, 503})
    void anAllowingBodyUnderAnyStatusOtherThan2xxIsADeny(int status) {
        server.expect(requestTo(VERIFY_URL)).andRespond(
                withStatus(HttpStatusCode.valueOf(status)).contentType(MediaType.APPLICATION_JSON)
                        .body(ALLOWING_VERDICT));

        VerificationResult result = client.verify(signature());

        assertThat(result.getReason()).as("HTTP " + status).isEqualTo("NETWORK_ERROR");
        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 201, 299})
    void aVerdictUnderA2xxStatusIsRead(int status) {
        server.expect(requestTo(VERIFY_URL)).andRespond(
                withStatus(HttpStatusCode.valueOf(status)).contentType(MediaType.APPLICATION_JSON)
                        .body(ALLOWING_VERDICT));

        VerificationResult result = client.verify(signature());

        assertThat(result.getReason()).as("HTTP " + status).isEqualTo("OK");
        assertThat(result.isSignatureValid()).isTrue();
    }

    @Test
    void theStatusOfARefusedAnswerIsLoggedAndItsBodyIsNot() {
        Logger logger = (Logger) LoggerFactory.getLogger(GatekeeperClient.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            server.expect(requestTo(VERIFY_URL)).andRespond(
                    withStatus(HttpStatus.FOUND).contentType(MediaType.APPLICATION_JSON).body(ALLOWING_VERDICT));

            client.verify(signature());

            assertThat(appender.list).singleElement().satisfies(event ->
                    assertThat(event.getFormattedMessage())
                            .isEqualTo("Gatekeeper unreachable for cert 0123456789: the gatekeeper answered HTTP 302"));
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void aTimeoutThatIsNotPositiveIsRefusedAtStartUp() {
        Duration ok = Duration.ofSeconds(2);
        for (Duration refused : new Duration[] {null, Duration.ZERO, Duration.ofSeconds(-1)}) {
            assertThatThrownBy(() -> new GatekeeperClient("https://gatekeeper.test:8443", refused, ok, false))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("railgate.gatekeeper.connect-timeout must be a positive duration");
            assertThatThrownBy(() -> new GatekeeperClient("https://gatekeeper.test:8443", ok, refused, false))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("railgate.gatekeeper.read-timeout must be a positive duration");
        }
    }

    private static GatekeeperClient clientFor(String baseUrl, Duration readTimeout) {
        return new GatekeeperClient(baseUrl, Duration.ofSeconds(2), readTimeout, true);
    }

    /**
     * Until 1.7.0 the read timeout bounded each read, so a gatekeeper that
     * sent a byte before each one expired was not bounded at all.
     */
    @Test
    void anAnswerThatArrivesAByteAtATimeEndsInADenyWhenTheReadTimeoutIsUp() throws Exception {
        try (SilentServer dripping = SilentServer.dripping(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 60000\r\n\r\n", 50)) {
            GatekeeperClient client = clientFor(dripping.baseUrl(), Duration.ofMillis(500));

            long started = System.nanoTime();
            VerificationResult result = client.verify(signature());
            long elapsedMillis = (System.nanoTime() - started) / 1_000_000;

            assertThat(result.getReason()).isEqualTo("NETWORK_ERROR");
            assertThat(elapsedMillis).as("the bytes kept coming for as long as railgate listened")
                    .isBetween(400L, 10_000L);
        }
    }

    @Test
    void headersThatArriveAByteAtATimeEndInADenyAsWell() throws Exception {
        try (SilentServer dripping = SilentServer.dripping("HTTP/1.1 200 OK\r\nX-Slow: ", 50)) {
            GatekeeperClient client = clientFor(dripping.baseUrl(), Duration.ofMillis(500));

            long started = System.nanoTime();
            VerificationResult result = client.verify(signature());
            long elapsedMillis = (System.nanoTime() - started) / 1_000_000;

            assertThat(result.getReason()).isEqualTo("NETWORK_ERROR");
            assertThat(elapsedMillis).isBetween(400L, 10_000L);
        }
    }

    @Test
    void aGatekeeperThatAcceptsAndNeverAnswersEndsInADeny() throws Exception {
        try (SilentServer silent = SilentServer.silent()) {
            GatekeeperClient client = clientFor(silent.baseUrl(), Duration.ofMillis(500));

            long started = System.nanoTime();
            VerificationResult result = client.verify(signature());
            long elapsedMillis = (System.nanoTime() - started) / 1_000_000;

            assertThat(result.getReason()).isEqualTo("NETWORK_ERROR");
            assertThat(elapsedMillis).isBetween(400L, 10_000L);
        }
    }

    @Test
    void anAnswerLargerThanTheLimitIsADenyAndOneWithinItIsRead() throws Exception {
        String padding = " ".repeat(GatekeeperClient.MAX_RESPONSE_BYTES - ALLOWING_VERDICT.length());
        byte[][] bodies = {
                (ALLOWING_VERDICT + padding).getBytes(StandardCharsets.UTF_8),
                (ALLOWING_VERDICT + padding + " ").getBytes(StandardCharsets.UTF_8)};
        String[] expected = {"OK", "NETWORK_ERROR"};

        for (int i = 0; i < bodies.length; i++) {
            byte[] body = bodies[i];
            HttpServer gatekeeper = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            gatekeeper.createContext("/api/v1/verify", exchange -> {
                try (exchange) {
                    exchange.getRequestBody().readAllBytes();
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, body.length);
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(body);
                    }
                }
            });
            gatekeeper.start();
            try {
                GatekeeperClient client = clientFor("http://127.0.0.1:" + gatekeeper.getAddress().getPort(),
                        Duration.ofSeconds(5));

                assertThat(client.verify(signature()).getReason()).as(body.length + " bytes").isEqualTo(expected[i]);
            } finally {
                gatekeeper.stop(0);
            }
        }
    }

    @Test
    void theBoundedResponseIsTheGatekeepersInEveryOtherRespect() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        boolean[] closed = {false};
        ClientHttpResponse answer = new ClientHttpResponse() {
            @Override
            public HttpStatusCode getStatusCode() {
                return HttpStatus.ACCEPTED;
            }

            @Override
            public String getStatusText() {
                return "Accepted";
            }

            @Override
            public HttpHeaders getHeaders() {
                return headers;
            }

            @Override
            public InputStream getBody() {
                return new ByteArrayInputStream(new byte[GatekeeperClient.MAX_RESPONSE_BYTES + 1]);
            }

            @Override
            public void close() {
                closed[0] = true;
            }
        };
        GatekeeperClient.BoundedResponse response = new GatekeeperClient.BoundedResponse(answer);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getStatusText()).isEqualTo("Accepted");
        assertThat(response.getHeaders()).isSameAs(headers);
        InputStream body = response.getBody();
        assertThat(body.readNBytes(GatekeeperClient.MAX_RESPONSE_BYTES)).hasSize(GatekeeperClient.MAX_RESPONSE_BYTES);
        assertThatThrownBy(body::read).isInstanceOf(IOException.class)
                .hasMessage("the answer exceeds 65536 bytes");
        response.close();
        assertThat(closed[0]).isTrue();
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
