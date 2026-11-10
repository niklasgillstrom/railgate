package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.signing.TrustedCertificates;
import eu.gillstrom.railgate.testsupport.ReferenceOperator;
import eu.gillstrom.railgate.testsupport.SilentServer;
import eu.gillstrom.railgate.testsupport.TestKeys;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How {@link HttpPaymentNetworkClient} conducts one exchange with the
 * operator: the request it sends, what it makes of each status and failure,
 * and that it waits for an answer no longer than its read timeout. Most of it
 * is observed through {@link HttpPaymentNetworkClient#send}, with an answer
 * that never touches the network.
 */
class HttpPaymentNetworkClientConnectionTest {

    /** A status and a body. */
    private record Answer(int statusCode, byte[] body, HttpRequest request) implements HttpResponse<byte[]> {

        @Override
        public Optional<HttpResponse<byte[]>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return HttpHeaders.of(Map.of(), (name, value) -> true);
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public URI uri() {
            return request.uri();
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }
    }

    private static TrustedCertificates operatorTrust() {
        return TrustedCertificates.of(List.of(TestKeys.certificate(TestKeys.OPERATOR_CERT)));
    }

    private HttpRequest requested;
    private CompletableFuture<HttpResponse<byte[]>> pending;

    /** A client whose exchanges are answered by {@code answer} instead of the network. */
    private HttpPaymentNetworkClient client(String baseUrl, Duration readTimeout,
                                            Function<HttpRequest, CompletableFuture<HttpResponse<byte[]>>> answer) {
        return new HttpPaymentNetworkClient(baseUrl, false, null, null, Duration.ofMillis(1500), readTimeout,
                operatorTrust()) {
            @Override
            CompletableFuture<HttpResponse<byte[]>> send(HttpRequest request) {
                requested = request;
                pending = answer.apply(request);
                return pending;
            }
        };
    }

    private PaymentNetworkLookup lookup(int status, byte[] body) {
        return client("https://operator.test", Duration.ofSeconds(5),
                request -> CompletableFuture.completedFuture(new Answer(status, body, request))).lookup("UETR-1");
    }

    private PaymentNetworkLookup lookupFailingWith(Throwable failure) {
        return client("https://operator.test", Duration.ofSeconds(5),
                request -> CompletableFuture.failedFuture(failure)).lookup("UETR-1");
    }

    private static String unavailableDetail(PaymentNetworkLookup lookup) {
        assertThat(lookup).isInstanceOf(PaymentNetworkLookup.Unavailable.class);
        return ((PaymentNetworkLookup.Unavailable) lookup).detail();
    }

    private static String invalidDetail(PaymentNetworkLookup lookup) {
        assertThat(lookup).isInstanceOf(PaymentNetworkLookup.OperatorSignatureInvalid.class);
        return ((PaymentNetworkLookup.OperatorSignatureInvalid) lookup).detail();
    }

    @Test
    void oneGetWithAJsonAcceptHeaderOverAConnectionThatFollowsNoRedirect() {
        HttpPaymentNetworkClient client = client("https://operator.test/", Duration.ofMillis(2500),
                request -> CompletableFuture.completedFuture(new Answer(404, new byte[0], request)));

        assertThat(client.lookup("UETR-1")).isInstanceOf(PaymentNetworkLookup.NotFound.class);

        assertThat(requested.uri()).as("a trailing slash in the base URL is dropped")
                .isEqualTo(URI.create("https://operator.test/v1/payout-artefacts/UETR-1"));
        assertThat(requested.method()).isEqualTo("GET");
        assertThat(requested.headers().allValues("Accept")).containsExactly("application/json");
        assertThat(client.http().connectTimeout()).contains(Duration.ofMillis(1500));
        assertThat(client.http().followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
        assertThat(client.http().version()).isEqualTo(HttpClient.Version.HTTP_1_1);
    }

    @Test
    void anotherStatusThan200And404IsUnavailableAndNamed() {
        for (int status : new int[] {400, 500, 302, 204, 201, 199}) {
            assertThat(unavailableDetail(lookup(status, "ignored".getBytes(StandardCharsets.UTF_8))))
                    .isEqualTo("operator answered HTTP " + status);
        }
        assertThat(lookup(404, "{\"error\":\"unknown reference\"}".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(PaymentNetworkLookup.NotFound.class);
    }

    @Test
    void aFailedExchangeIsNamedByItsException() {
        assertThat(unavailableDetail(lookupFailingWith(new IOException()))).isEqualTo("IOException");
        assertThat(unavailableDetail(lookupFailingWith(new IOException("connection reset"))))
                .isEqualTo("IOException: connection reset");
    }

    /**
     * Until 1.7.0 the read timeout bounded each read, so an answer arriving a
     * byte at a time was not bounded.
     */
    @Test
    void anAnswerThatIsNotCompleteWithinTheReadTimeoutIsUnavailableAndAbandoned() {
        HttpPaymentNetworkClient client = client("https://operator.test", Duration.ofMillis(200),
                request -> new CompletableFuture<>());

        long started = System.nanoTime();
        String detail = unavailableDetail(client.lookup("UETR-1"));
        long elapsedMillis = (System.nanoTime() - started) / 1_000_000;

        assertThat(detail).isEqualTo("no complete answer within PT0.2S");
        assertThat(elapsedMillis).isBetween(150L, 5_000L);
        assertThat(pending.isCancelled()).as("the exchange is abandoned, not left running").isTrue();
    }

    @Test
    void anInterruptedLookupIsUnavailableAbandonsTheExchangeAndStaysInterrupted() {
        HttpPaymentNetworkClient client = client("https://operator.test", Duration.ofSeconds(30),
                request -> new CompletableFuture<>());

        Thread.currentThread().interrupt();
        String detail;
        boolean stillInterrupted;
        try {
            detail = unavailableDetail(client.lookup("UETR-1"));
        } finally {
            stillInterrupted = Thread.interrupted();
        }

        assertThat(detail).isEqualTo("interrupted while waiting for the operator");
        assertThat(stillInterrupted).as("the caller can still see that it was interrupted").isTrue();
        assertThat(pending.isCancelled()).isTrue();
    }

    @Test
    void anAnswerWhoseBodyWasAbandonedAtTheLimitIsRefusedAndAnyOtherBodyIsVerified() {
        assertThat(invalidDetail(lookup(200, null)))
                .isEqualTo("response body exceeds " + HttpPaymentNetworkClient.MAX_RESPONSE_BYTES + " bytes");
        assertThat(invalidDetail(lookup(200, "[]".getBytes(StandardCharsets.UTF_8))))
                .isEqualTo("response body is not a JSON object");
    }

    @Test
    void aBaseUrlTheClientCannotCallIsUnavailableWithoutAnExchange() {
        String detail = unavailableDetail(client("https://operator.test/a b", Duration.ofSeconds(5),
                request -> CompletableFuture.completedFuture(new Answer(200, new byte[0], request))).lookup("UETR-1"));

        assertThat(detail).startsWith("IllegalArgumentException: ");
        assertThat(pending).as("nothing was sent").isNull();
    }

    /**
     * As a path segment "." and ".." name a directory. A server or proxy that
     * resolves them answers for {@code /v1/payout-artefacts/} or {@code /v1/},
     * not for a payout.
     */
    @Test
    void aReferenceThatIsADotSegmentIsNotRequested() {
        HttpPaymentNetworkClient client = client("https://operator.test", Duration.ofSeconds(5),
                request -> CompletableFuture.completedFuture(new Answer(404, new byte[0], request)));
        for (String reference : new String[] {".", ".."}) {
            assertThat(client.lookup(reference)).as(reference).isInstanceOf(PaymentNetworkLookup.NotFound.class);
            assertThat(requested).as(reference).isNull();
        }

        client.lookup("...");
        assertThat(requested.uri()).as("three dots are an ordinary segment")
                .isEqualTo(URI.create("https://operator.test/v1/payout-artefacts/..."));
        client.lookup(".a");
        assertThat(requested.uri()).isEqualTo(URI.create("https://operator.test/v1/payout-artefacts/.a"));
    }

    // ---- over a real connection ---------------------------------------------------

    private static HttpPaymentNetworkClient overTheNetwork(String baseUrl, Duration readTimeout) {
        return new HttpPaymentNetworkClient(baseUrl, true, null, null, Duration.ofSeconds(2), readTimeout,
                operatorTrust());
    }

    @Test
    void aBodyOfExactlyTheLimitIsReadAndOneByteMoreIsRefused() throws Exception {
        try (ReferenceOperator operator = ReferenceOperator.start()) {
            operator.register(new ReferenceOperator.Artefacts("UETR-1", "PAYOUT-1", "0x00C0FFEE",
                    "CN=Example CA, O=Example Bank, C=SE", "ab".repeat(64), "c2lnbmF0dXJl", "2026-10-30T12:00:00Z"));
            HttpPaymentNetworkClient client = overTheNetwork(operator.baseUrl(), Duration.ofSeconds(5));

            operator.rawBody = " ".repeat(HttpPaymentNetworkClient.MAX_RESPONSE_BYTES);
            assertThat(invalidDetail(client.lookup("UETR-1"))).as("read in full, and then not JSON")
                    .doesNotContain("exceeds");

            operator.rawBody = " ".repeat(HttpPaymentNetworkClient.MAX_RESPONSE_BYTES + 1);
            assertThat(invalidDetail(client.lookup("UETR-1")))
                    .isEqualTo("response body exceeds " + HttpPaymentNetworkClient.MAX_RESPONSE_BYTES + " bytes");
        }
    }

    @Test
    void anAnswerThatArrivesAByteAtATimeIsUnavailableWhenTheReadTimeoutIsUp() throws Exception {
        String[] heads = {
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 60000\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX-Slow: "};
        for (String head : heads) {
            try (SilentServer dripping = SilentServer.dripping(head, 50)) {
                HttpPaymentNetworkClient client = overTheNetwork(dripping.baseUrl(), Duration.ofMillis(500));

                long started = System.nanoTime();
                String detail = unavailableDetail(client.lookup("UETR-1"));
                long elapsedMillis = (System.nanoTime() - started) / 1_000_000;

                assertThat(detail).isEqualTo("no complete answer within PT0.5S");
                assertThat(elapsedMillis).isBetween(400L, 10_000L);
            }
        }
    }

    @Test
    void onlyTheUnreservedCharactersAreLeftUnencoded() {
        assertThat(HttpPaymentNetworkClient.encodePathSegment("AZaz09-._~")).isEqualTo("AZaz09-._~");
        // The neighbours of each range: '@' and '[' around A-Z, '`' and '{' around a-z, '/' and ':' around 0-9.
        assertThat(HttpPaymentNetworkClient.encodePathSegment("@[`{/:")).isEqualTo("%40%5B%60%7B%2F%3A");
    }
}
