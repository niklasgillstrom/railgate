package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.signing.TrustedCertificates;
import eu.gillstrom.railgate.testsupport.TestKeys;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How {@link HttpPaymentNetworkClient} uses its connection, observed through a
 * connection that never touches the network: the settings of the request,
 * which stream each status is read from, that every stream it opens is
 * drained and closed, and that a failed connection is disconnected.
 */
class HttpPaymentNetworkClientConnectionTest {

    /** A status, the two streams, and what the client did with the connection. */
    static final class FakeConnection extends HttpURLConnection {
        int status = 404;
        IOException failure;
        RecordingStream errorStream = new RecordingStream(new byte[0]);
        RecordingStream inputStream = new RecordingStream(new byte[0]);
        boolean disconnected;
        boolean inputRequested;

        FakeConnection(URL url) {
            super(url);
        }

        @Override
        public void connect() {
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void disconnect() {
            disconnected = true;
        }

        @Override
        public int getResponseCode() throws IOException {
            if (failure != null) {
                throw failure;
            }
            return status;
        }

        @Override
        public InputStream getErrorStream() {
            return status >= 400 ? errorStream : null;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            inputRequested = true;
            if (status >= 400) {
                // As HttpURLConnection does for an error status.
                throw new IOException("Server returned HTTP response code: " + status);
            }
            return inputStream;
        }
    }

    static final class RecordingStream extends ByteArrayInputStream {
        boolean closed;

        RecordingStream(byte[] bytes) {
            super(bytes);
        }

        RecordingStream(String text) {
            this(text.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public void close() throws IOException {
            closed = true;
            super.close();
        }

        int remaining() {
            return count - pos;
        }
    }

    private FakeConnection connection;
    private URI requested;
    private Consumer<FakeConnection> setUp = c -> { };

    private HttpPaymentNetworkClient client(String baseUrl) {
        return new HttpPaymentNetworkClient(baseUrl, false, null, null, Duration.ofMillis(1500),
                Duration.ofMillis(2500), TrustedCertificates.of(List.of(TestKeys.certificate(TestKeys.OPERATOR_CERT)))) {
            @Override
            HttpURLConnection open(URI uri) throws IOException {
                requested = uri;
                connection = new FakeConnection(uri.toURL());
                setUp.accept(connection);
                return connection;
            }
        };
    }

    private PaymentNetworkLookup lookup(Consumer<FakeConnection> setUp) {
        this.setUp = setUp;
        return client("https://operator.test").lookup("UETR-1");
    }

    private static String unavailableDetail(PaymentNetworkLookup lookup) {
        assertThat(lookup).isInstanceOf(PaymentNetworkLookup.Unavailable.class);
        return ((PaymentNetworkLookup.Unavailable) lookup).detail();
    }

    @Test
    void oneUncachedGetWithTheConfiguredTimeoutsNoRedirectsAndAJsonAcceptHeader() {
        this.setUp = c -> { };
        assertThat(client("https://operator.test/").lookup("UETR-1")).isInstanceOf(PaymentNetworkLookup.NotFound.class);

        assertThat(requested).as("a trailing slash in the base URL is dropped")
                .isEqualTo(URI.create("https://operator.test/v1/payout-artefacts/UETR-1"));
        assertThat(connection.getConnectTimeout()).isEqualTo(1500);
        assertThat(connection.getReadTimeout()).isEqualTo(2500);
        assertThat(connection.getInstanceFollowRedirects()).isFalse();
        assertThat(connection.getUseCaches()).isFalse();
        assertThat(connection.getRequestMethod()).isEqualTo("GET");
        assertThat(connection.getRequestProperty("Accept")).isEqualTo("application/json");
    }

    @Test
    void notFoundDrainsAndClosesTheErrorStreamOrHasNoneToDrain() {
        assertThat(lookup(c -> c.errorStream = new RecordingStream("{\"error\":\"unknown reference\"}")))
                .isInstanceOf(PaymentNetworkLookup.NotFound.class);
        assertThat(connection.errorStream.closed).isTrue();
        assertThat(connection.errorStream.remaining()).isZero();
        assertThat(connection.inputRequested).isFalse();

        assertThat(lookup(c -> c.errorStream = null)).isInstanceOf(PaymentNetworkLookup.NotFound.class);
    }

    @Test
    void anotherStatusDrainsTheStreamThatStatusComesOn() {
        for (int status : new int[] {400, 500}) {
            String detail = unavailableDetail(lookup(c -> {
                c.status = status;
                c.errorStream = new RecordingStream("error body");
            }));
            assertThat(detail).isEqualTo("operator answered HTTP " + status);
            assertThat(connection.errorStream.closed).as("HTTP " + status).isTrue();
            assertThat(connection.errorStream.remaining()).as("HTTP " + status).isZero();
            assertThat(connection.inputRequested).as("HTTP " + status).isFalse();
        }

        String detail = unavailableDetail(lookup(c -> {
            c.status = 302;
            c.inputStream = new RecordingStream("moved");
        }));
        assertThat(detail).isEqualTo("operator answered HTTP 302");
        assertThat(connection.inputStream.closed).isTrue();
        assertThat(connection.inputStream.remaining()).isZero();
    }

    @Test
    void aFailedExchangeIsDisconnectedAndNamedByItsException() {
        assertThat(unavailableDetail(lookup(c -> c.failure = new IOException()))).isEqualTo("IOException");
        assertThat(connection.disconnected).isTrue();

        assertThat(unavailableDetail(lookup(c -> c.failure = new IOException("connection reset"))))
                .isEqualTo("IOException: connection reset");
        assertThat(connection.disconnected).isTrue();
    }

    @Test
    void aBodyOfExactlyTheLimitIsReadAndOneByteMoreIsRefused() {
        byte[] atLimit = new byte[HttpPaymentNetworkClient.MAX_RESPONSE_BYTES];
        Arrays.fill(atLimit, (byte) ' ');

        PaymentNetworkLookup read = lookup(c -> {
            c.status = 200;
            c.inputStream = new RecordingStream(atLimit);
        });
        assertThat(read).isInstanceOf(PaymentNetworkLookup.OperatorSignatureInvalid.class);
        assertThat(((PaymentNetworkLookup.OperatorSignatureInvalid) read).detail()).doesNotContain("exceeds");

        PaymentNetworkLookup refused = lookup(c -> {
            c.status = 200;
            c.inputStream = new RecordingStream(Arrays.copyOf(atLimit, atLimit.length + 1));
        });
        assertThat(((PaymentNetworkLookup.OperatorSignatureInvalid) refused).detail())
                .isEqualTo("response body exceeds " + HttpPaymentNetworkClient.MAX_RESPONSE_BYTES + " bytes");
    }

    @Test
    void onlyTheUnreservedCharactersAreLeftUnencoded() {
        assertThat(HttpPaymentNetworkClient.encodePathSegment("AZaz09-._~")).isEqualTo("AZaz09-._~");
        // The neighbours of each range: '@' and '[' around A-Z, '`' and '{' around a-z, '/' and ':' around 0-9.
        assertThat(HttpPaymentNetworkClient.encodePathSegment("@[`{/:")).isEqualTo("%40%5B%60%7B%2F%3A");
    }
}
