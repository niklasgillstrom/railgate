package eu.gillstrom.railgate.client;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/**
 * What railgate's two outbound connections have in common: to the gatekeeper
 * ({@link GatekeeperClient}) and to the payment-network operator
 * ({@link HttpPaymentNetworkClient}).
 *
 * <p>Both use the JDK's {@link HttpClient}, over HTTP/1.1, without following
 * redirects. Until 1.7.0 both used {@code HttpURLConnection}, whose read
 * timeout bounds each read separately: a peer that sent one byte before each
 * one expired kept the call, and the settlement waiting for it, open for as
 * long as it chose. An exchange of the JDK client can be cancelled as a
 * whole, so the time each client allows for an answer now bounds the whole
 * answer.</p>
 */
final class OutboundHttp {

    private OutboundHttp() {
    }

    /**
     * @return {@code duration}
     * @throws IllegalStateException when it is null, zero or negative
     */
    static Duration positive(Duration duration, String property) {
        if (duration == null || duration.isZero() || duration.isNegative()) {
            throw new IllegalStateException(property + " must be a positive duration");
        }
        return duration;
    }

    /**
     * The SSL context of the Spring Boot SSL bundle named by {@code property},
     * or {@code null} when it names none and the JVM default applies.
     *
     * @throws IllegalStateException when a bundle is named but no registry is
     *     available, or when the bundle sets ciphers or enabled protocols,
     *     which railgate does not apply
     * @throws org.springframework.boot.ssl.NoSuchSslBundleException when the
     *     name is not a configured bundle
     */
    static SSLContext sslContext(String property, String sslBundle, SslBundles sslBundles) {
        if (sslBundle == null || sslBundle.isBlank()) {
            return null;
        }
        String bundleName = sslBundle.trim();
        if (sslBundles == null) {
            throw new IllegalStateException(property + " is '" + bundleName
                    + "' but no SSL bundle registry is available.");
        }
        SslBundle bundle = sslBundles.getBundle(bundleName);
        if (bundle.getOptions() != null && bundle.getOptions().isSpecified()) {
            throw new IllegalStateException("SSL bundle '" + bundleName + "' (" + property + ") sets ciphers "
                    + "or enabled protocols. railgate does not apply them to its outbound connections; "
                    + "remove the bundle's options or use a bundle without them.");
        }
        return bundle.createSslContext();
    }

    /**
     * An HTTP/1.1 client that follows no redirect.
     *
     * @param sslContext key and trust material, or {@code null} for the JVM
     *     default
     */
    static HttpClient client(Duration connectTimeout, SSLContext sslContext) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(connectTimeout);
        if (sslContext != null) {
            builder.sslContext(sslContext);
        }
        return builder.build();
    }

    /** A stream that fails once more than {@code limit} bytes have been read from it. */
    static final class BoundedInputStream extends FilterInputStream {

        private final int limit;
        private long total;

        BoundedInputStream(InputStream in, int limit) {
            super(in);
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) == -1 ? -1 : one[0] & 0xFF;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int n = super.read(buffer, offset, length);
            if (n != -1) {
                total += n;
                if (total > limit) {
                    throw new IOException("the answer exceeds " + limit + " bytes");
                }
            }
            return n;
        }
    }

    /**
     * Collects a response body of at most {@code limit} bytes. A longer body
     * is abandoned where it passes the limit, and the result is {@code null}.
     */
    static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {

        private final int limit;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private Flow.Subscription subscription;

        LimitedBody(int limit) {
            this.limit = limit;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (bytes.size() + buffer.remaining() > limit) {
                    subscription.cancel();
                    body.complete(null);
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                bytes.writeBytes(chunk);
            }
        }

        @Override
        public void onError(Throwable failure) {
            body.completeExceptionally(failure);
        }

        @Override
        public void onComplete() {
            body.complete(bytes.toByteArray());
        }
    }
}
