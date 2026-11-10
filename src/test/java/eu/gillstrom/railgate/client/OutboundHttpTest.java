package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.client.OutboundHttp.BoundedInputStream;
import eu.gillstrom.railgate.client.OutboundHttp.LimitedBody;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ssl.SslBundles;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * What the two outbound clients share: positive timeouts, the client they
 * call with, and the two bounds on the size of an answer.
 */
class OutboundHttpTest {

    /** A subscription that records what the subscriber asked of it. */
    private static final class Subscription implements Flow.Subscription {
        long requested;
        boolean cancelled;

        @Override
        public void request(long n) {
            requested = n;
        }

        @Override
        public void cancel() {
            cancelled = true;
        }
    }

    private static byte[] bytes(int length) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) 'x');
        return bytes;
    }

    private static ByteBuffer buffer(String text) {
        return ByteBuffer.wrap(text.getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void aTimeoutMustBeGreaterThanZero() {
        Duration timeout = Duration.ofMillis(1500);
        assertThat(OutboundHttp.positive(timeout, "p")).isSameAs(timeout);

        for (Duration refused : new Duration[] {null, Duration.ZERO, Duration.ofNanos(-1)}) {
            assertThatThrownBy(() -> OutboundHttp.positive(refused, "railgate.some.timeout"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("railgate.some.timeout must be a positive duration");
        }
    }

    @Test
    void withoutABundleNameThereIsNoContextAndTheRegistryIsNotConsulted() {
        SslBundles bundles = mock(SslBundles.class);

        assertThat(OutboundHttp.sslContext("p", null, bundles)).isNull();
        assertThat(OutboundHttp.sslContext("p", "  ", bundles)).isNull();
        verifyNoInteractions(bundles);
    }

    @Test
    void theClientIsHttp11FollowsNoRedirectAndUsesTheContextItIsGiven() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);

        HttpClient withContext = OutboundHttp.client(Duration.ofMillis(700), context);
        HttpClient withDefault = OutboundHttp.client(Duration.ofMillis(700), null);

        assertThat(withContext.sslContext()).isSameAs(context);
        assertThat(withDefault.sslContext()).isSameAs(SSLContext.getDefault());
        assertThat(withContext.connectTimeout()).contains(Duration.ofMillis(700));
        assertThat(withContext.version()).isEqualTo(HttpClient.Version.HTTP_1_1);
        assertThat(withContext.followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
    }

    // ---- a stream that is read by the caller ---------------------------------------

    @Test
    void aStreamOfExactlyTheLimitIsReadAndOneByteMoreFails() throws IOException {
        BoundedInputStream atLimit = new BoundedInputStream(new ByteArrayInputStream(bytes(8)), 8);
        byte[] buffer = new byte[16];
        assertThat(atLimit.read(buffer, 0, 16)).isEqualTo(8);
        assertThat(atLimit.read(buffer, 0, 16)).as("end of stream is not counted").isEqualTo(-1);
        assertThat(atLimit.read(buffer, 0, 16)).isEqualTo(-1);

        BoundedInputStream over = new BoundedInputStream(new ByteArrayInputStream(bytes(9)), 8);
        assertThat(over.read(buffer, 0, 5)).isEqualTo(5);
        assertThatThrownBy(() -> over.read(buffer, 5, 11))
                .isInstanceOf(IOException.class)
                .hasMessage("the answer exceeds 8 bytes");
    }

    @Test
    void readingByteByByteGivesTheSameBytesAndTheSameLimit() throws IOException {
        BoundedInputStream stream = new BoundedInputStream(
                new ByteArrayInputStream(new byte[] {'A', (byte) 0xE9, 0}), 3);
        assertThat(stream.read()).isEqualTo('A');
        assertThat(stream.read()).as("an unsigned byte").isEqualTo(0xE9);
        assertThat(stream.read()).isZero();
        assertThat(stream.read()).isEqualTo(-1);

        BoundedInputStream over = new BoundedInputStream(new ByteArrayInputStream(bytes(2)), 1);
        assertThat(over.read()).isEqualTo('x');
        assertThatThrownBy(over::read).isInstanceOf(IOException.class);
    }

    // ---- a body that is delivered to a subscriber -----------------------------------

    @Test
    void aBodyWithinTheLimitIsCollectedInOrderAcrossBuffersAndDeliveries() {
        LimitedBody body = new LimitedBody(8);
        Subscription subscription = new Subscription();
        CompletableFuture<byte[]> result = body.getBody().toCompletableFuture();

        body.onSubscribe(subscription);
        assertThat(subscription.requested).as("everything is asked for at once").isEqualTo(Long.MAX_VALUE);
        body.onNext(List.of(buffer("ab"), buffer("cd")));
        body.onNext(List.of(buffer("efgh")));
        assertThat(result).as("not before the body is complete").isNotDone();
        body.onComplete();

        assertThat(result).isCompleted();
        assertThat(new String(result.join(), StandardCharsets.US_ASCII)).isEqualTo("abcdefgh");
        assertThat(subscription.cancelled).isFalse();
    }

    @Test
    void aBodyThatPassesTheLimitIsAbandonedThereAndIsNull() {
        LimitedBody body = new LimitedBody(8);
        Subscription subscription = new Subscription();
        CompletableFuture<byte[]> result = body.getBody().toCompletableFuture();
        body.onSubscribe(subscription);

        body.onNext(List.of(buffer("abcd"), buffer("efgh")));
        assertThat(subscription.cancelled).isFalse();
        body.onNext(List.of(buffer("i")));

        assertThat(subscription.cancelled).as("the rest of the body is not received").isTrue();
        assertThat(result).isCompletedWithValue(null);
    }

    @Test
    void aBodyThatFailsOnItsWayFailsTheResult() {
        LimitedBody body = new LimitedBody(8);
        body.onSubscribe(new Subscription());
        IOException reset = new IOException("connection reset");

        body.onError(reset);

        assertThat(body.getBody().toCompletableFuture()).isCompletedExceptionally();
        assertThatThrownBy(() -> body.getBody().toCompletableFuture().join()).hasCause(reset);
    }
}
