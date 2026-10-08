package eu.gillstrom.railgate.security;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestSizeLimitFilterTest {

    @Test
    void aDeclaredLengthAboveTheCapIs413BeforeTheBodyIsRead() throws Exception {
        RequestSizeLimitFilter filter = new RequestSizeLimitFilter("16B");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/settle/precheck");
        request.setContent(new byte[17]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentType()).isEqualTo("application/json;charset=UTF-8");
        assertThat(response.getContentAsString()).contains("\"error\":\"request_too_large\"");
        assertThat(chain.getRequest()).as("the chain is not entered").isNull();
    }

    @Test
    void aDeclaredEmptyBodyIsPassedThroughUnwrapped() throws Exception {
        RequestSizeLimitFilter filter = new RequestSizeLimitFilter("16B");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/settle/precheck");
        request.setContent(new byte[0]);
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(request.getContentLengthLong()).isZero();
        assertThat(chain.getRequest()).isSameAs(request);
    }

    /** Records what the counting stream forwards to the stream it wraps. */
    private static final class RecordingStream extends jakarta.servlet.ServletInputStream {
        private final java.io.ByteArrayInputStream bytes = new java.io.ByteArrayInputStream(new byte[] {7, 8, 9});
        boolean closed;
        jakarta.servlet.ReadListener listener;

        @Override public int read() { return bytes.read(); }
        @Override public int available() { return bytes.available(); }
        @Override public void close() { closed = true; }
        @Override public boolean isFinished() { return bytes.available() == 0; }
        @Override public boolean isReady() { return !closed; }
        @Override public void setReadListener(jakarta.servlet.ReadListener readListener) { listener = readListener; }
    }

    @Test
    void theCountingStreamForwardsToTheStreamItWraps() throws Exception {
        RecordingStream underlying = new RecordingStream();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/settle/precheck") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }

            @Override
            public jakarta.servlet.ServletInputStream getInputStream() {
                return underlying;
            }
        };
        AtomicReference<HttpServletRequest> seen = new AtomicReference<>();
        new RequestSizeLimitFilter("16B").doFilter(request, new MockHttpServletResponse(),
                (req, res) -> seen.set((HttpServletRequest) req));
        var in = seen.get().getInputStream();
        assertThat(in).isNotSameAs(underlying);

        assertThat(in.read()).isEqualTo(7);
        assertThat(in.available()).isEqualTo(2);
        assertThat(in.isFinished()).isFalse();
        assertThat(in.isReady()).isTrue();
        assertThat(in.read()).isEqualTo(8);
        assertThat(in.read()).isEqualTo(9);
        assertThat(in.isFinished()).isTrue();

        jakarta.servlet.ReadListener listener = new jakarta.servlet.ReadListener() {
            @Override public void onDataAvailable() { }
            @Override public void onAllDataRead() { }
            @Override public void onError(Throwable t) { }
        };
        in.setReadListener(listener);
        assertThat(underlying.listener).isSameAs(listener);

        in.close();
        assertThat(underlying.closed).isTrue();
        assertThat(in.isReady()).isFalse();
    }

    @Test
    void aDeclaredLengthAtTheCapPasses() throws Exception {
        RequestSizeLimitFilter filter = new RequestSizeLimitFilter("16B");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/settle/precheck");
        request.setContent(new byte[16]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).isSameAs(request);
    }

    @Test
    void anUndeclaredLengthIsCountedWhileRead() throws Exception {
        RequestSizeLimitFilter filter = new RequestSizeLimitFilter("16B");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/settle/precheck") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }

            @Override
            public int getContentLength() {
                return -1;
            }
        };
        request.setContent(new byte[17]);
        AtomicReference<HttpServletRequest> seen = new AtomicReference<>();
        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> seen.set((HttpServletRequest) req));

        var in = seen.get().getInputStream();
        assertThat(in.readNBytes(16)).hasSize(16);
        assertThatThrownBy(in::read).isInstanceOf(IOException.class);

        MockHttpServletRequest small = new MockHttpServletRequest("POST", "/x") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };
        small.setContent(new byte[16]);
        filter.doFilter(small, new MockHttpServletResponse(), (req, res) -> seen.set((HttpServletRequest) req));
        assertThat(seen.get().getInputStream().readAllBytes()).hasSize(16);
        assertThat(seen.get().getReader()).isNotNull();
    }

    @Test
    void aNonPositiveCapIsRefused() {
        assertThatThrownBy(() -> new RequestSizeLimitFilter("0B")).isInstanceOf(IllegalArgumentException.class);
    }
}
