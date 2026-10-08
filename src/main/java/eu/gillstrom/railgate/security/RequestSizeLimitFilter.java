package eu.gillstrom.railgate.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Rejects HTTP requests whose body exceeds
 * {@code railgate.limits.max-http-request-size}.
 *
 * <p>Spring Boot bounds headers ({@code server.max-http-request-header-size}),
 * multipart and form-encoded bodies, but not a JSON body, which is every
 * request railgate accepts. The same filter as gatekeeper's: a declared
 * {@code Content-Length} above the cap is answered with 413 before a body
 * byte is read; a chunked body is counted while it is read and the read
 * fails once the cap is passed (the status is then whatever the container
 * makes of the {@link IOException}; the guarantee is the memory bound).</p>
 *
 * <p>The default of 16 KB is set against {@code SettlementRequest}: a
 * transaction reference of at most 36 characters, an instrument code of 35,
 * a certificate serial of 128, two BICs and two booleans fit in well under
 * 1 KB.</p>
 */
@Component
public class RequestSizeLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestSizeLimitFilter.class);

    private final long maxBytes;

    public RequestSizeLimitFilter(
            @Value("${railgate.limits.max-http-request-size:16KB}") String maxRequestSize) {
        // Parsed here rather than bound as a DataSize so the property works
        // identically whether or not the ApplicationConversionService is in
        // play (it is not, for example, in a standalone filter unit test).
        this.maxBytes = DataSize.parse(maxRequestSize).toBytes();
        if (this.maxBytes <= 0) {
            throw new IllegalArgumentException(
                    "railgate.limits.max-http-request-size must be positive, got " + maxRequestSize);
        }
        log.info("RequestSizeLimitFilter initialised: request bodies capped at {} bytes ({})",
                this.maxBytes, maxRequestSize);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        long declared = request.getContentLengthLong();

        if (declared > maxBytes) {
            log.warn("Rejecting request to {} : declared Content-Length {} exceeds cap {}",
                    request.getRequestURI(), declared, maxBytes);
            response.setStatus(HttpStatus.CONTENT_TOO_LARGE.value());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"error\":\"request_too_large\","
                  + "\"message\":\"Request body exceeds the configured maximum.\","
                  + "\"maxBytes\":" + maxBytes + "}");
            return;
        }

        if (declared >= 0) {
            // Length declared and within the cap; nothing to police.
            filterChain.doFilter(request, response);
            return;
        }

        // Undeclared length (chunked transfer encoding). Count as we read.
        filterChain.doFilter(new LimitedBodyRequest(request, maxBytes), response);
    }

    /** Raised when a chunked body passes the cap mid-read. */
    static class RequestBodyTooLargeException extends IOException {
        RequestBodyTooLargeException(long maxBytes) {
            super("Request body exceeded the configured maximum of " + maxBytes + " bytes");
        }
    }

    /**
     * Request wrapper whose body stream aborts once {@code maxBytes} have
     * been read. Only installed for requests with no {@code Content-Length}.
     */
    private static final class LimitedBodyRequest extends HttpServletRequestWrapper {

        private final long maxBytes;
        private ServletInputStream stream;
        private BufferedReader reader;

        LimitedBodyRequest(HttpServletRequest request, long maxBytes) {
            super(request);
            this.maxBytes = maxBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new CountingServletInputStream(super.getInputStream(), maxBytes);
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (reader == null) {
                String encoding = getCharacterEncoding();
                Charset charset = encoding == null
                        ? StandardCharsets.UTF_8
                        : Charset.forName(encoding);
                reader = new BufferedReader(new InputStreamReader(getInputStream(), charset));
            }
            return reader;
        }
    }

    /**
     * {@link ServletInputStream} that throws once more than {@code maxBytes}
     * have been read from the delegate.
     */
    private static final class CountingServletInputStream extends ServletInputStream {

        private final ServletInputStream delegate;
        private final long maxBytes;
        private long read;

        CountingServletInputStream(ServletInputStream delegate, long maxBytes) {
            this.delegate = delegate;
            this.maxBytes = maxBytes;
        }

        private void account(long n) throws IOException {
            read += Math.max(n, 0); // -1 is end of stream
            if (read > maxBytes) {
                log.warn("Aborting chunked request: body passed the {}-byte cap", maxBytes);
                throw new RequestBodyTooLargeException(maxBytes);
            }
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();
            if (b != -1) {
                account(1);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = delegate.read(b, off, len);
            account(n);
            return n;
        }

        @Override
        public int available() throws IOException {
            return delegate.available();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            delegate.setReadListener(readListener);
        }
    }
}
