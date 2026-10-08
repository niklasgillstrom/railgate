package eu.gillstrom.railgate.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.web.server.Ssl;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Refuses to start railgate on a plain-HTTP listener.
 *
 * <p>{@code /api/v1/**} is authenticated with HTTP Basic, and its responses
 * are the settlement verdicts. Over plain HTTP the credentials can be read
 * and the verdicts rewritten by anyone on the path, which is the same
 * exposure {@code railgate.gatekeeper.allow-insecure-http} already refuses
 * for the gatekeeper connection. railgate therefore requires TLS on its own
 * listener: {@code server.ssl} with a bundle, a key store or a certificate.
 * A reverse proxy that terminates TLS in front of railgate does not count:
 * the hop from it to railgate would still carry the credentials in clear.</p>
 *
 * <p>{@code railgate.server.allow-insecure-http=true} lets a local
 * development run start without TLS and logs a WARN; the {@code dev}
 * profile sets it. Never set it in a deployed configuration.</p>
 */
@Component
public class ListenerTlsGuard {

    private static final Logger log = LoggerFactory.getLogger(ListenerTlsGuard.class);

    public ListenerTlsGuard(Environment environment,
            @Value("${railgate.server.allow-insecure-http:false}") boolean allowInsecureHttp) {
        Ssl ssl = Binder.get(environment).bind("server.ssl", Ssl.class).orElse(null);
        if (Ssl.isEnabled(ssl) && hasKeyMaterial(ssl)) {
            return;
        }
        if (!allowInsecureHttp) {
            throw new IllegalStateException("railgate's listener has no TLS. Configure server.ssl "
                    + "(server.ssl.bundle, server.ssl.key-store or server.ssl.certificate): the "
                    + "HTTP Basic credentials of /api/v1/** and the settlement verdicts are "
                    + "readable and rewritable over plain HTTP. Set "
                    + "railgate.server.allow-insecure-http=true for a local development run only.");
        }
        log.warn("railgate's listener has no TLS and railgate.server.allow-insecure-http=true. "
                + "Credentials and settlement verdicts travel in clear. This configuration MUST "
                + "NOT be deployed.");
    }

    private static boolean hasKeyMaterial(Ssl ssl) {
        return notBlank(ssl.getBundle()) || notBlank(ssl.getKeyStore()) || notBlank(ssl.getCertificate());
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
