package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerdictSignatureStatus;
import eu.gillstrom.railgate.model.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Client for invoking the gatekeeper verification endpoint.
 *
 * <p>Sends {@code (certSerial, issuerDn, digestHex, signatureBase64)} to the
 * supervisor's gatekeeper instance via {@code POST /api/v1/verify} and
 * receives a {@link VerificationResult} indicating whether the signature
 * verifies and whether the certificate is compliant.
 *
 * <p>railgate never sends transaction payload content. Only the digest is
 * transmitted; the supervisor never sees transaction content.
 *
 * <p>Connection failures, an answer that is not complete within
 * {@code railgate.gatekeeper.read-timeout}, an answer larger than
 * {@value #MAX_RESPONSE_BYTES} bytes and every status other than 2xx
 * translate to a {@link VerificationResult} with
 * {@code reason = "NETWORK_ERROR"} so that the orchestrator can apply
 * default-deny without conflating crypto failure with infrastructure failure.
 * Until 1.7.0 only 4xx and 5xx statuses did: the body of a 3xx answer was read
 * as a verdict, the answer had no size limit, and the read timeout bounded
 * each read rather than the answer ({@link OutboundHttp}).
 *
 * <p><b>Signed verdicts.</b> Every verdict is passed to a
 * {@link VerdictVerifier}. With {@code railgate.gatekeeper.require-signed-verdict=true}
 * (the default) a verdict is used only if it carries the gatekeeper's
 * {@code sv1} signature, made under a certificate in
 * {@code railgate.gatekeeper.trusted-keys}, over the request railgate sent,
 * with a {@code verifiedAt} within {@code railgate.gatekeeper.verdict-max-skew};
 * otherwise the result is a deny with {@code VERDICT_SIGNATURE_INVALID} or
 * {@code VERDICT_STALE}. With the property {@code false}, a verdict without
 * signature fields is used as before and marked
 * {@link VerdictSignatureStatus#UNSIGNED}; its integrity then rests on the
 * transport alone. With the property {@code false}, a signed verdict is
 * verified when {@code trusted-keys} is configured, and used unchecked as
 * {@link VerdictSignatureStatus#UNVERIFIED} when it is not.
 *
 * <p><b>What this client does not do.</b> A verified signature shows that the
 * holder of a pinned gatekeeper key signed this verdict over the
 * {@code certSerial}, {@code issuerDn} and {@code digestHex} railgate sent,
 * stating a {@code verifiedAt} within the skew window of railgate's clock.
 * {@code sv1} carries no per-call nonce, so it does not bind the verdict to
 * this particular call: a verdict captured for an identical
 * {@code (certSerial, issuerDn, digestHex)} can be presented again within that
 * window. It says nothing about whether the gatekeeper's own decision was
 * right.
 */
@Component
@Slf4j
public class GatekeeperClient {

    /** SHA-512 in hex: 64 bytes, 128 hex characters, nothing else. */
    private static final Pattern SHA512_HEX = Pattern.compile("^[0-9a-fA-F]{128}$");

    private static final int MAX_ISSUER_DN_LENGTH = 512;

    private static final int MAX_SIGNATURE_BASE64_LENGTH = 4096;

    private static final int MAX_LOGGED_ERROR_LENGTH = 512;

    /** Bound on the gatekeeper's answer; a signed verdict is under 4 KB. */
    static final int MAX_RESPONSE_BYTES = 64 * 1024;

    private final RestTemplate restTemplate;

    private final VerdictVerifier verdictVerifier;

    private String gatekeeperBaseUrl;

    /**
     * A settlement rail cannot wait indefinitely for the supervisor, and it
     * must not talk to the supervisor in clear text.
     *
     * <p>The previous {@code new RestTemplate()} used the default request
     * factory with no connect or read timeout, so a gatekeeper that accepted
     * the connection and then stopped responding blocked the calling thread
     * forever. That is not fail-open — the transaction is never allowed — but
     * it is not fail-closed either: the settlement pipeline stalls instead of
     * receiving a deny. Bounded timeouts turn that case into the
     * {@code NETWORK_ERROR} deny the design already describes.
     * {@code connect-timeout} bounds the connect. {@code read-timeout} bounds
     * everything after it, up to the last byte of the answer; until 1.7.0 it
     * bounded each read, so an answer arriving a byte at a time was not
     * bounded at all. Both must be greater than zero.</p>
     *
     * <p>The base URL is a constructor argument rather than an injected field
     * because the scheme check below has to run at start-up. A field would be
     * populated after construction, so an {@code http://} URL would only be
     * discovered on the first settlement — which is the wrong time to find
     * out that verification traffic is unencrypted.</p>
     *
     * <p>When {@code railgate.gatekeeper.ssl-bundle} names a Spring Boot SSL
     * bundle ({@code spring.ssl.bundle.*}), the bundle's key and trust
     * material are used for the gatekeeper connection, which is how the
     * client certificate for mTLS and a private truststore are supplied.
     * Without it the JVM default SSL context applies. The bundle is resolved
     * here, at start-up, for the same reason as the scheme check.</p>
     *
     * <p>{@code railgate.gatekeeper.trusted-keys} (PEM, one or more gatekeeper
     * signing certificates), {@code require-signed-verdict} (default
     * {@code true}) and {@code verdict-max-skew} (default {@code PT60S})
     * configure the {@link VerdictVerifier}. An empty {@code trusted-keys}
     * with a signature required does not stop start-up; it logs a WARN, and
     * every verdict is then rejected with {@code VERDICT_SIGNATURE_INVALID}.</p>
     *
     * @throws IllegalStateException when the base URL is not {@code https://}
     *     and {@code railgate.gatekeeper.allow-insecure-http} has not been
     *     set to {@code true}, when a timeout is not positive, when the
     *     named SSL bundle sets ciphers or enabled protocols, which railgate
     *     does not apply, when {@code railgate.gatekeeper.trusted-keys} is set
     *     but cannot be read or holds no certificate, or when
     *     {@code railgate.gatekeeper.verdict-max-skew} is negative
     * @throws org.springframework.boot.ssl.NoSuchSslBundleException when
     *     {@code railgate.gatekeeper.ssl-bundle} names no configured bundle
     */
    @Autowired
    public GatekeeperClient(
            @Value("${railgate.gatekeeper.base-url:https://localhost:8443}") String gatekeeperBaseUrl,
            @Value("${railgate.gatekeeper.connect-timeout:PT2S}") Duration connectTimeout,
            @Value("${railgate.gatekeeper.read-timeout:PT5S}") Duration readTimeout,
            @Value("${railgate.gatekeeper.allow-insecure-http:false}") boolean allowInsecureHttp,
            @Value("${railgate.gatekeeper.ssl-bundle:}") String sslBundle,
            ObjectProvider<SslBundles> sslBundles,
            @Value("${railgate.gatekeeper.trusted-keys:}") String trustedKeys,
            @Value("${railgate.gatekeeper.require-signed-verdict:true}") boolean requireSignedVerdict,
            @Value("${railgate.gatekeeper.verdict-max-skew:PT60S}") Duration verdictMaxSkew) {
        this(gatekeeperBaseUrl, connectTimeout, readTimeout, allowInsecureHttp, sslBundle,
                sslBundles.getIfAvailable(),
                VerdictVerifier.fromConfiguration(trustedKeys, requireSignedVerdict, verdictMaxSkew,
                        Clock.systemUTC()));
    }

    /**
     * Without verdict-signature enforcement
     * ({@link VerdictVerifier#unsignedAccepted()}): every verdict is used, and
     * marked {@code UNSIGNED} or {@code UNVERIFIED}. The Spring-managed bean is
     * built by the constructor above, from {@code railgate.gatekeeper.*}.
     */
    public GatekeeperClient(
            String gatekeeperBaseUrl,
            Duration connectTimeout,
            Duration readTimeout,
            boolean allowInsecureHttp) {
        this(gatekeeperBaseUrl, connectTimeout, readTimeout, allowInsecureHttp, null, (SslBundles) null);
    }

    GatekeeperClient(
            String gatekeeperBaseUrl,
            Duration connectTimeout,
            Duration readTimeout,
            boolean allowInsecureHttp,
            String sslBundle,
            SslBundles sslBundles) {
        this(gatekeeperBaseUrl, connectTimeout, readTimeout, allowInsecureHttp, sslBundle, sslBundles,
                VerdictVerifier.unsignedAccepted());
    }

    GatekeeperClient(
            String gatekeeperBaseUrl,
            Duration connectTimeout,
            Duration readTimeout,
            boolean allowInsecureHttp,
            String sslBundle,
            SslBundles sslBundles,
            VerdictVerifier verdictVerifier) {
        this.verdictVerifier = java.util.Objects.requireNonNull(verdictVerifier, "verdictVerifier");

        String baseUrl = gatekeeperBaseUrl == null ? "" : gatekeeperBaseUrl.trim();

        if (!baseUrl.toLowerCase(java.util.Locale.ROOT).startsWith("https://")) {
            if (!allowInsecureHttp) {
                throw new IllegalStateException(
                        "railgate.gatekeeper.base-url must use https:// (configured value: '"
                        + baseUrl + "'). The digest, signature and certificate identifiers "
                        + "railgate forwards to the gatekeeper, and the verdict it receives "
                        + "back, are unauthenticated over plain HTTP: an intermediary can "
                        + "read them, and unless a signed verdict is required and verified "
                        + "(railgate.gatekeeper.require-signed-verdict) it can rewrite "
                        + "signatureValid/compliant to true. "
                        + "Set railgate.gatekeeper.allow-insecure-http=true to override this "
                        + "for a local development run only.");
            }
            log.warn("railgate.gatekeeper.base-url is '{}' and "
                    + "railgate.gatekeeper.allow-insecure-http=true. Gatekeeper traffic is "
                    + "unencrypted, and the verdict is integrity-protected only by its signature, "
                    + "when one is verified. This configuration MUST NOT be deployed.", baseUrl);
        }

        this.gatekeeperBaseUrl = baseUrl;

        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(OutboundHttp.client(
                OutboundHttp.positive(connectTimeout, "railgate.gatekeeper.connect-timeout"),
                OutboundHttp.sslContext("railgate.gatekeeper.ssl-bundle", sslBundle, sslBundles)));
        // Spring cancels the exchange, or closes the body it is reading, when
        // this time has passed since the request was sent.
        factory.setReadTimeout(OutboundHttp.positive(readTimeout, "railgate.gatekeeper.read-timeout"));
        this.restTemplate = guarded(new RestTemplate(factory));
    }

    /**
     * Every status other than 2xx is an error whose body is not read, and at
     * most {@value #MAX_RESPONSE_BYTES} bytes of a 2xx body are read.
     * {@code RestTemplate}'s default treats only 4xx and 5xx as errors, so the
     * body of a 3xx answer was deserialised as a verdict.
     */
    private static RestTemplate guarded(RestTemplate restTemplate) {
        restTemplate.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return !response.getStatusCode().is2xxSuccessful();
            }

            @Override
            public void handleError(URI url, HttpMethod method, ClientHttpResponse response) throws IOException {
                throw new RestClientException("the gatekeeper answered HTTP " + response.getStatusCode().value());
            }
        });
        restTemplate.getInterceptors().add((request, body, execution) ->
                new BoundedResponse(execution.execute(request, body)));
        return restTemplate;
    }

    /** The gatekeeper's response with its body bounded. */
    static final class BoundedResponse implements ClientHttpResponse {

        private final ClientHttpResponse response;

        BoundedResponse(ClientHttpResponse response) {
            this.response = response;
        }

        @Override
        public HttpStatusCode getStatusCode() throws IOException {
            return response.getStatusCode();
        }

        @Override
        public String getStatusText() throws IOException {
            return response.getStatusText();
        }

        @Override
        public HttpHeaders getHeaders() {
            return response.getHeaders();
        }

        @Override
        public InputStream getBody() throws IOException {
            return new OutboundHttp.BoundedInputStream(response.getBody(), MAX_RESPONSE_BYTES);
        }

        @Override
        public void close() {
            response.close();
        }
    }

    /**
     * For tests: inject a RestTemplate that MockRestServiceServer is bound to.
     * Verdicts are checked as by {@link VerdictVerifier#unsignedAccepted()}.
     */
    GatekeeperClient(RestTemplate restTemplate) {
        this(restTemplate, VerdictVerifier.unsignedAccepted());
    }

    /** For tests: a RestTemplate and the verdict verifier to apply. */
    GatekeeperClient(RestTemplate restTemplate, VerdictVerifier verdictVerifier) {
        this.restTemplate = guarded(restTemplate);
        this.verdictVerifier = java.util.Objects.requireNonNull(verdictVerifier, "verdictVerifier");
    }

    public VerificationResult verify(PaymentSignature signature) {
        String materialProblem = validateMaterial(signature);
        if (materialProblem != null) {
            // Malformed material never reaches the gatekeeper. Forwarding it
            // would spend a supervisory call on input that cannot verify, and
            // would return SIGNATURE_INVALID — an accusation of a bad
            // signature — for what is a defect in the artefacts the
            // payment-network operator supplied.
            log.warn("Rejecting verification request without calling gatekeeper: {}", materialProblem);
            return VerificationResult.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .reason("INVALID_SIGNATURE_MATERIAL")
                    .build();
        }

        String url = gatekeeperBaseUrl + "/api/v1/verify";

        Map<String, String> body = new HashMap<>();
        body.put("certSerial", signature.getCertSerial());
        body.put("issuerDn", signature.getIssuerDn());
        body.put("digestHex", signature.getDigestHex());
        body.put("signatureBase64", signature.getSignatureBase64());

        try {
            ResponseEntity<VerificationResult> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    new HttpEntity<>(body), // Jackson writes application/json
                    VerificationResult.class
            );

            VerificationResult result = response.getBody();
            if (result == null) {
                log.warn("Gatekeeper returned empty body for cert {}",
                        RailgateAuditLog.sanitise(signature.getCertSerial(), Integer.MAX_VALUE));
                return VerificationResult.builder()
                        .signatureValid(false)
                        .compliant(false)
                        .reason("NETWORK_ERROR")
                        .build();
            }
            VerdictVerifier.Check check = verdictVerifier.check(signature, result);
            if (check.status() == VerdictSignatureStatus.INVALID) {
                // Nothing from a rejected verdict is carried forward: its
                // flags, reason and audit references are all unauthenticated.
                log.warn("Rejecting gatekeeper verdict for cert {}: {} ({})",
                        RailgateAuditLog.sanitise(signature.getCertSerial(), Integer.MAX_VALUE),
                        check.reasonCode(), check.detail());
                return VerificationResult.builder()
                        .signatureValid(false)
                        .compliant(false)
                        .reason(check.reasonCode())
                        .verdictSignature(VerdictSignatureStatus.INVALID)
                        .build();
            }
            result.setVerdictSignature(check.status());
            return result;

        } catch (RestClientException ex) {
            log.warn("Gatekeeper unreachable for cert {}: {}",
                    RailgateAuditLog.sanitise(signature.getCertSerial(), Integer.MAX_VALUE),
                    RailgateAuditLog.sanitise(ex.getMessage(), MAX_LOGGED_ERROR_LENGTH));
            return VerificationResult.builder()
                    .signatureValid(false)
                    .compliant(false)
                    .reason("NETWORK_ERROR")
                    .build();
        }
    }

    /**
     * Structural check of the cryptographic material before it is forwarded.
     *
     * <p>Returns a description of the first problem found, or {@code null}
     * when the material is well formed. The description names the field, not
     * its value: the values are supplied by an upstream system and go into
     * the operator's log.</p>
     */
    private static String validateMaterial(PaymentSignature signature) {
        if (signature == null) {
            return "no signature artefacts supplied";
        }
        String digestHex = signature.getDigestHex();
        if (digestHex == null || !SHA512_HEX.matcher(digestHex).matches()) {
            return "digestHex is not 128 hexadecimal characters (SHA-512)";
        }
        String signatureBase64 = signature.getSignatureBase64();
        if (signatureBase64 == null || signatureBase64.isBlank()) {
            return "signatureBase64 is blank";
        }
        if (signatureBase64.length() > MAX_SIGNATURE_BASE64_LENGTH) {
            return "signatureBase64 exceeds " + MAX_SIGNATURE_BASE64_LENGTH + " characters";
        }
        try {
            Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException ex) {
            return "signatureBase64 is not valid base64";
        }
        String certSerial = signature.getCertSerial();
        if (isBlank(certSerial)) {
            return "certSerial is blank";
        }
        if (PaymentSignature.parseCertSerial(certSerial) == null) {
            return "certSerial is not a hexadecimal serial of at most "
                    + PaymentSignature.MAX_CERT_SERIAL_LENGTH + " characters";
        }
        String issuerDn = signature.getIssuerDn();
        if (isBlank(issuerDn)) {
            return "issuerDn is blank";
        }
        if (issuerDn.length() > MAX_ISSUER_DN_LENGTH) {
            return "issuerDn exceeds " + MAX_ISSUER_DN_LENGTH + " characters";
        }
        try {
            new X500Principal(issuerDn);
        } catch (IllegalArgumentException ex) {
            return "issuerDn is not an RFC 4514 distinguished name";
        }
        return null;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
