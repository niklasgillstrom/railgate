package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.signing.OperatorArtefactsCanonicalizer;
import eu.gillstrom.railgate.signing.SignedStatementVerifier;
import eu.gillstrom.railgate.signing.TrustedCertificates;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/**
 * {@link PaymentNetworkClient} for a payment-network operator that offers the
 * interface specified in {@code api/payment-network-operator.openapi.yaml}:
 * {@code GET {base-url}/v1/payout-artefacts/{transactionReference}} over mTLS,
 * answering 200 with signed {@code PayoutArtefacts} or 404. Selected with
 * {@code railgate.payment-network.mode=http}.
 *
 * <p><b>What is accepted.</b> A 200 answer is used only if all of the
 * following hold; otherwise the lookup is
 * {@link PaymentNetworkLookup.OperatorSignatureInvalid} and the settlement is
 * denied with {@code OPERATOR_SIGNATURE_INVALID}:</p>
 * <ol>
 *   <li>the body is at most {@value #MAX_RESPONSE_BYTES} bytes of JSON, an
 *       object without duplicate keys, in which all ten {@code PayoutArtefacts}
 *       properties are JSON strings, {@code payoutInstructionId} is 1–64
 *       printable ASCII characters without spaces, {@code certSerial} is
 *       hexadecimal and {@code issuerDn} is a distinguished name (so that the
 *       canonical form can be built);</li>
 *   <li>{@code transactionReference} equals the reference requested,
 *       character for character;</li>
 *   <li>{@code operatorKeyFingerprintHex} equals the key fingerprint
 *       ({@link TrustedCertificates#fingerprintHex}: SHA-256 of the DER
 *       SubjectPublicKeyInfo, lowercase hex, the gatekeeper's {@code /keys}
 *       convention) of a certificate in
 *       {@code railgate.payment-network.trusted-keys};</li>
 *   <li>{@code operatorSignatureAlgorithm} is on
 *       {@link SignedStatementVerifier#ALLOWED_ALGORITHMS};</li>
 *   <li>{@code operatorSignatureBase64} verifies under that certificate's
 *       public key over the {@code op1} canonical bytes
 *       ({@link OperatorArtefactsCanonicalizer}).</li>
 * </ol>
 *
 * <p><b>What else happens.</b> 404 is {@link PaymentNetworkLookup.NotFound}
 * ({@code DORA_32_AUDIT_MISSING}). Any other status, a redirect, a connect
 * timeout, an answer that is not complete within
 * {@code railgate.payment-network.read-timeout}, a TLS failure or any other
 * I/O error is {@link PaymentNetworkLookup.Unavailable}
 * ({@code NETWORK_ERROR}). Nothing in the 404 or error bodies is read for
 * meaning. The references {@code .} and {@code ..} are never requested: as a
 * path segment each names a directory, which a server or proxy resolves away,
 * so the request would reach another path than the one asked for. They are
 * answered {@link PaymentNetworkLookup.NotFound} without a call.</p>
 *
 * <p><b>Transport.</b> {@code railgate.payment-network.base-url} must be
 * {@code https://} unless {@code railgate.payment-network.allow-insecure-http}
 * is {@code true}, which logs a WARN at start-up. The client certificate for
 * mTLS and the truststore come from the Spring Boot SSL bundle named by
 * {@code railgate.payment-network.ssl-bundle}, or from the JVM defaults when it
 * is empty. As for {@code GatekeeperClient}, the connection is the JDK's
 * {@code HttpClient} ({@link OutboundHttp}): HTTP/1.1, no redirect followed, a
 * bundle that sets ciphers or protocols refused at start-up, and hostname
 * verification the JDK default. {@code connect-timeout} bounds the connect and
 * {@code read-timeout} the whole exchange, from the request to the last byte
 * of the answer; until 1.7.0 it bounded each read.</p>
 *
 * <p><b>What this does not establish.</b> A verified answer proves that a
 * holder of a pinned operator key produced it. It does not show that the
 * artefacts are those the originating bank submitted, nor that the operator
 * holds no other artefacts for the reference.</p>
 */
@Component
@ConditionalOnProperty(prefix = "railgate.payment-network", name = "mode", havingValue = "http")
public class HttpPaymentNetworkClient implements PaymentNetworkClient {

    private static final Logger log = LoggerFactory.getLogger(HttpPaymentNetworkClient.class);

    /** Path of the artefact resource, relative to the base URL. */
    public static final String PATH = "/v1/payout-artefacts/";

    /** Bound on the operator's 200 body; a {@code PayoutArtefacts} object is well under 8 KB. */
    static final int MAX_RESPONSE_BYTES = 64 * 1024;

    /** {@code payoutInstructionId}: 1–64 printable ASCII characters, no space. */
    static final Pattern PAYOUT_INSTRUCTION_ID = Pattern.compile("^[!-~]{1,64}$");

    private static final int MAX_LOGGED_DETAIL_LENGTH = 256;

    private static final int MAX_LOGGED_REFERENCE_LENGTH = 128;

    private final String baseUrl;
    private final Duration readTimeout;
    private final HttpClient http;
    private final TrustedCertificates trustedOperatorCertificates;
    private final JsonMapper json = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();

    @Autowired
    public HttpPaymentNetworkClient(
            @Value("${railgate.payment-network.base-url:}") String baseUrl,
            @Value("${railgate.payment-network.allow-insecure-http:false}") boolean allowInsecureHttp,
            @Value("${railgate.payment-network.ssl-bundle:}") String sslBundle,
            @Value("${railgate.payment-network.connect-timeout:PT2S}") Duration connectTimeout,
            @Value("${railgate.payment-network.read-timeout:PT5S}") Duration readTimeout,
            @Value("${railgate.payment-network.trusted-keys:}") String trustedKeys,
            ObjectProvider<SslBundles> sslBundles) {
        this(baseUrl, allowInsecureHttp, sslBundle, sslBundles.getIfAvailable(), connectTimeout, readTimeout,
                loadTrustedKeys(trustedKeys));
    }

    HttpPaymentNetworkClient(
            String baseUrl,
            boolean allowInsecureHttp,
            String sslBundle,
            SslBundles sslBundles,
            Duration connectTimeout,
            Duration readTimeout,
            TrustedCertificates trustedOperatorCertificates) {
        String url = baseUrl == null ? "" : baseUrl.trim();
        if (url.isEmpty()) {
            throw new IllegalStateException("railgate.payment-network.mode=http requires "
                    + "railgate.payment-network.base-url");
        }
        String lower = url.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("https://")) {
            if (!allowInsecureHttp) {
                throw new IllegalStateException(
                        "railgate.payment-network.base-url must use https:// (configured value: '"
                        + url + "'). Over plain HTTP the operator's answer and the transaction "
                        + "reference are readable by any intermediary, and the operator cannot "
                        + "authenticate railgate. Set railgate.payment-network.allow-insecure-http=true "
                        + "to override this for a local development run only.");
            }
            if (!lower.startsWith("http://")) {
                throw new IllegalStateException("railgate.payment-network.base-url must be an "
                        + "http:// or https:// URL (configured value: '" + url + "')");
            }
            log.warn("railgate.payment-network.base-url is '{}' and "
                    + "railgate.payment-network.allow-insecure-http=true. Payment-network operator "
                    + "traffic is unencrypted and the operator cannot authenticate railgate. "
                    + "This configuration MUST NOT be deployed.", url);
        }
        this.baseUrl = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        this.readTimeout = OutboundHttp.positive(readTimeout, "railgate.payment-network.read-timeout");
        this.http = OutboundHttp.client(
                OutboundHttp.positive(connectTimeout, "railgate.payment-network.connect-timeout"),
                OutboundHttp.sslContext("railgate.payment-network.ssl-bundle", sslBundle, sslBundles));
        if (trustedOperatorCertificates == null || trustedOperatorCertificates.isEmpty()) {
            throw new IllegalStateException("railgate.payment-network.mode=http requires at least one "
                    + "trusted operator certificate in railgate.payment-network.trusted-keys");
        }
        this.trustedOperatorCertificates = trustedOperatorCertificates;
        log.info("HttpPaymentNetworkClient active against {}; trusted operator key fingerprints: {}",
                this.baseUrl, trustedOperatorCertificates.fingerprints());
    }

    private static TrustedCertificates loadTrustedKeys(String location) {
        if (location == null || location.isBlank()) {
            throw new IllegalStateException("railgate.payment-network.mode=http requires "
                    + "railgate.payment-network.trusted-keys: a PEM file with the operator's "
                    + "signing certificate(s). Without it no operator answer can be authenticated.");
        }
        return TrustedCertificates.load(location, "railgate.payment-network.trusted-keys");
    }

    @Override
    public Optional<PaymentSignature> getSignature(String transactionReference) {
        return lookup(transactionReference) instanceof PaymentNetworkLookup.Found found
                ? Optional.of(found.signature())
                : Optional.empty();
    }

    @Override
    public PaymentNetworkLookup lookup(String transactionReference) {
        if (transactionReference == null || transactionReference.isBlank()) {
            return new PaymentNetworkLookup.NotFound();
        }
        if (transactionReference.equals(".") || transactionReference.equals("..")) {
            log.warn("Payment-network operator not asked for ref={}: as a path segment it names a "
                    + "directory, not a payout", transactionReference);
            return new PaymentNetworkLookup.NotFound();
        }
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(URI.create(baseUrl + PATH + encodePathSegment(transactionReference)))
                    .header("Accept", "application/json")
                    .GET()
                    .build();
        } catch (IllegalArgumentException e) {
            // A base URL that is not a valid URI, or not one the client can call.
            return unavailable(transactionReference, describe(e));
        }
        CompletableFuture<HttpResponse<byte[]>> pending = send(request);
        HttpResponse<byte[]> response;
        try {
            response = pending.get(readTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            pending.cancel(true);
            return unavailable(transactionReference, "no complete answer within " + readTimeout);
        } catch (InterruptedException e) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            return unavailable(transactionReference, "interrupted while waiting for the operator");
        } catch (ExecutionException e) {
            return unavailable(transactionReference, describe(e.getCause()));
        }
        int status = response.statusCode();
        if (status == 404) {
            return new PaymentNetworkLookup.NotFound();
        }
        if (status != 200) {
            return unavailable(transactionReference, "operator answered HTTP " + status);
        }
        byte[] body = response.body();
        if (body == null) {
            return invalid(transactionReference, "response body exceeds " + MAX_RESPONSE_BYTES + " bytes");
        }
        return verify(transactionReference, body);
    }

    /**
     * Sends one request. The future completes when the whole answer has
     * arrived, with a {@code null} body if it is longer than
     * {@value #MAX_RESPONSE_BYTES} bytes, and cancelling it abandons the
     * exchange. Package-private so tests can supply the answer.
     */
    CompletableFuture<HttpResponse<byte[]>> send(HttpRequest request) {
        return http.sendAsync(request, info -> new OutboundHttp.LimitedBody(MAX_RESPONSE_BYTES));
    }

    /** The client the requests are sent with. Package-private for tests. */
    HttpClient http() {
        return http;
    }

    private static String describe(Throwable failure) {
        return failure.getClass().getSimpleName()
                + (failure.getMessage() == null ? "" : ": " + failure.getMessage());
    }

    /** Parses and authenticates a 200 body. Package-private for tests. */
    PaymentNetworkLookup verify(String requestedReference, byte[] body) {
        JsonNode root;
        try {
            root = json.readTree(body);
        } catch (JacksonException e) {
            return invalid(requestedReference, "response body is not JSON");
        }
        if (root == null || !root.isObject()) {
            return invalid(requestedReference, "response body is not a JSON object");
        }
        String transactionReference = string(root, "transactionReference");
        String payoutInstructionId = string(root, "payoutInstructionId");
        String certSerial = string(root, "certSerial");
        String issuerDn = string(root, "issuerDn");
        String digestHex = string(root, "digestHex");
        String signatureBase64 = string(root, "signatureBase64");
        String issuedAt = string(root, "issuedAt");
        String operatorSignatureBase64 = string(root, "operatorSignatureBase64");
        String operatorSignatureAlgorithm = string(root, "operatorSignatureAlgorithm");
        String operatorKeyFingerprintHex = string(root, "operatorKeyFingerprintHex");
        if (transactionReference == null || payoutInstructionId == null || certSerial == null
                || issuerDn == null || digestHex == null || signatureBase64 == null || issuedAt == null
                || operatorSignatureBase64 == null || operatorSignatureAlgorithm == null
                || operatorKeyFingerprintHex == null) {
            return invalid(requestedReference, "a required PayoutArtefacts property is missing or not a string");
        }
        if (!transactionReference.equals(requestedReference)) {
            return invalid(requestedReference, "the echoed transactionReference is not the one requested");
        }
        if (!PAYOUT_INSTRUCTION_ID.matcher(payoutInstructionId).matches()) {
            return invalid(requestedReference, "payoutInstructionId is not 1-64 printable ASCII characters");
        }
        byte[] canonical;
        try {
            canonical = OperatorArtefactsCanonicalizer.canonicalBytes(transactionReference,
                    payoutInstructionId, certSerial, issuerDn, digestHex, signatureBase64, issuedAt);
        } catch (IllegalArgumentException e) {
            return invalid(requestedReference, "certSerial or issuerDn cannot be canonicalised");
        }
        SignedStatementVerifier.Outcome outcome = SignedStatementVerifier.verify(trustedOperatorCertificates,
                operatorKeyFingerprintHex, operatorSignatureAlgorithm, operatorSignatureBase64, canonical);
        if (outcome != SignedStatementVerifier.Outcome.VALID) {
            return invalid(requestedReference, "operator signature rejected: " + outcome.describe());
        }
        return new PaymentNetworkLookup.Found(PaymentSignature.builder()
                .certSerial(certSerial)
                .issuerDn(issuerDn)
                .digestHex(digestHex)
                .signatureBase64(signatureBase64)
                .payoutInstructionId(payoutInstructionId)
                .build());
    }

    /**
     * Percent-encodes every UTF-8 octet except the RFC 3986 unreserved
     * characters ({@code A-Z a-z 0-9 - . _ ~}), as {@code %XX} with uppercase
     * hex. Stricter than a path segment requires, so that {@code ;}, {@code +}
     * and the other sub-delimiters cannot be read as matrix parameters or
     * spaces by the operator's server.
     */
    static String encodePathSegment(String value) {
        StringBuilder out = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~') {
                out.append((char) c);
            } else {
                out.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
            }
        }
        return out.toString();
    }

    private static String string(JsonNode root, String property) {
        JsonNode node = root.get(property);
        return node != null && node.isString() ? node.stringValue() : null;
    }

    private static PaymentNetworkLookup unavailable(String reference, String detail) {
        String safe = RailgateAuditLog.sanitise(detail, MAX_LOGGED_DETAIL_LENGTH);
        log.warn("Payment-network operator unavailable for ref={}: {}",
                RailgateAuditLog.sanitise(reference, MAX_LOGGED_REFERENCE_LENGTH), safe);
        return new PaymentNetworkLookup.Unavailable(safe);
    }

    private static PaymentNetworkLookup invalid(String reference, String detail) {
        log.warn("Payment-network operator answer rejected for ref={}: {}",
                RailgateAuditLog.sanitise(reference, MAX_LOGGED_REFERENCE_LENGTH), detail);
        return new PaymentNetworkLookup.OperatorSignatureInvalid(detail);
    }
}
