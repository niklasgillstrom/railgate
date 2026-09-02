package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

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
 * <p>Connection failures and non-2xx responses translate to a
 * {@link VerificationResult} with {@code reason = "NETWORK_ERROR"} so that
 * the orchestrator can apply default-deny without conflating crypto failure
 * with infrastructure failure.
 *
 * <p><b>What this client does not do.</b> The gatekeeper's response is
 * consumed as plain JSON over the transport. railgate does not verify a
 * signature over that response, so the integrity of the verdict rests on the
 * transport (TLS, and mTLS where the deployer configures it) and on the
 * gatekeeper's own controls — not on anything this class checks. See
 * {@code THREAT_MODEL.md} (Spoofing, Tampering).
 */
@Component
@Slf4j
public class GatekeeperClient {

    /** SHA-512 in hex: 64 bytes, 128 hex characters, nothing else. */
    private static final Pattern SHA512_HEX = Pattern.compile("^[0-9a-fA-F]{128}$");

    private final RestTemplate restTemplate;

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
     * {@code NETWORK_ERROR} deny the design already describes.</p>
     *
     * <p>The base URL is a constructor argument rather than an injected field
     * because the scheme check below has to run at start-up. A field would be
     * populated after construction, so an {@code http://} URL would only be
     * discovered on the first settlement — which is the wrong time to find
     * out that verification traffic is unencrypted.</p>
     *
     * @throws IllegalStateException when the base URL is not {@code https://}
     *     and {@code railgate.gatekeeper.allow-insecure-http} has not been
     *     set to {@code true}
     */
    @Autowired
    public GatekeeperClient(
            @Value("${railgate.gatekeeper.base-url:https://localhost:8443}") String gatekeeperBaseUrl,
            @Value("${railgate.gatekeeper.connect-timeout:PT2S}") Duration connectTimeout,
            @Value("${railgate.gatekeeper.read-timeout:PT5S}") Duration readTimeout,
            @Value("${railgate.gatekeeper.allow-insecure-http:false}") boolean allowInsecureHttp) {

        String baseUrl = gatekeeperBaseUrl == null ? "" : gatekeeperBaseUrl.trim();

        if (!baseUrl.toLowerCase(java.util.Locale.ROOT).startsWith("https://")) {
            if (!allowInsecureHttp) {
                throw new IllegalStateException(
                        "railgate.gatekeeper.base-url must use https:// (configured value: '"
                        + baseUrl + "'). The digest, signature and certificate identifiers "
                        + "railgate forwards to the gatekeeper, and the verdict it receives "
                        + "back, are unauthenticated over plain HTTP: an intermediary can "
                        + "read them and can rewrite signatureValid/compliant to true. "
                        + "Set railgate.gatekeeper.allow-insecure-http=true to override this "
                        + "for a local development run only.");
            }
            log.warn("railgate.gatekeeper.base-url is '{}' and "
                    + "railgate.gatekeeper.allow-insecure-http=true. Gatekeeper traffic is "
                    + "unencrypted and the verification verdict is not integrity-protected. "
                    + "This configuration MUST NOT be deployed.", baseUrl);
        }

        this.gatekeeperBaseUrl = baseUrl;

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectTimeout);
        factory.setReadTimeout(readTimeout);
        this.restTemplate = new RestTemplate(factory);
    }

    /** For tests: inject a RestTemplate that MockRestServiceServer is bound to. */
    GatekeeperClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
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

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, String> body = new HashMap<>();
        body.put("certSerial", signature.getCertSerial());
        body.put("issuerDn", signature.getIssuerDn());
        body.put("digestHex", signature.getDigestHex());
        body.put("signatureBase64", signature.getSignatureBase64());

        try {
            ResponseEntity<VerificationResult> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    new HttpEntity<>(body, headers),
                    VerificationResult.class
            );

            VerificationResult result = response.getBody();
            if (result == null) {
                log.warn("Gatekeeper returned empty body for cert {}", signature.getCertSerial());
                return VerificationResult.builder()
                        .signatureValid(false)
                        .compliant(false)
                        .reason("NETWORK_ERROR")
                        .build();
            }
            return result;

        } catch (RestClientException ex) {
            log.warn("Gatekeeper unreachable for cert {}: {}", signature.getCertSerial(), ex.getMessage());
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
        try {
            Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException ex) {
            return "signatureBase64 is not valid base64";
        }
        if (isBlank(signature.getCertSerial())) {
            return "certSerial is blank";
        }
        if (isBlank(signature.getIssuerDn())) {
            return "issuerDn is blank";
        }
        return null;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
