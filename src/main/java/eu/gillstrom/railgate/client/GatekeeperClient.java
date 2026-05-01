package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

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
 */
@Component
@Slf4j
public class GatekeeperClient {

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${railgate.gatekeeper.base-url:http://localhost:8080}")
    private String gatekeeperBaseUrl;

    public VerificationResult verify(PaymentSignature signature) {
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
}
