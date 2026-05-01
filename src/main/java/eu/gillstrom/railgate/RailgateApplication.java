package eu.gillstrom.railgate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the railgate settlement-layer enforcement service.
 *
 * <p>Railgate sits at the central-bank settlement rail (RIX-INST in Sweden,
 * TIPS in the Eurosystem, FedNow in the US, FPS in the UK, NPP in Australia)
 * and performs deterministic cryptographic signature verification at
 * settlement time.
 *
 * <p>For each settlement request identified as a regulated payment, railgate
 * orchestrates retrieval of the SHA-512 digest, signature, and certificate
 * serial number from the payment-network operator, then queries the
 * supervisor's gatekeeper instance for cryptographic verification. Default-deny
 * if any step fails.
 *
 * <p>Companion artefacts:
 * <ul>
 *   <li>hsm — HSM attestation verification reference
 *       (<a href="https://doi.org/10.5281/zenodo.19930310">DOI</a>)</li>
 *   <li>gatekeeper — NCA-operated certificate-issuance gate
 *       (<a href="https://doi.org/10.5281/zenodo.19930395">DOI</a>)</li>
 * </ul>
 */
@SpringBootApplication
public class RailgateApplication {

    public static void main(String[] args) {
        SpringApplication.run(RailgateApplication.class, args);
    }
}
