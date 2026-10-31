package eu.gillstrom.railgate.testsupport;

import eu.gillstrom.railgate.signing.TrustedCertificates;
import eu.gillstrom.railgate.signing.VerdictCanonicalizer;
import tools.jackson.databind.json.JsonMapper;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds a gatekeeper {@code POST /api/v1/verify} response body signed per
 * {@code sv1}, as the gatekeeper is specified to. Every value can be changed
 * before or after signing to model a tampered or foreign verdict.
 */
public final class VerdictSigner {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    public PrivateKey key = TestKeys.privateKey(TestKeys.GATEKEEPER_KEY);
    public X509Certificate certificate = TestKeys.certificate(TestKeys.GATEKEEPER_CERT);
    public String algorithm = "SHA256withECDSA";

    public String verifiedAt = Instant.parse("2026-10-30T12:00:00Z").toString();
    /** The request values the gatekeeper signs over (what it received). */
    public String certSerial;
    public String issuerDn;
    public String digestHex;
    public boolean signatureValid = true;
    public boolean compliant = true;
    public String reason = "OK";
    public String auditEntryId = "AE-SIGNED";
    public String auditEntryHashHex = "ab".repeat(32);

    public VerdictSigner(String certSerial, String issuerDn, String digestHex) {
        this.certSerial = certSerial;
        this.issuerDn = issuerDn;
        this.digestHex = digestHex;
    }

    /** The response properties, signed over the current values. */
    public Map<String, Object> body() {
        byte[] canonical = VerdictCanonicalizer.canonicalBytes(verifiedAt, certSerial, issuerDn, digestHex,
                signatureValid, compliant, reason, auditEntryId, auditEntryHashHex);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("signatureValid", signatureValid);
        body.put("compliant", compliant);
        body.put("auditEntryId", auditEntryId);
        body.put("reason", reason);
        body.put("auditEntryHashHex", auditEntryHashHex);
        body.put("verifiedAt", verifiedAt);
        body.put("verdictSignatureBase64", TestKeys.signBase64(algorithm, key, canonical));
        body.put("verdictSignatureAlgorithm", algorithm);
        body.put("signingKeyFingerprintHex", TrustedCertificates.fingerprintHex(certificate));
        return body;
    }

    public static String json(Map<String, Object> body) {
        return JSON.writeValueAsString(body);
    }

    public String json() {
        return json(body());
    }
}
