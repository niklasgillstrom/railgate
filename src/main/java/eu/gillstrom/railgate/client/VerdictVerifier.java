package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerdictSignatureStatus;
import eu.gillstrom.railgate.model.VerificationResult;
import eu.gillstrom.railgate.signing.CanonicalFields;
import eu.gillstrom.railgate.signing.SignedStatementVerifier;
import eu.gillstrom.railgate.signing.TrustedCertificates;
import eu.gillstrom.railgate.signing.VerdictCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Objects;

/**
 * Checks the gatekeeper's signature over its {@code POST /api/v1/verify}
 * verdict ({@code sv1}, {@link VerdictCanonicalizer}).
 *
 * <p>When the verdict carries none of {@code verifiedAt},
 * {@code verdictSignatureBase64}, {@code verdictSignatureAlgorithm} and
 * {@code signingKeyFingerprintHex}, it is rejected if a signature is required
 * and accepted as {@link VerdictSignatureStatus#UNSIGNED} otherwise. When it
 * carries any of them while no signature is required and no key is trusted,
 * there is nothing to check it with: it is accepted as
 * {@link VerdictSignatureStatus#UNVERIFIED}. Otherwise — a signature required,
 * or at least one trusted key configured — it is verified in this order, and
 * the first failure decides:</p>
 * <ol>
 *   <li>all four fields are present and non-blank;</li>
 *   <li>{@code signingKeyFingerprintHex} selects a certificate in
 *       {@code railgate.gatekeeper.trusted-keys};</li>
 *   <li>{@code verdictSignatureAlgorithm} is on
 *       {@link SignedStatementVerifier#ALLOWED_ALGORITHMS};</li>
 *   <li>the signature verifies over the {@code sv1} bytes built from
 *       {@code verifiedAt} as received, the {@code certSerial},
 *       {@code issuerDn} and {@code digestHex} railgate <em>sent</em>, and the
 *       verdict's {@code signatureValid}, {@code compliant}, {@code reason},
 *       {@code auditEntryId} and {@code auditEntryHashHex};</li>
 *   <li>each request field the gatekeeper echoes ({@code certSerial},
 *       {@code issuerDn}, {@code digestHex}; each optional) equals what railgate
 *       sent after {@link CanonicalFields} normalisation;</li>
 *   <li>{@code verifiedAt} parses as an ISO-8601 instant;</li>
 *   <li>{@code verifiedAt} is no further than {@code maxSkew} from this
 *       verifier's clock, in either direction.</li>
 * </ol>
 *
 * <p>Steps 1–6 failing is {@code VERDICT_SIGNATURE_INVALID}; step 7 is
 * {@code VERDICT_STALE}. Because the canonical bytes are built from what
 * railgate sent, a verdict the gatekeeper signed for a different serial,
 * issuer or digest does not verify even when it echoes nothing.</p>
 */
public final class VerdictVerifier {

    private static final Logger log = LoggerFactory.getLogger(VerdictVerifier.class);

    public static final String VERDICT_SIGNATURE_INVALID = "VERDICT_SIGNATURE_INVALID";
    public static final String VERDICT_STALE = "VERDICT_STALE";

    /** Default {@code railgate.gatekeeper.verdict-max-skew}. */
    public static final Duration DEFAULT_MAX_SKEW = Duration.ofSeconds(60);

    /**
     * Result of one check.
     *
     * @param status     what was established about the signature
     * @param reasonCode {@code null} unless {@code status} is
     *                   {@link VerdictSignatureStatus#INVALID}
     * @param detail     a description for the operator's log; carries no
     *                   values from the verdict
     */
    public record Check(VerdictSignatureStatus status, String reasonCode, String detail) {
    }

    private final TrustedCertificates trusted;
    private final boolean requireSigned;
    private final Duration maxSkew;
    private final Clock clock;

    public VerdictVerifier(TrustedCertificates trusted, boolean requireSigned, Duration maxSkew, Clock clock) {
        this.trusted = Objects.requireNonNull(trusted, "trusted");
        this.requireSigned = requireSigned;
        if (maxSkew == null || maxSkew.isNegative()) {
            throw new IllegalStateException("railgate.gatekeeper.verdict-max-skew must not be negative");
        }
        this.maxSkew = maxSkew;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The behaviour of railgate before signed verdicts: every verdict is
     * accepted, as {@code UNSIGNED} or (when it carries signature fields)
     * {@code UNVERIFIED}. Used by the {@code GatekeeperClient} constructors
     * that predate this class.
     */
    public static VerdictVerifier unsignedAccepted() {
        return new VerdictVerifier(TrustedCertificates.none(), false, DEFAULT_MAX_SKEW, Clock.systemUTC());
    }

    /**
     * Builds the verifier from the {@code railgate.gatekeeper.*} properties.
     *
     * @throws IllegalStateException when {@code trustedKeys} names a location
     *     that cannot be read or holds no certificate, or the skew is negative
     */
    public static VerdictVerifier fromConfiguration(String trustedKeys, boolean requireSigned, Duration maxSkew,
                                                    Clock clock) {
        TrustedCertificates trusted = trustedKeys == null || trustedKeys.isBlank()
                ? TrustedCertificates.none()
                : TrustedCertificates.load(trustedKeys, "railgate.gatekeeper.trusted-keys");
        VerdictVerifier verifier = new VerdictVerifier(trusted, requireSigned, maxSkew, clock);
        if (!requireSigned) {
            log.warn("railgate.gatekeeper.require-signed-verdict=false: a gatekeeper verdict without "
                    + "a signature is accepted and recorded as UNSIGNED, so its integrity rests on the "
                    + "transport alone. This configuration MUST NOT be deployed.");
        } else if (trusted.isEmpty()) {
            log.warn("railgate.gatekeeper.require-signed-verdict=true and railgate.gatekeeper.trusted-keys "
                    + "is empty: no gatekeeper verdict can be verified, so every settlement that reaches "
                    + "the gatekeeper is denied with VERDICT_SIGNATURE_INVALID.");
        } else {
            log.info("Gatekeeper verdict signatures required; trusted gatekeeper key fingerprints: {}; "
                    + "maximum skew {}", trusted.fingerprints(), maxSkew);
        }
        return verifier;
    }

    public boolean isSignatureRequired() {
        return requireSigned;
    }

    public Check check(PaymentSignature sent, VerificationResult verdict) {
        if (!verdict.hasAnySignatureField()) {
            if (requireSigned) {
                return invalid("the verdict is unsigned and railgate.gatekeeper.require-signed-verdict is true");
            }
            return new Check(VerdictSignatureStatus.UNSIGNED, null, "unsigned verdict accepted");
        }
        if (!requireSigned && trusted.isEmpty()) {
            return new Check(VerdictSignatureStatus.UNVERIFIED, null,
                    "signature fields present but not checked: no signature required and no key trusted");
        }
        if (isBlank(verdict.getVerifiedAt()) || isBlank(verdict.getVerdictSignatureBase64())
                || isBlank(verdict.getVerdictSignatureAlgorithm()) || isBlank(verdict.getSigningKeyFingerprintHex())) {
            return invalid("the verdict carries some but not all of the four signature fields");
        }

        String sentSerial;
        String sentIssuer;
        String sentDigest;
        try {
            sentSerial = CanonicalFields.certSerialHex(sent.getCertSerial());
            sentIssuer = CanonicalFields.issuerDn(sent.getIssuerDn());
            sentDigest = CanonicalFields.digestHex(sent.getDigestHex());
        } catch (IllegalArgumentException e) {
            // GatekeeperClient checks the material before the call; unreachable there.
            return invalid("the request fields cannot be canonicalised");
        }

        byte[] canonical = VerdictCanonicalizer.canonicalBytes(
                verdict.getVerifiedAt(),
                sent.getCertSerial(),
                sent.getIssuerDn(),
                sent.getDigestHex(),
                verdict.isSignatureValid(),
                verdict.isCompliant(),
                verdict.getReason(),
                verdict.getAuditEntryId(),
                verdict.getAuditEntryHashHex());
        SignedStatementVerifier.Outcome outcome = SignedStatementVerifier.verify(trusted,
                verdict.getSigningKeyFingerprintHex(), verdict.getVerdictSignatureAlgorithm(),
                verdict.getVerdictSignatureBase64(), canonical);
        if (outcome != SignedStatementVerifier.Outcome.VALID) {
            return invalid("verdict signature rejected: " + outcome.describe());
        }

        if (verdict.getCertSerial() != null && !sameSerial(sentSerial, verdict.getCertSerial())) {
            return invalid("the echoed certSerial does not match the request");
        }
        if (verdict.getIssuerDn() != null && !sameIssuer(sentIssuer, verdict.getIssuerDn())) {
            return invalid("the echoed issuerDn does not match the request");
        }
        if (verdict.getDigestHex() != null
                && !sentDigest.equals(verdict.getDigestHex().toLowerCase(Locale.ROOT))) {
            return invalid("the echoed digestHex does not match the request");
        }

        Instant verifiedAt;
        try {
            verifiedAt = Instant.parse(verdict.getVerifiedAt());
        } catch (DateTimeParseException e) {
            return invalid("verifiedAt is not an ISO-8601 instant");
        }
        Duration skew = Duration.between(verifiedAt, clock.instant()).abs();
        if (skew.compareTo(maxSkew) > 0) {
            return new Check(VerdictSignatureStatus.INVALID, VERDICT_STALE,
                    "verifiedAt is " + skew + " from railgate's clock; the maximum is " + maxSkew);
        }
        return new Check(VerdictSignatureStatus.VERIFIED, null, "verdict signature verified");
    }

    /** Whether the echoed serial is the one sent; an echo that does not parse is not. */
    private static boolean sameSerial(String sentSerial, String echoed) {
        try {
            return sentSerial.equals(CanonicalFields.certSerialHex(echoed));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Whether the echoed issuer is the one sent; an echo that does not parse is not. */
    private static boolean sameIssuer(String sentIssuer, String echoed) {
        try {
            return sentIssuer.equals(CanonicalFields.issuerDn(echoed));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static Check invalid(String detail) {
        return new Check(VerdictSignatureStatus.INVALID, VERDICT_SIGNATURE_INVALID, detail);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
