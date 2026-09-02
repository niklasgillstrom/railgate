package eu.gillstrom.railgate.service;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.client.PaymentNetworkClient;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.model.VerificationResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

/**
 * Core orchestration logic for settlement-time enforcement.
 *
 * <p>Flow:
 * <ol>
 *   <li>Determine whether the settlement is a regulated payment.
 *       Non-regulated settlements are passed through without verification
 *       (railgate has no opinion on them).</li>
 *   <li>Retrieve {@code (digest, signature, certSerial)} from the
 *       payment-network operator. Missing entry → default-deny with
 *       {@code DORA_32_AUDIT_MISSING}.</li>
 *   <li>Forward to gatekeeper for cryptographic verification and
 *       compliance check.</li>
 *   <li>Allow if and only if both signature is valid and certificate is
 *       compliant. Otherwise default-deny with the specific reason code.</li>
 *   <li>Record the decision in railgate's audit log.</li>
 * </ol>
 *
 * <p>This logic is deliberately simple: the entire complexity of
 * verification lives in the components it orchestrates (gatekeeper does
 * the cryptography, the payment-network operator holds the signature,
 * regulated-payment detection identifies what to verify). Railgate is
 * the glue that makes default-deny enforceable at the settlement rail.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SettlementOrchestrator {

    private final RegulatedPaymentDetector detector;
    private final PaymentNetworkClient paymentNetworkClient;
    private final GatekeeperClient gatekeeperClient;
    private final RailgateAuditLog auditLog;

    public SettlementDecision evaluate(SettlementRequest request) {
        // The pass-through below is the only path that yields allow=true
        // without a gatekeeper response, so it is guarded twice: the
        // classification must be present, and the detector must say the
        // settlement is not regulated. RegulatedPaymentDetector already
        // treats a missing classification as regulated; the check is
        // repeated here so the invariant does not depend on a collaborator.
        boolean classified = request != null
                && request.getDebtorIsOrganization() != null
                && request.getCreditorIsPrivatePerson() != null;

        if (classified && !detector.isRegulated(request)) {
            // Non-regulated settlement: railgate has no role; pass through.
            return record(SettlementDecision.builder()
                    .allow(true)
                    .reasonCode("NOT_REGULATED")
                    .message("Settlement is not subject to railgate enforcement")
                    .transactionReference(request.getTransactionReference())
                    .build());
        }

        Optional<PaymentSignature> signature = paymentNetworkClient.getSignature(
                request.getTransactionReference());

        if (signature.isEmpty()) {
            return record(SettlementDecision.builder()
                    .allow(false)
                    .reasonCode("DORA_32_AUDIT_MISSING")
                    .message("No signature artefacts found at payment-network operator "
                            + "for this transaction reference. Either the originating "
                            + "bank has not properly registered the transaction or the "
                            + "transaction has been routed outside the regulated path.")
                    .transactionReference(request.getTransactionReference())
                    .build());
        }

        VerificationResult verification = gatekeeperClient.verify(signature.get());

        if (!verification.isAllowed()) {
            return record(SettlementDecision.builder()
                    .allow(false)
                    .reasonCode(reasonCodeFor(verification))
                    .message(verification.getReason() != null
                            ? verification.getReason()
                            : "Verification did not return a positive result")
                    .transactionReference(request.getTransactionReference())
                    .auditEntryId(verification.getAuditEntryId())
                    .build());
        }

        return record(SettlementDecision.builder()
                .allow(true)
                .reasonCode("ALLOWED")
                .message("Cryptographic verification passed against compliant gatekeeper audit entry")
                .transactionReference(request.getTransactionReference())
                .auditEntryId(verification.getAuditEntryId())
                .build());
    }

    private SettlementDecision record(SettlementDecision decision) {
        auditLog.record(decision);
        return decision;
    }

    /**
     * Reason codes that may arrive in {@link VerificationResult#getReason()}
     * and are passed through unchanged.
     *
     * <p>The first four are produced by the gatekeeper. The fifth is produced
     * by {@code GatekeeperClient} itself: {@code NETWORK_ERROR} when the
     * supervisor could not be reached, {@code INVALID_SIGNATURE_MATERIAL}
     * when the artefacts from the payment-network operator were malformed and
     * the call was never made. Both describe a failure upstream of the
     * cryptography and must not be reported as {@code SIGNATURE_INVALID},
     * which is an accusation against the originating bank.</p>
     */
    private static final Set<String> PASSTHROUGH_REASONS = Set.of(
            "CERT_NOT_FOUND",
            "CERT_NON_COMPLIANT",
            "SIGNATURE_INVALID",
            "NETWORK_ERROR",
            "INVALID_SIGNATURE_MATERIAL");

    /**
     * Maps a non-positive verification result to the reason code returned to
     * the originating bank.
     *
     * <p>The gatekeeper's own reason is read first. {@code CERT_NOT_FOUND} —
     * the certificate matches no gatekeeper audit entry, which is the
     * circumvented-issuance case — is distinct from a certificate that exists
     * and failed its checks, and deriving the code from the two booleans
     * alone collapsed the two into {@code SIGNATURE_INVALID}.</p>
     *
     * <p>Called only when {@code !verification.isAllowed()}, so the fallback
     * is exhaustive: either the signature did not verify, or it did and the
     * certificate was not compliant. There is no third case, and the
     * {@code VERIFICATION_FAILED} branch that used to sit here was
     * unreachable.</p>
     */
    private static String reasonCodeFor(VerificationResult verification) {
        String reason = verification.getReason();
        if (reason != null && PASSTHROUGH_REASONS.contains(reason.trim())) {
            return reason.trim();
        }
        if (!verification.isSignatureValid()) {
            return "SIGNATURE_INVALID";
        }
        return "CERT_NON_COMPLIANT";
    }
}
