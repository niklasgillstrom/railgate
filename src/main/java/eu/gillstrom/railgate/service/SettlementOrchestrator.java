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
        if (!detector.isRegulated(request)) {
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

    private static String reasonCodeFor(VerificationResult verification) {
        if (!verification.isSignatureValid()) {
            return "SIGNATURE_INVALID";
        }
        if (!verification.isCompliant()) {
            return "CERT_NON_COMPLIANT";
        }
        if ("NETWORK_ERROR".equals(verification.getReason())) {
            return "NETWORK_ERROR";
        }
        return "VERIFICATION_FAILED";
    }
}
