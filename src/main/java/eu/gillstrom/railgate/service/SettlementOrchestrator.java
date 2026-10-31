package eu.gillstrom.railgate.service;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.client.PaymentNetworkClient;
import eu.gillstrom.railgate.client.PaymentNetworkLookup;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.model.VerificationResult;
import eu.gillstrom.railgate.replay.ReplayGuard;
import eu.gillstrom.railgate.replay.ReplayJournalException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
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
 *       {@code DORA_32_AUDIT_MISSING}; operator unreachable →
 *       {@code NETWORK_ERROR}; operator answer not authenticated
 *       ({@code http} mode) → {@code OPERATOR_SIGNATURE_INVALID}.</li>
 *   <li>If the settlement message declares a certificate serial, compare it
 *       numerically with the payment-network operator's. A difference →
 *       default-deny with {@code DECLARED_CERT_MISMATCH}, without calling
 *       the gatekeeper.</li>
 *   <li>Reserve the transaction reference and, when the operator supplied
 *       one, its payout instruction id in {@link ReplayGuard}. Either already
 *       allowed, or held by a concurrent evaluation → default-deny with
 *       {@code REFERENCE_ALREADY_SETTLED}, without calling the gatekeeper.</li>
 *   <li>Forward to gatekeeper for cryptographic verification and
 *       compliance check; {@code GatekeeperClient} checks the verdict's
 *       signature.</li>
 *   <li>Allow if and only if both signature is valid and certificate is
 *       compliant, and the reservation has been committed to the replay
 *       journal. Otherwise release the reservation and default-deny with
 *       the specific reason code.</li>
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
@Slf4j
public class SettlementOrchestrator {

    private final RegulatedPaymentDetector detector;
    private final PaymentNetworkClient paymentNetworkClient;
    private final GatekeeperClient gatekeeperClient;
    private final RailgateAuditLog auditLog;
    private final ReplayGuard replayGuard;

    @Autowired
    public SettlementOrchestrator(RegulatedPaymentDetector detector,
                                  PaymentNetworkClient paymentNetworkClient,
                                  GatekeeperClient gatekeeperClient,
                                  RailgateAuditLog auditLog,
                                  ReplayGuard replayGuard) {
        this.detector = detector;
        this.paymentNetworkClient = paymentNetworkClient;
        this.gatekeeperClient = gatekeeperClient;
        this.auditLog = auditLog;
        this.replayGuard = replayGuard;
    }

    /** For tests: replay protection held in memory only. */
    SettlementOrchestrator(RegulatedPaymentDetector detector,
                           PaymentNetworkClient paymentNetworkClient,
                           GatekeeperClient gatekeeperClient,
                           RailgateAuditLog auditLog) {
        this(detector, paymentNetworkClient, gatekeeperClient, auditLog, ReplayGuard.inMemory());
    }

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

        String reference = request.getTransactionReference();
        PaymentNetworkLookup lookup = paymentNetworkClient.lookup(reference);

        PaymentSignature signature;
        switch (lookup) {
            case PaymentNetworkLookup.Found found -> signature = found.signature();
            case PaymentNetworkLookup.NotFound notFound -> {
                return record(SettlementDecision.builder()
                        .allow(false)
                        .reasonCode("DORA_32_AUDIT_MISSING")
                        .message("No signature artefacts found at payment-network operator "
                                + "for this transaction reference. Either the originating "
                                + "bank has not properly registered the transaction or the "
                                + "transaction has been routed outside the regulated path.")
                        .transactionReference(reference)
                        .build());
            }
            case PaymentNetworkLookup.Unavailable unavailable -> {
                return record(SettlementDecision.builder()
                        .allow(false)
                        .reasonCode("NETWORK_ERROR")
                        .message("The payment-network operator could not be reached or did not "
                                + "answer usably. Default-deny applied.")
                        .transactionReference(reference)
                        .build());
            }
            case PaymentNetworkLookup.OperatorSignatureInvalid invalid -> {
                return record(SettlementDecision.builder()
                        .allow(false)
                        .reasonCode("OPERATOR_SIGNATURE_INVALID")
                        .message("The payment-network operator's answer could not be authenticated: "
                                + invalid.detail() + ". The gatekeeper was not called.")
                        .transactionReference(reference)
                        .build());
            }
        }

        if (declaredCertSerialMismatch(request.getDeclaredCertSerial(), signature.getCertSerial())) {
            return record(SettlementDecision.builder()
                    .allow(false)
                    .reasonCode("DECLARED_CERT_MISMATCH")
                    .message("The certificate serial declared in the settlement message does "
                            + "not match the serial the payment-network operator holds for "
                            + "this transaction reference.")
                    .transactionReference(reference)
                    .build());
        }

        ReplayGuard.Reservation reservation;
        switch (replayGuard.tryReserve(reference, signature.getPayoutInstructionId())) {
            case ReplayGuard.Reserved reserved -> reservation = reserved.reservation();
            case ReplayGuard.Refused refused -> {
                return record(SettlementDecision.builder()
                        .allow(false)
                        .reasonCode("REFERENCE_ALREADY_SETTLED")
                        .message(alreadySettledMessage(refused))
                        .transactionReference(reference)
                        .build());
            }
        }

        boolean committed = false;
        try {
            VerificationResult verification = gatekeeperClient.verify(signature);

            if (!verification.isAllowed()) {
                return record(SettlementDecision.builder()
                        .allow(false)
                        .reasonCode(reasonCodeFor(verification))
                        .message(verification.getReason() != null
                                ? verification.getReason()
                                : "Verification did not return a positive result")
                        .transactionReference(reference)
                        .auditEntryId(verification.getAuditEntryId())
                        .auditEntryHashHex(verification.getAuditEntryHashHex())
                        .verdictSignature(verification.getVerdictSignature())
                        .build());
            }

            try {
                replayGuard.commit(reservation);
                committed = true;
            } catch (ReplayJournalException e) {
                log.error("Allowed settlement could not be recorded in the replay journal; denying it", e);
                return record(SettlementDecision.builder()
                        .allow(false)
                        .reasonCode("INTERNAL_ERROR")
                        .message("Verification passed, but the settlement could not be recorded as "
                                + "allowed in railgate's replay journal. Default-deny applied.")
                        .transactionReference(reference)
                        .auditEntryId(verification.getAuditEntryId())
                        .auditEntryHashHex(verification.getAuditEntryHashHex())
                        .verdictSignature(verification.getVerdictSignature())
                        .build());
            }

            return record(SettlementDecision.builder()
                    .allow(true)
                    .reasonCode("ALLOWED")
                    .message("Cryptographic verification passed against compliant gatekeeper audit entry")
                    .transactionReference(reference)
                    .auditEntryId(verification.getAuditEntryId())
                    .auditEntryHashHex(verification.getAuditEntryHashHex())
                    .verdictSignature(verification.getVerdictSignature())
                    .build());
        } finally {
            if (!committed) {
                replayGuard.release(reservation);
            }
        }
    }

    private static String alreadySettledMessage(ReplayGuard.Refused refused) {
        String what = refused.key() == ReplayGuard.Key.PAYOUT_INSTRUCTION_ID
                ? "The payment-network operator's payout instruction id for this transaction reference"
                : "This transaction reference";
        if (refused.inProgress()) {
            return what + " is held by another settlement evaluation that has not finished. "
                    + "The gatekeeper was not called; resubmit once that evaluation has been denied.";
        }
        return what + " has already been allowed by railgate. The gatekeeper was not called.";
    }

    private SettlementDecision record(SettlementDecision decision) {
        auditLog.record(decision);
        return decision;
    }

    private static boolean declaredCertSerialMismatch(String declaredCertSerial, String operatorCertSerial) {
        if (declaredCertSerial == null || declaredCertSerial.isBlank()) {
            return false;
        }
        BigInteger operator = PaymentSignature.parseCertSerial(operatorCertSerial);
        if (operator == null) {
            return false;
        }
        return !operator.equals(PaymentSignature.parseCertSerial(declaredCertSerial.trim()));
    }

    /**
     * Reason codes that may arrive in {@link VerificationResult#getReason()}
     * and are passed through unchanged.
     *
     * <p>The first nine are produced by the gatekeeper; {@code CERT_EXPIRED}
     * (gatekeeper 1.6.0) is a certificate outside its validity period, which
     * arrives with {@code signatureValid=true} and was reported as
     * {@code CERT_NON_COMPLIANT}. {@code CERT_SUPERSEDED},
     * {@code CERT_REVOKED} and {@code CERT_DECOMMISSIONED} are certificates
     * whose key was rotated, revoked or decommissioned by a key-lifecycle
     * event on the gatekeeper ({@code POST /v1/attestation/{cc}/lifecycle});
     * they also arrive with {@code signatureValid=true} and would otherwise be
     * reported as {@code CERT_NON_COMPLIANT}. {@code MALFORMED_INPUT}
     * (the gatekeeper could not parse the request; gatekeeper 1.4.0 answered
     * it to every request railgate sends, because it required a PEM
     * certificate railgate does not forward) and
     * {@code ALGORITHM_NOT_SUPPORTED} (the gatekeeper would not run the
     * signature algorithm) say nothing about the
     * signature; both arrive with {@code signatureValid=false}, and deriving
     * the code from that boolean reported them as {@code SIGNATURE_INVALID}.
     * The last two are produced by {@code GatekeeperClient} itself:
     * {@code NETWORK_ERROR} when the supervisor could not be reached,
     * {@code INVALID_SIGNATURE_MATERIAL} when the artefacts from the
     * payment-network operator were malformed and the call was never made.
     * All four describe a failure outside the cryptography and must not be
     * reported as {@code SIGNATURE_INVALID}, which is an accusation against
     * the originating bank. {@code VERDICT_SIGNATURE_INVALID} and
     * {@code VERDICT_STALE} are also produced by {@code GatekeeperClient}, when
     * the gatekeeper's verdict fails its signature or freshness check; the
     * verdict's own flags and reason are then discarded.</p>
     */
    private static final Set<String> PASSTHROUGH_REASONS = Set.of(
            "CERT_NOT_FOUND",
            "CERT_NON_COMPLIANT",
            "CERT_EXPIRED",
            "CERT_SUPERSEDED",
            "CERT_REVOKED",
            "CERT_DECOMMISSIONED",
            "SIGNATURE_INVALID",
            "MALFORMED_INPUT",
            "ALGORITHM_NOT_SUPPORTED",
            "NETWORK_ERROR",
            "INVALID_SIGNATURE_MATERIAL",
            "VERDICT_SIGNATURE_INVALID",
            "VERDICT_STALE");

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
