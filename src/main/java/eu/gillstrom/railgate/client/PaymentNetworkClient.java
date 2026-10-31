package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;

import java.util.Optional;

/**
 * Client interface for retrieving cryptographic artefacts from the
 * payment-network operator (Getswish AB in the Swedish reference deployment).
 *
 * <p>The payment-network operator is the authoritative source for the
 * {@code (digest, signature, certSerial)} triple — they receive the original
 * signed payment instruction from the originating bank when the bank calls
 * the network's payout API and store these artefacts as part of normal
 * operations.
 *
 * <p>Why railgate queries the payment-network operator rather than the
 * originating bank: the payment-network operator is independent of the
 * originating bank's incentives. That removes the bank as the source of the
 * artefacts; it does not make a misreport by the operator detectable in
 * general. The only cross-check railgate performs is against the serial the
 * bank declares in pacs.008 RgltryRptg, when it declares one: a difference
 * is denied as {@code DECLARED_CERT_MISMATCH}. Without a declared serial,
 * railgate verifies what the operator returns and nothing else.
 *
 * <p><b>Authenticity of the operator's answer.</b> Three implementations
 * exist. {@link HttpPaymentNetworkClient} ({@code mode=http}) calls the
 * operator interface specified in
 * {@code api/payment-network-operator.openapi.yaml}, over mTLS, and accepts an
 * answer only when the operator's {@code op1} signature over it verifies under
 * a pinned operator certificate, the algorithm is allow-listed and the echoed
 * transaction reference is the one requested; otherwise the settlement is
 * denied with {@code OPERATOR_SIGNATURE_INVALID}. The signature makes the
 * operator accountable for what it returned; it does not make a false answer
 * from the operator detectable. {@link InMemoryPaymentNetworkClient} and
 * {@link FilePaymentNetworkClient} perform no such check, and whoever fills
 * them controls the artefacts. No operator offers this interface today; it is
 * specified so that it can be required of one.
 *
 * <p><b>Reuse of a transaction reference.</b> The lookup itself does not bind
 * the artefacts to one settlement. {@code SettlementOrchestrator} does: it
 * records the transaction reference (and, in {@code http} mode, the operator's
 * {@code payoutInstructionId}) of every {@code ALLOWED} settlement in
 * {@code ReplayGuard} and denies a later settlement that carries either with
 * {@code REFERENCE_ALREADY_SETTLED}. That record is local to one railgate
 * instance and its journal.
 *
 * <p>The implementation lookup is by {@code transactionReference} (typically
 * pacs.008 EndToEndId or UETR), which the payment-network operator already
 * receives as part of the normal payment flow.
 */
public interface PaymentNetworkClient {

    /**
     * Retrieve the signature artefacts associated with a settlement.
     *
     * @param transactionReference end-to-end transaction reference (UETR
     *     or EndToEndId)
     * @return signature artefacts if found, empty if no matching transaction
     *     was registered with the payment-network operator, or (for
     *     {@link HttpPaymentNetworkClient}) if the operator could not be
     *     reached or its answer did not verify
     */
    Optional<PaymentSignature> getSignature(String transactionReference);

    /**
     * Retrieve the artefacts and say why when there are none.
     *
     * <p>The orchestrator calls this method. The default wraps
     * {@link #getSignature}, which can only report found or not found;
     * {@link HttpPaymentNetworkClient} overrides it to report an unreachable
     * operator and an unauthenticated answer separately.
     */
    default PaymentNetworkLookup lookup(String transactionReference) {
        return getSignature(transactionReference)
                .<PaymentNetworkLookup>map(PaymentNetworkLookup.Found::new)
                .orElseGet(PaymentNetworkLookup.NotFound::new);
    }
}
