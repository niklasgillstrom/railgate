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
 * originating bank's incentives and cannot misreport the signature or cert
 * serial without immediately producing detectable inconsistency. This
 * eliminates bank cooperation as a trust point in the verification chain.
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
     *     was registered with the payment-network operator
     */
    Optional<PaymentSignature> getSignature(String transactionReference);
}
