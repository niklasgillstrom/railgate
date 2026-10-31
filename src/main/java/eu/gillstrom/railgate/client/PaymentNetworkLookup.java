package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;

import java.util.Objects;

/**
 * Outcome of one artefact lookup at the payment-network operator.
 *
 * <p>{@link PaymentNetworkClient#getSignature} can only say "found" or "not
 * found". An HTTP client has two more outcomes that must not be confused with
 * either: the operator could not be reached, and the operator answered with
 * something railgate could not authenticate. The orchestrator maps each to its
 * own reason code.</p>
 */
public sealed interface PaymentNetworkLookup {

    /** The operator returned artefacts (and, in {@code http} mode, they verified). */
    record Found(PaymentSignature signature) implements PaymentNetworkLookup {
        public Found {
            Objects.requireNonNull(signature, "signature");
        }
    }

    /** The operator holds nothing for the reference ({@code DORA_32_AUDIT_MISSING}). */
    record NotFound() implements PaymentNetworkLookup {
    }

    /** The operator could not be reached or did not answer usably ({@code NETWORK_ERROR}). */
    record Unavailable(String detail) implements PaymentNetworkLookup {
    }

    /** The operator answered, but the answer is not authenticated ({@code OPERATOR_SIGNATURE_INVALID}). */
    record OperatorSignatureInvalid(String detail) implements PaymentNetworkLookup {
    }
}
