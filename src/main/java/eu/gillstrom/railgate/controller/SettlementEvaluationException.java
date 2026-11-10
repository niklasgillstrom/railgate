package eu.gillstrom.railgate.controller;

/**
 * An unexpected failure while a settlement request that had been read and
 * validated was being evaluated. It carries the transaction reference, so
 * that the deny {@link SettlementExceptionHandler} records can be matched to
 * the settlement it concerns.
 */
public class SettlementEvaluationException extends RuntimeException {

    private final String transactionReference;

    public SettlementEvaluationException(String transactionReference, Throwable cause) {
        super("settlement evaluation failed", cause);
        this.transactionReference = transactionReference;
    }

    public String transactionReference() {
        return transactionReference;
    }
}
