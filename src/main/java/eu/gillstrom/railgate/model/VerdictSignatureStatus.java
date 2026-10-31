package eu.gillstrom.railgate.model;

/**
 * What railgate established about the signature on the gatekeeper's verdict.
 * Recorded on {@link SettlementDecision} and in the audit log; {@code null}
 * there means no gatekeeper verdict was consumed (the gatekeeper was not
 * called, or did not answer with a body).
 */
public enum VerdictSignatureStatus {

    /**
     * The verdict carried an {@code sv1} signature that verified under a
     * certificate in {@code railgate.gatekeeper.trusted-keys}, its echoed
     * request fields matched what railgate sent, and {@code verifiedAt} was
     * within {@code railgate.gatekeeper.verdict-max-skew}.
     */
    VERIFIED,

    /**
     * The verdict carried none of the four signature fields and
     * {@code railgate.gatekeeper.require-signed-verdict=false}: it was
     * consumed as plain JSON, as every verdict was before signed verdicts, with no integrity
     * protection beyond the transport.
     */
    UNSIGNED,

    /**
     * The verdict carried signature fields, but
     * {@code railgate.gatekeeper.require-signed-verdict=false} and
     * {@code railgate.gatekeeper.trusted-keys} is empty, so railgate had no key
     * to check them with and did not check them. The verdict was consumed as
     * {@link #UNSIGNED} would be.
     */
    UNVERIFIED,

    /**
     * The verdict was rejected: unsigned while a signature was required, or
     * signed but failing a check. The decision is a deny with
     * {@code VERDICT_SIGNATURE_INVALID} or {@code VERDICT_STALE}.
     */
    INVALID
}
