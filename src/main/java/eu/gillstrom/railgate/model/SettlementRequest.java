package eu.gillstrom.railgate.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Settlement request as received from the central-bank settlement rail.
 *
 * <p>This is a minimal abstraction of an ISO 20022 pacs.008 message — only the
 * fields railgate actually needs are modelled. A production deployment would
 * receive the full pacs.008 and parse the relevant fields; the abstraction
 * here keeps the reference implementation focused on the verification logic
 * rather than ISO 20022 parsing.
 *
 * <p>Identification of a settlement as a regulated payment uses two paths:
 * <ul>
 *   <li>Explicit: {@code localInstrumentCode} matches a known regulated
 *       payment-type code (e.g. "SWISH" for Swedish Swish utbetalning).</li>
 *   <li>Structural derivation: {@code debtorIsOrganization} is true and
 *       {@code creditorIsPrivatePerson} is true — by definition this is
 *       Swish utbetalning in the Swedish context.</li>
 * </ul>
 *
 * <p><b>What the party-type flags are, and are not.</b> Both flags are
 * metadata: they are derived by the settlement system from the debtor and
 * creditor identification structures in the incoming pacs.008
 * ({@code Dbtr/Id/OrgId}, {@code Cdtr/Id/PrvtId}) and handed to railgate in
 * this model. railgate does not parse the pacs.008 and cannot confirm the
 * derivation. The structural path is therefore harder to evade than the
 * explicit code — a payout to a private person has to be identified as one
 * somewhere in the message for the payment to work at all — but it is not a
 * property railgate verifies. Both flags are {@code @NotNull}: a request
 * that omits either is rejected by validation, and a request that reaches
 * the detector without them is treated as regulated, so an absent
 * classification produces verification rather than a pass-through. See
 * {@code RegulatedPaymentDetector}.
 *
 * <p>The {@code transactionReference} (typically pacs.008 EndToEndId or
 * UETR) is used to look up the corresponding signature and digest at the
 * payment-network operator.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SettlementRequest {

    /**
     * Unique end-to-end transaction reference, typically the pacs.008
     * EndToEndId or UETR. Used to correlate this settlement attempt with
     * the originating signed payment instruction at the payment-network
     * operator.
     */
    @NotBlank
    private String transactionReference;

    /**
     * Local instrument code from PmtTpInf/LclInstrm/Cd in pacs.008. May be
     * empty if the originating bank has not populated it. When populated,
     * a value such as "SWISH" identifies the payment as Swish utbetalning.
     * Bounded to the ISO 20022 {@code Max35Text} length of the underlying
     * element.
     */
    @Size(max = 35)
    private String localInstrumentCode;

    /**
     * Optional certificate serial number, extracted from
     * pacs.008 RgltryRptg field if populated by the originating bank. May
     * be null — railgate then queries the payment-network operator for
     * the authoritative cert serial.
     */
    private String declaredCertSerial;

    /**
     * Whether the debtor (sender) is identified as an organization.
     *
     * <p>A wrapper rather than a primitive so that "not supplied" is
     * distinguishable from "false". As a primitive, an omitted field
     * deserialised to {@code false}, and a request carrying no
     * classification at all was indistinguishable from a private-to-private
     * transfer — which is the one shape that passes through railgate without
     * verification. Missing is now missing.
     */
    @NotNull
    private Boolean debtorIsOrganization;

    /**
     * Whether the creditor (receiver) is identified as a private person.
     * Wrapper type for the same reason as {@link #debtorIsOrganization}.
     */
    @NotNull
    private Boolean creditorIsPrivatePerson;

    /** Originating bank BIC (sender). */
    private String debtorBic;

    /** Receiving bank BIC. */
    private String creditorBic;
}
