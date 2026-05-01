package eu.gillstrom.railgate.model;

import jakarta.validation.constraints.NotBlank;
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
 *       Swish utbetalning in the Swedish context. The structural derivation
 *       does not depend on bank-supplied transaction-type metadata and
 *       therefore cannot be circumvented by mislabelling the transaction.</li>
 * </ul>
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
     */
    private String localInstrumentCode;

    /**
     * Optional certificate serial number, extracted from
     * pacs.008 RgltryRptg field if populated by the originating bank. May
     * be null — railgate then queries the payment-network operator for
     * the authoritative cert serial.
     */
    private String declaredCertSerial;

    /** Whether the debtor (sender) is identified as an organization. */
    private boolean debtorIsOrganization;

    /** Whether the creditor (receiver) is identified as a private person. */
    private boolean creditorIsPrivatePerson;

    /** Originating bank BIC (sender). */
    private String debtorBic;

    /** Receiving bank BIC. */
    private String creditorBic;
}
