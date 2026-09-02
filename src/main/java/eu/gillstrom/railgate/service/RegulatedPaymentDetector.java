package eu.gillstrom.railgate.service;

import eu.gillstrom.railgate.model.SettlementRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * Determines whether an incoming settlement request is a regulated payment
 * subject to railgate enforcement.
 *
 * <p>Two paths are checked:
 *
 * <ol>
 *   <li><b>Explicit:</b> {@code PmtTpInf/LclInstrm/Cd} matches a configured
 *       regulated payment-type code. In the Swedish reference deployment
 *       this is {@code "SWISH"}; other jurisdictions configure their own
 *       codes. Matching is case-insensitive and ignores surrounding
 *       whitespace, so {@code " swish "} is not a way past the check.</li>
 *
 *   <li><b>Structural derivation:</b> {@code OrgId} is populated on the
 *       debtor side and {@code PrvtId} on the creditor side. By definition
 *       of the Swish utbetalning service in Sweden, organization-to-private
 *       payouts via instant settlement are Swish utbetalning.</li>
 * </ol>
 *
 * <p>Either path is sufficient. A bank that omits the explicit code does
 * not avoid railgate enforcement; the structural path catches it.
 *
 * <p><b>What the structural path rests on.</b> Both flags are metadata
 * derived by the settlement system from the debtor and creditor
 * identification structures in the pacs.008 and handed to railgate in
 * {@link SettlementRequest}. railgate does not parse the pacs.008 and
 * cannot recompute the derivation, so this is not a check railgate performs
 * on the message itself — it is a classification railgate consumes. What
 * makes the path useful is that the classification is harder to suppress
 * than the instrument code: a payout has to identify its creditor as a
 * private person somewhere in the message for the payment to reach one.
 *
 * <p><b>Missing classification is treated as regulated.</b> When either
 * flag is absent, this method returns {@code true}. An absent classification
 * therefore produces verification, not a pass-through: the only way to
 * obtain {@code allow=true} without a gatekeeper response is an explicit,
 * present classification that is not organisation-to-private.
 */
@Service
public class RegulatedPaymentDetector {

    @Value("${railgate.regulated.local-instrument-codes:SWISH}")
    private Set<String> regulatedCodes;

    /**
     * Whether this settlement should be subject to railgate verification.
     *
     * @param request settlement request from the central-bank rail
     * @return true if either the explicit or the structural derivation
     *     identifies it as a regulated payment, and true whenever the
     *     party-type classification is incomplete
     */
    public boolean isRegulated(SettlementRequest request) {
        if (request == null) {
            return true;
        }

        if (matchesRegulatedCode(request.getLocalInstrumentCode())) {
            return true;
        }

        Boolean debtorIsOrganization = request.getDebtorIsOrganization();
        Boolean creditorIsPrivatePerson = request.getCreditorIsPrivatePerson();

        if (debtorIsOrganization == null || creditorIsPrivatePerson == null) {
            // Default-deny reading of an incomplete request: unclassified
            // means unverified, and unverified means it goes to the
            // gatekeeper rather than past it.
            return true;
        }

        return debtorIsOrganization && creditorIsPrivatePerson;
    }

    private boolean matchesRegulatedCode(String localInstrumentCode) {
        if (localInstrumentCode == null || regulatedCodes == null) {
            return false;
        }
        String candidate = localInstrumentCode.trim();
        if (candidate.isEmpty()) {
            return false;
        }
        for (String configured : regulatedCodes) {
            if (configured != null && configured.trim().equalsIgnoreCase(candidate)) {
                return true;
            }
        }
        return false;
    }
}
