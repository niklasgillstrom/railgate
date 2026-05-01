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
 *       codes.</li>
 *
 *   <li><b>Structural derivation:</b> {@code OrgId} is populated on the
 *       debtor side and {@code PrvtId} on the creditor side. By definition
 *       of the Swish utbetalning service in Sweden, organization-to-private
 *       payouts via instant settlement are Swish utbetalning. This path
 *       cannot be circumvented by the originating bank by mislabelling the
 *       transaction — the directional structure is inherent to the
 *       transaction.</li>
 * </ol>
 *
 * <p>Either path is sufficient. A bank that omits the explicit code does
 * not avoid railgate enforcement; the structural path catches it.
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
     *     identifies it as a regulated payment
     */
    public boolean isRegulated(SettlementRequest request) {
        if (request.getLocalInstrumentCode() != null
                && regulatedCodes.contains(request.getLocalInstrumentCode())) {
            return true;
        }
        if (request.isDebtorIsOrganization() && request.isCreditorIsPrivatePerson()) {
            return true;
        }
        return false;
    }
}
