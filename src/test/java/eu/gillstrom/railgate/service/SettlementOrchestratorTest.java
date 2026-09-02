package eu.gillstrom.railgate.service;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.client.InMemoryPaymentNetworkClient;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.model.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SettlementOrchestratorTest {

    private InMemoryPaymentNetworkClient paymentNetworkClient;
    private GatekeeperClient gatekeeperClient;
    private RegulatedPaymentDetector detector;
    private RailgateAuditLog auditLog;
    private SettlementOrchestrator orchestrator;

    @BeforeEach
    void setUp() {
        paymentNetworkClient = new InMemoryPaymentNetworkClient();
        gatekeeperClient = mock(GatekeeperClient.class);
        detector = new RegulatedPaymentDetector();
        auditLog = new RailgateAuditLog();
        // Inject regulated codes for tests
        try {
            var f = RegulatedPaymentDetector.class.getDeclaredField("regulatedCodes");
            f.setAccessible(true);
            f.set(detector, java.util.Set.of("SWISH"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        orchestrator = new SettlementOrchestrator(detector, paymentNetworkClient, gatekeeperClient, auditLog);
    }

    @Test
    void allowsSettlementWhenSignatureVerifiesAndCertCompliant() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("TXREF-1")
                .localInstrumentCode("SWISH")
                .build();

        paymentNetworkClient.register("TXREF-1", PaymentSignature.builder()
                .digestHex("deadbeef")
                .signatureBase64("AAAA")
                .certSerial("12345")
                .issuerDn("CN=SEB Customer CA")
                .build());

        when(gatekeeperClient.verify(any())).thenReturn(VerificationResult.builder()
                .signatureValid(true)
                .compliant(true)
                .auditEntryId("ENTRY-X")
                .build());

        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isTrue();
        assertThat(decision.getReasonCode()).isEqualTo("ALLOWED");
        assertThat(decision.getAuditEntryId()).isEqualTo("ENTRY-X");
    }

    @Test
    void deniesWhenSignatureMissingFromPaymentNetwork() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("UNKNOWN-REF")
                .localInstrumentCode("SWISH")
                .build();

        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("DORA_32_AUDIT_MISSING");
    }

    @Test
    void deniesWhenSignatureInvalid() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("TXREF-2")
                .localInstrumentCode("SWISH")
                .build();

        paymentNetworkClient.register("TXREF-2", PaymentSignature.builder()
                .digestHex("deadbeef")
                .signatureBase64("BAD")
                .certSerial("99999")
                .issuerDn("CN=SEB Customer CA")
                .build());

        when(gatekeeperClient.verify(any())).thenReturn(VerificationResult.builder()
                .signatureValid(false)
                .compliant(true)
                .reason("SIGNATURE_INVALID")
                .build());

        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("SIGNATURE_INVALID");
    }

    @Test
    void deniesWhenCertNonCompliant() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("TXREF-3")
                .localInstrumentCode("SWISH")
                .build();

        paymentNetworkClient.register("TXREF-3", PaymentSignature.builder()
                .digestHex("deadbeef")
                .signatureBase64("AAAA")
                .certSerial("12345")
                .issuerDn("CN=SEB Customer CA")
                .build());

        when(gatekeeperClient.verify(any())).thenReturn(VerificationResult.builder()
                .signatureValid(true)
                .compliant(false)
                .reason("CERT_NON_COMPLIANT")
                .build());

        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("CERT_NON_COMPLIANT");
    }

    @Test
    void identifiesSwishUtbetalningByStructuralDerivation() {
        // No LclInstrm code, but org → private — must still be regulated
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("TXREF-4")
                .localInstrumentCode(null)
                .debtorIsOrganization(true)
                .creditorIsPrivatePerson(true)
                .build();

        // No signature registered → default-deny with DORA_32_AUDIT_MISSING
        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("DORA_32_AUDIT_MISSING");
    }

    @Test
    void passesThroughNonRegulatedSettlements() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("TXREF-5")
                .localInstrumentCode("SCT")
                .debtorIsOrganization(true)
                .creditorIsPrivatePerson(false)
                .build();

        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isTrue();
        assertThat(decision.getReasonCode()).isEqualTo("NOT_REGULATED");
    }

    // ---------------------------------------------------------------
    // Default-deny on missing classification (1.4.0)
    // ---------------------------------------------------------------

    @Test
    void missingPartyTypeFlagsAreTreatedAsRegulated() {
        // Both flags absent and no instrument code: nothing identifies this
        // as a Swish utbetalning, and nothing identifies it as anything else
        // either. As primitives the two flags deserialised to false, which
        // read as private-to-private — the one shape that passes through
        // without verification. Unclassified must mean verified.
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("TXREF-UNCLASSIFIED")
                .localInstrumentCode(null)
                .debtorIsOrganization(null)
                .creditorIsPrivatePerson(null)
                .build();

        assertThat(detector.isRegulated(request)).isTrue();

        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("DORA_32_AUDIT_MISSING");
    }

    @Test
    void oneMissingPartyTypeFlagIsAlsoTreatedAsRegulated() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("TXREF-HALF-CLASSIFIED")
                .debtorIsOrganization(false)
                .creditorIsPrivatePerson(null)
                .build();

        assertThat(detector.isRegulated(request)).isTrue();
        assertThat(orchestrator.evaluate(request).isAllow()).isFalse();
    }

    @Test
    void instrumentCodeMatchingIsCaseInsensitiveAndTrimmed() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("TXREF-CASE")
                .localInstrumentCode("  swish ")
                .debtorIsOrganization(false)
                .creditorIsPrivatePerson(false)
                .build();

        assertThat(detector.isRegulated(request)).isTrue();
        assertThat(orchestrator.evaluate(request).getReasonCode())
                .isEqualTo("DORA_32_AUDIT_MISSING");
    }

    // ---------------------------------------------------------------
    // Reason-code mapping (1.4.0)
    // ---------------------------------------------------------------

    @Test
    void certNotFoundIsReportedAsCertNotFound() {
        // The certificate matches no gatekeeper audit entry — the
        // circumvented-issuance case. Deriving the code from the two booleans
        // alone reported it as SIGNATURE_INVALID, which says the bank sent a
        // bad signature when what happened is that the certificate was never
        // issued through the compliant flow.
        SettlementRequest request = regulatedRequest("TXREF-6");
        registerSignature("TXREF-6");

        when(gatekeeperClient.verify(any())).thenReturn(VerificationResult.builder()
                .signatureValid(false)
                .compliant(false)
                .reason("CERT_NOT_FOUND")
                .build());

        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("CERT_NOT_FOUND");
    }

    @Test
    void gatekeeperOutageIsReportedAsNetworkErrorThroughTheOrchestrator() {
        // Regression test for the 1.3.0 fix. GatekeeperClient signals an
        // unreachable gatekeeper as signatureValid=false + reason=NETWORK_ERROR.
        // Until 1.3.0 the orchestrator tested the boolean first and reported
        // every outage as SIGNATURE_INVALID. The 1.3.0 fix was covered only at
        // the client; this pins it at the orchestrator, which is where the code
        // the bank receives is decided.
        SettlementRequest request = regulatedRequest("TXREF-7");
        registerSignature("TXREF-7");

        when(gatekeeperClient.verify(any())).thenReturn(VerificationResult.builder()
                .signatureValid(false)
                .compliant(false)
                .reason("NETWORK_ERROR")
                .build());

        SettlementDecision decision = orchestrator.evaluate(request);

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("NETWORK_ERROR");
    }

    @Test
    void malformedSignatureMaterialIsNotReportedAsSignatureInvalid() {
        // GatekeeperClient rejects malformed artefacts without calling the
        // gatekeeper. That is a defect in what the payment-network operator
        // supplied, not an accusation against the originating bank.
        SettlementRequest request = regulatedRequest("TXREF-8");
        registerSignature("TXREF-8");

        when(gatekeeperClient.verify(any())).thenReturn(VerificationResult.builder()
                .signatureValid(false)
                .compliant(false)
                .reason("INVALID_SIGNATURE_MATERIAL")
                .build());

        assertThat(orchestrator.evaluate(request).getReasonCode())
                .isEqualTo("INVALID_SIGNATURE_MATERIAL");
    }

    @Test
    void unknownGatekeeperReasonFallsBackToTheBooleanDerivation() {
        SettlementRequest request = regulatedRequest("TXREF-9");
        registerSignature("TXREF-9");

        when(gatekeeperClient.verify(any())).thenReturn(VerificationResult.builder()
                .signatureValid(true)
                .compliant(false)
                .reason("SOMETHING_ELSE")
                .build());

        assertThat(orchestrator.evaluate(request).getReasonCode())
                .isEqualTo("CERT_NON_COMPLIANT");
    }

    private static SettlementRequest regulatedRequest(String reference) {
        return SettlementRequest.builder()
                .transactionReference(reference)
                .localInstrumentCode("SWISH")
                .debtorIsOrganization(true)
                .creditorIsPrivatePerson(true)
                .build();
    }

    private void registerSignature(String reference) {
        paymentNetworkClient.register(reference, PaymentSignature.builder()
                .digestHex("deadbeef")
                .signatureBase64("AAAA")
                .certSerial("12345")
                .issuerDn("CN=SEB Customer CA")
                .build());
    }
}
