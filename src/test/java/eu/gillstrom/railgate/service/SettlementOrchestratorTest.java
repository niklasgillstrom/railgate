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
}
