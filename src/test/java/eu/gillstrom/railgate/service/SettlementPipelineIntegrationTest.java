package eu.gillstrom.railgate.service;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.client.HttpPaymentNetworkClient;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.model.VerdictSignatureStatus;
import eu.gillstrom.railgate.replay.ReplayGuard;
import eu.gillstrom.railgate.testsupport.ReferenceGatekeeper;
import eu.gillstrom.railgate.testsupport.ReferenceOperator;
import eu.gillstrom.railgate.testsupport.TestKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ssl.SslBundles;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The three hardening measures together, over real HTTP: a reference
 * operator signing {@code op1}, a reference gatekeeper signing {@code sv1},
 * and a replay journal on disk, each built with its production constructor.
 */
class SettlementPipelineIntegrationTest {

    private static final String DIGEST = "5e".repeat(64);

    @TempDir
    Path tempDir;

    private ReferenceOperator operator;
    private ReferenceGatekeeper gatekeeper;
    private RailgateAuditLog auditLog;
    private ReplayGuard replayGuard;
    private SettlementOrchestrator orchestrator;

    @BeforeEach
    void setUp() throws Exception {
        operator = ReferenceOperator.start();
        gatekeeper = ReferenceGatekeeper.start();
        auditLog = new RailgateAuditLog();
        replayGuard = new ReplayGuard(tempDir.resolve("replay.journal").toString());
        orchestrator = orchestrator(replayGuard);
    }

    @AfterEach
    void tearDown() {
        operator.close();
        gatekeeper.close();
        replayGuard.close();
    }

    private SettlementOrchestrator orchestrator(ReplayGuard guard) throws Exception {
        @SuppressWarnings("unchecked")
        ObjectProvider<SslBundles> noBundles = mock(ObjectProvider.class);
        HttpPaymentNetworkClient paymentNetwork = new HttpPaymentNetworkClient(operator.baseUrl(), true, "",
                Duration.ofSeconds(2), Duration.ofSeconds(5), "classpath:" + TestKeys.OPERATOR_CERT, noBundles);
        GatekeeperClient gatekeeperClient = new GatekeeperClient(gatekeeper.baseUrl(), Duration.ofSeconds(2),
                Duration.ofSeconds(5), true, "", noBundles, "classpath:" + TestKeys.GATEKEEPER_CERT, true,
                Duration.ofSeconds(60));
        RegulatedPaymentDetector detector = new RegulatedPaymentDetector();
        var codes = RegulatedPaymentDetector.class.getDeclaredField("regulatedCodes");
        codes.setAccessible(true);
        codes.set(detector, Set.of("SWISH"));
        return new SettlementOrchestrator(detector, paymentNetwork, gatekeeperClient, auditLog, guard);
    }

    private static SettlementRequest regulated(String reference) {
        return SettlementRequest.builder()
                .transactionReference(reference)
                .localInstrumentCode("SWISH")
                .debtorIsOrganization(true)
                .creditorIsPrivatePerson(true)
                .build();
    }

    private void payout(String reference, String payoutInstructionId) {
        operator.register(new ReferenceOperator.Artefacts(reference, payoutInstructionId, "0x00C0FFEE",
                "CN=Example CA, O=Example Bank, C=SE", DIGEST, "c2lnbmF0dXJl", "2026-10-30T12:00:00Z"));
    }

    @Test
    void aSignedPayoutIsAllowedOnceAndItsReplaysAreRefusedAcrossARestart() throws Exception {
        payout("UETR-PIPE-1", "PAYOUT-PIPE-1");
        payout("UETR-PIPE-2", "PAYOUT-PIPE-1"); // the same payout under a second reference

        SettlementDecision allowed = orchestrator.evaluate(regulated("UETR-PIPE-1"));
        assertThat(allowed.isAllow()).isTrue();
        assertThat(allowed.getReasonCode()).isEqualTo("ALLOWED");
        assertThat(allowed.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.VERIFIED);
        assertThat(allowed.getAuditEntryId()).isEqualTo("AE-REF");

        assertThat(orchestrator.evaluate(regulated("UETR-PIPE-1")).getReasonCode())
                .isEqualTo("REFERENCE_ALREADY_SETTLED");
        assertThat(orchestrator.evaluate(regulated("UETR-PIPE-2")).getReasonCode())
                .isEqualTo("REFERENCE_ALREADY_SETTLED");
        assertThat(gatekeeper.calls()).isEqualTo(1);

        replayGuard.close();
        replayGuard = new ReplayGuard(tempDir.resolve("replay.journal").toString());
        SettlementOrchestrator restarted = orchestrator(replayGuard);

        assertThat(restarted.evaluate(regulated("UETR-PIPE-1")).getReasonCode()).isEqualTo("REFERENCE_ALREADY_SETTLED");
        assertThat(restarted.evaluate(regulated("UETR-PIPE-2")).getReasonCode()).isEqualTo("REFERENCE_ALREADY_SETTLED");
        assertThat(gatekeeper.calls()).isEqualTo(1);
    }

    @Test
    void anOperatorAnswerSignedWithAnUntrustedKeyNeverReachesTheGatekeeper() {
        payout("UETR-PIPE-3", "PAYOUT-PIPE-3");
        operator.signingKey = TestKeys.privateKey(TestKeys.UNTRUSTED_KEY);
        operator.signingCertificate = TestKeys.certificate(TestKeys.UNTRUSTED_CERT);

        SettlementDecision decision = orchestrator.evaluate(regulated("UETR-PIPE-3"));

        assertThat(decision.getReasonCode()).isEqualTo("OPERATOR_SIGNATURE_INVALID");
        assertThat(gatekeeper.calls()).isZero();
        assertThat(replayGuard.settledCount()).isZero();
    }

    @Test
    void aSignedGatekeeperDenialIsPassedThroughAndTheReferenceStaysFree() {
        payout("UETR-PIPE-4", "PAYOUT-PIPE-4");
        gatekeeper.signatureValid = false;
        gatekeeper.compliant = false;
        gatekeeper.reason = "CERT_NOT_FOUND";

        SettlementDecision denied = orchestrator.evaluate(regulated("UETR-PIPE-4"));
        gatekeeper.signatureValid = true;
        gatekeeper.compliant = true;
        gatekeeper.reason = "OK";
        SettlementDecision resubmitted = orchestrator.evaluate(regulated("UETR-PIPE-4"));

        assertThat(denied.getReasonCode()).isEqualTo("CERT_NOT_FOUND");
        assertThat(denied.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.VERIFIED);
        assertThat(resubmitted.getReasonCode()).isEqualTo("ALLOWED");
    }

    @Test
    void anUnknownReferenceAtTheOperatorIsAuditMissing() {
        assertThat(orchestrator.evaluate(regulated("UETR-PIPE-UNKNOWN")).getReasonCode())
                .isEqualTo("DORA_32_AUDIT_MISSING");
        assertThat(gatekeeper.calls()).isZero();
    }
}
