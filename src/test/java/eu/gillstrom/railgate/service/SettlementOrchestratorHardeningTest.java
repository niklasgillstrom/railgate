package eu.gillstrom.railgate.service;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.client.InMemoryPaymentNetworkClient;
import eu.gillstrom.railgate.client.PaymentNetworkClient;
import eu.gillstrom.railgate.client.PaymentNetworkLookup;
import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.model.VerdictSignatureStatus;
import eu.gillstrom.railgate.model.VerificationResult;
import eu.gillstrom.railgate.replay.ReplayGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The orchestrator's handling of the operator lookup outcomes, replay
 * protection and the verdict-signature status.
 */
class SettlementOrchestratorHardeningTest {

    @TempDir
    Path tempDir;

    private InMemoryPaymentNetworkClient paymentNetwork;
    private GatekeeperClient gatekeeper;
    private RegulatedPaymentDetector detector;
    private RailgateAuditLog auditLog;
    private ReplayGuard replayGuard;
    private SettlementOrchestrator orchestrator;

    @BeforeEach
    void setUp() throws Exception {
        paymentNetwork = new InMemoryPaymentNetworkClient();
        gatekeeper = mock(GatekeeperClient.class);
        detector = new RegulatedPaymentDetector();
        var codes = RegulatedPaymentDetector.class.getDeclaredField("regulatedCodes");
        codes.setAccessible(true);
        codes.set(detector, java.util.Set.of("SWISH"));
        auditLog = new RailgateAuditLog();
        replayGuard = ReplayGuard.inMemory();
        orchestrator = new SettlementOrchestrator(detector, paymentNetwork, gatekeeper, auditLog, replayGuard);
    }

    private static SettlementRequest regulated(String reference) {
        return SettlementRequest.builder()
                .transactionReference(reference)
                .localInstrumentCode("SWISH")
                .debtorIsOrganization(true)
                .creditorIsPrivatePerson(true)
                .build();
    }

    private void register(String reference, String payoutInstructionId) {
        paymentNetwork.register(reference, PaymentSignature.builder()
                .digestHex("ab".repeat(64))
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("c0ffee")
                .issuerDn("CN=Example CA,C=SE")
                .payoutInstructionId(payoutInstructionId)
                .build());
    }

    private static VerificationResult allowed(VerdictSignatureStatus status) {
        return VerificationResult.builder()
                .signatureValid(true)
                .compliant(true)
                .auditEntryId("AE-1")
                .verdictSignature(status)
                .build();
    }

    private SettlementOrchestrator withLookup(PaymentNetworkLookup lookup) {
        PaymentNetworkClient client = new PaymentNetworkClient() {
            @Override
            public Optional<PaymentSignature> getSignature(String transactionReference) {
                throw new AssertionError("the orchestrator calls lookup()");
            }

            @Override
            public PaymentNetworkLookup lookup(String transactionReference) {
                return lookup;
            }
        };
        return new SettlementOrchestrator(detector, client, gatekeeper, auditLog, replayGuard);
    }

    // ---------------------------------------------------------------
    // Payment-network lookup outcomes
    // ---------------------------------------------------------------

    @Test
    void anUnauthenticatedOperatorAnswerIsOperatorSignatureInvalidWithoutCallingTheGatekeeper() {
        SettlementDecision decision = withLookup(new PaymentNetworkLookup.OperatorSignatureInvalid(
                "operator signature rejected: the signature does not verify over the canonical bytes"))
                .evaluate(regulated("TX-OP-1"));

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("OPERATOR_SIGNATURE_INVALID");
        assertThat(decision.getMessage()).contains("does not verify");
        verifyNoInteractions(gatekeeper);
        assertThat(auditLog.snapshot()).singleElement()
                .satisfies(entry -> assertThat(entry.reasonCode()).isEqualTo("OPERATOR_SIGNATURE_INVALID"));
        assertThat(replayGuard.isSettled("TX-OP-1")).isFalse();
    }

    @Test
    void anUnreachableOperatorIsNetworkErrorWithoutCallingTheGatekeeper() {
        SettlementDecision decision = withLookup(new PaymentNetworkLookup.Unavailable("operator answered HTTP 503"))
                .evaluate(regulated("TX-OP-2"));

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("NETWORK_ERROR");
        assertThat(decision.getMessage()).contains("payment-network operator");
        verifyNoInteractions(gatekeeper);
    }

    @Test
    void anAbsentAnswerIsStillAuditMissing() {
        SettlementDecision decision = withLookup(new PaymentNetworkLookup.NotFound()).evaluate(regulated("TX-OP-3"));

        assertThat(decision.getReasonCode()).isEqualTo("DORA_32_AUDIT_MISSING");
        verifyNoInteractions(gatekeeper);
    }

    // ---------------------------------------------------------------
    // Replay protection
    // ---------------------------------------------------------------

    @Test
    void anAllowedReferenceIsRefusedTheSecondTimeWithoutCallingTheGatekeeper() {
        register("TX-R-1", null);
        when(gatekeeper.verify(any())).thenReturn(allowed(VerdictSignatureStatus.VERIFIED));

        SettlementDecision first = orchestrator.evaluate(regulated("TX-R-1"));
        SettlementDecision second = orchestrator.evaluate(regulated("TX-R-1"));

        assertThat(first.getReasonCode()).isEqualTo("ALLOWED");
        assertThat(second.isAllow()).isFalse();
        assertThat(second.getReasonCode()).isEqualTo("REFERENCE_ALREADY_SETTLED");
        assertThat(second.getMessage()).contains("already been allowed");
        verify(gatekeeper, times(1)).verify(any());
        assertThat(auditLog.snapshot()).extracting(RailgateAuditLog.AuditEntry::reasonCode)
                .containsExactly("ALLOWED", "REFERENCE_ALREADY_SETTLED");
    }

    @Test
    void anAllowedPayoutInstructionIdIsRefusedUnderAnotherReference() {
        register("TX-R-2", "PAYOUT-7");
        register("TX-R-3", "PAYOUT-7");
        when(gatekeeper.verify(any())).thenReturn(allowed(VerdictSignatureStatus.VERIFIED));

        assertThat(orchestrator.evaluate(regulated("TX-R-2")).getReasonCode()).isEqualTo("ALLOWED");
        SettlementDecision replay = orchestrator.evaluate(regulated("TX-R-3"));

        assertThat(replay.getReasonCode()).isEqualTo("REFERENCE_ALREADY_SETTLED");
        assertThat(replay.getMessage()).contains("payout instruction id");
        verify(gatekeeper, times(1)).verify(any());
    }

    @Test
    void aDeniedSettlementReleasesItsReferenceForResubmission() {
        register("TX-R-4", "PAYOUT-4");
        when(gatekeeper.verify(any()))
                .thenReturn(VerificationResult.builder().signatureValid(false).compliant(false)
                        .reason("NETWORK_ERROR").build())
                .thenReturn(allowed(VerdictSignatureStatus.VERIFIED));

        assertThat(orchestrator.evaluate(regulated("TX-R-4")).getReasonCode()).isEqualTo("NETWORK_ERROR");
        assertThat(replayGuard.isSettled("TX-R-4")).isFalse();
        assertThat(orchestrator.evaluate(regulated("TX-R-4")).getReasonCode()).isEqualTo("ALLOWED");
        assertThat(replayGuard.isSettled("TX-R-4")).isTrue();
        assertThat(replayGuard.isPayoutInstructionSettled("PAYOUT-4")).isTrue();
    }

    @Test
    void aReferenceDeniedBeforeTheReservationIsNotRecorded() {
        register("TX-R-5", null);
        SettlementRequest mismatch = regulated("TX-R-5");
        mismatch.setDeclaredCertSerial("0bad");

        assertThat(orchestrator.evaluate(mismatch).getReasonCode()).isEqualTo("DECLARED_CERT_MISMATCH");
        assertThat(replayGuard.tryReserve("TX-R-5", null)).isInstanceOf(ReplayGuard.Reserved.class);
    }

    @Test
    void aNonRegulatedSettlementIsNeitherCheckedNorRecorded() {
        SettlementRequest privateToPrivate = SettlementRequest.builder()
                .transactionReference("TX-R-6").debtorIsOrganization(false).creditorIsPrivatePerson(true).build();

        assertThat(orchestrator.evaluate(privateToPrivate).getReasonCode()).isEqualTo("NOT_REGULATED");
        assertThat(orchestrator.evaluate(privateToPrivate).getReasonCode()).isEqualTo("NOT_REGULATED");
        assertThat(replayGuard.settledCount()).isZero();
    }

    @Test
    void anExceptionFromTheGatekeeperClientReleasesTheReservation() {
        register("TX-R-7", null);
        when(gatekeeper.verify(any())).thenThrow(new IllegalStateException("boom"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> orchestrator.evaluate(regulated("TX-R-7")))
                .isInstanceOf(IllegalStateException.class);
        assertThat(replayGuard.tryReserve("TX-R-7", null)).isInstanceOf(ReplayGuard.Reserved.class);
    }

    @Test
    void ofTwoConcurrentEvaluationsOfOneReferenceAtMostOneIsAllowed() throws Exception {
        register("TX-RACE", "PAYOUT-RACE");
        int evaluations = 8;
        CountDownLatch insideGatekeeper = new CountDownLatch(1);
        CountDownLatch othersDone = new CountDownLatch(evaluations - 1);
        when(gatekeeper.verify(any())).thenAnswer(invocation -> {
            // Hold the first evaluation inside the gatekeeper call until every
            // other evaluation has finished, so they all overlap with it.
            insideGatekeeper.countDown();
            othersDone.await(10, TimeUnit.SECONDS);
            return allowed(VerdictSignatureStatus.VERIFIED);
        });

        ExecutorService pool = Executors.newFixedThreadPool(evaluations);
        List<Future<SettlementDecision>> futures = new ArrayList<>();
        try {
            futures.add(pool.submit(() -> orchestrator.evaluate(regulated("TX-RACE"))));
            assertThat(insideGatekeeper.await(10, TimeUnit.SECONDS)).isTrue();
            for (int i = 1; i < evaluations; i++) {
                futures.add(pool.submit(() -> {
                    try {
                        return orchestrator.evaluate(regulated("TX-RACE"));
                    } finally {
                        othersDone.countDown();
                    }
                }));
            }
            List<SettlementDecision> decisions = new ArrayList<>();
            for (Future<SettlementDecision> future : futures) {
                decisions.add(future.get(20, TimeUnit.SECONDS));
            }

            assertThat(decisions).filteredOn(SettlementDecision::isAllow).hasSize(1);
            assertThat(decisions).filteredOn(d -> !d.isAllow())
                    .hasSize(evaluations - 1)
                    .allSatisfy(d -> {
                        assertThat(d.getReasonCode()).isEqualTo("REFERENCE_ALREADY_SETTLED");
                        assertThat(d.getMessage()).contains("has not finished");
                    });
            verify(gatekeeper, times(1)).verify(any());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void ofManyUnsynchronisedEvaluationsOfOneReferenceAtMostOneIsAllowed() throws Exception {
        register("TX-STORM", null);
        when(gatekeeper.verify(any())).thenReturn(allowed(VerdictSignatureStatus.VERIFIED));
        int evaluations = 64;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<SettlementDecision>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < evaluations; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return orchestrator.evaluate(regulated("TX-STORM"));
                }));
            }
            start.countDown();
            int allowedCount = 0;
            for (Future<SettlementDecision> future : futures) {
                SettlementDecision decision = future.get(20, TimeUnit.SECONDS);
                if (decision.isAllow()) {
                    allowedCount++;
                } else {
                    assertThat(decision.getReasonCode()).isEqualTo("REFERENCE_ALREADY_SETTLED");
                }
            }
            assertThat(allowedCount).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void anAllowThatCannotBeJournalledIsDeniedAndReleased() {
        ReplayGuard journalled = new ReplayGuard(tempDir.resolve("replay.journal").toString());
        journalled.close(); // every append now fails
        SettlementOrchestrator failing = new SettlementOrchestrator(detector, paymentNetwork, gatekeeper, auditLog,
                journalled);
        register("TX-J-1", null);
        when(gatekeeper.verify(any())).thenReturn(allowed(VerdictSignatureStatus.VERIFIED));

        SettlementDecision decision = failing.evaluate(regulated("TX-J-1"));

        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("INTERNAL_ERROR");
        assertThat(decision.getMessage()).contains("replay journal");
        assertThat(journalled.isSettled("TX-J-1")).isFalse();
        assertThat(journalled.tryReserve("TX-J-1", null)).isInstanceOf(ReplayGuard.Reserved.class);
    }

    @Test
    void theReplayCheckRunsAfterTheLookupAndBeforeTheGatekeeper() {
        register("TX-R-8", null);
        ReplayGuard.Attempt held = replayGuard.tryReserve("TX-R-8", null);
        assertThat(held).isInstanceOf(ReplayGuard.Reserved.class);

        SettlementDecision decision = orchestrator.evaluate(regulated("TX-R-8"));

        assertThat(decision.getReasonCode()).isEqualTo("REFERENCE_ALREADY_SETTLED");
        verify(gatekeeper, never()).verify(any());
    }

    // ---------------------------------------------------------------
    // Verdict signature
    // ---------------------------------------------------------------

    @Test
    void theVerdictSignatureStatusIsRecordedInTheDecisionAndTheAuditLog() {
        register("TX-V-1", null);
        register("TX-V-2", null);
        register("TX-V-3", null);
        when(gatekeeper.verify(any()))
                .thenReturn(allowed(VerdictSignatureStatus.VERIFIED))
                .thenReturn(allowed(VerdictSignatureStatus.UNSIGNED))
                .thenReturn(VerificationResult.builder().signatureValid(false).compliant(false)
                        .reason("CERT_NOT_FOUND").verdictSignature(VerdictSignatureStatus.VERIFIED).build());

        assertThat(orchestrator.evaluate(regulated("TX-V-1")).getVerdictSignature())
                .isEqualTo(VerdictSignatureStatus.VERIFIED);
        assertThat(orchestrator.evaluate(regulated("TX-V-2")).getVerdictSignature())
                .isEqualTo(VerdictSignatureStatus.UNSIGNED);
        assertThat(orchestrator.evaluate(regulated("TX-V-3")).getVerdictSignature())
                .isEqualTo(VerdictSignatureStatus.VERIFIED);
        assertThat(auditLog.snapshot()).extracting(RailgateAuditLog.AuditEntry::verdictSignature)
                .containsExactly(VerdictSignatureStatus.VERIFIED, VerdictSignatureStatus.UNSIGNED,
                        VerdictSignatureStatus.VERIFIED);
    }

    @Test
    void verdictSignatureFailuresArePassedThroughAndReleaseTheReference() {
        register("TX-V-4", null);
        when(gatekeeper.verify(any()))
                .thenReturn(VerificationResult.builder().signatureValid(false).compliant(false)
                        .reason("VERDICT_SIGNATURE_INVALID").verdictSignature(VerdictSignatureStatus.INVALID).build())
                .thenReturn(VerificationResult.builder().signatureValid(false).compliant(false)
                        .reason("VERDICT_STALE").verdictSignature(VerdictSignatureStatus.INVALID).build());

        SettlementDecision invalid = orchestrator.evaluate(regulated("TX-V-4"));
        SettlementDecision stale = orchestrator.evaluate(regulated("TX-V-4"));

        assertThat(invalid.getReasonCode()).isEqualTo("VERDICT_SIGNATURE_INVALID");
        assertThat(invalid.getVerdictSignature()).isEqualTo(VerdictSignatureStatus.INVALID);
        assertThat(stale.getReasonCode()).isEqualTo("VERDICT_STALE");
        assertThat(replayGuard.isSettled("TX-V-4")).isFalse();
    }
}
