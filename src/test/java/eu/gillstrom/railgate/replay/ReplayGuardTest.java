package eu.gillstrom.railgate.replay;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReplayGuardTest {

    @TempDir
    Path tempDir;

    private static ReplayGuard.Reservation reserve(ReplayGuard guard, String reference, String payoutId) {
        ReplayGuard.Attempt attempt = guard.tryReserve(reference, payoutId);
        assertThat(attempt).isInstanceOf(ReplayGuard.Reserved.class);
        return ((ReplayGuard.Reserved) attempt).reservation();
    }

    @Test
    void aCommittedReferenceIsRefusedAfterwards() {
        ReplayGuard guard = ReplayGuard.inMemory();
        guard.commit(reserve(guard, "TX-1", null));

        assertThat(guard.tryReserve("TX-1", null))
                .isEqualTo(new ReplayGuard.Refused(ReplayGuard.Key.TRANSACTION_REFERENCE, false));
        assertThat(guard.isSettled("TX-1")).isTrue();
        assertThat(guard.isJournalled()).isFalse();
    }

    @Test
    void aCommittedPayoutInstructionIdIsRefusedUnderAnyReference() {
        ReplayGuard guard = ReplayGuard.inMemory();
        guard.commit(reserve(guard, "TX-1", "PAYOUT-1"));

        assertThat(guard.tryReserve("TX-2", "PAYOUT-1"))
                .isEqualTo(new ReplayGuard.Refused(ReplayGuard.Key.PAYOUT_INSTRUCTION_ID, false));
        assertThat(guard.isPayoutInstructionSettled("PAYOUT-1")).isTrue();
        assertThat(guard.isSettled("TX-2")).as("a refusal claims nothing").isFalse();
        assertThat(guard.tryReserve("TX-2", "PAYOUT-2")).isInstanceOf(ReplayGuard.Reserved.class);
    }

    @Test
    void aHeldReservationRefusesBothKeysUntilReleasedAndThenFreesBoth() {
        ReplayGuard guard = ReplayGuard.inMemory();
        ReplayGuard.Reservation held = reserve(guard, "TX-1", "PAYOUT-1");

        assertThat(guard.tryReserve("TX-1", "PAYOUT-9"))
                .isEqualTo(new ReplayGuard.Refused(ReplayGuard.Key.TRANSACTION_REFERENCE, true));
        assertThat(guard.tryReserve("TX-9", "PAYOUT-1"))
                .isEqualTo(new ReplayGuard.Refused(ReplayGuard.Key.PAYOUT_INSTRUCTION_ID, true));

        guard.release(held);
        guard.release(held); // idempotent

        assertThat(guard.isSettled("TX-1")).isFalse();
        ReplayGuard.Reservation again = reserve(guard, "TX-1", "PAYOUT-1");
        guard.commit(again);
        guard.release(again); // no effect after commit
        assertThat(guard.isSettled("TX-1")).isTrue();
        assertThatThrownBy(() -> guard.commit(again)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void ofManyConcurrentAttemptsOnOneReferenceExactlyOneCommits() throws Exception {
        ReplayGuard guard = new ReplayGuard(tempDir.resolve("replay.journal").toString());
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger committed = new AtomicInteger();
        AtomicInteger refused = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                String payoutId = "PAYOUT-" + i; // the reference alone must decide
                futures.add(pool.submit(() -> {
                    start.await();
                    for (int round = 0; round < 50; round++) {
                        ReplayGuard.Attempt attempt = guard.tryReserve("TX-RACE", payoutId + "-" + round);
                        if (attempt instanceof ReplayGuard.Reserved reserved) {
                            guard.commit(reserved.reservation());
                            committed.incrementAndGet();
                        } else {
                            refused.incrementAndGet();
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
            guard.close();
        }

        assertThat(committed.get()).isEqualTo(1);
        assertThat(refused.get()).isEqualTo(threads * 50 - 1);
        assertThat(Files.readAllLines(tempDir.resolve("replay.journal"))).hasSize(1);
    }

    @Test
    void theJournalIsReplayedAfterARestart() throws Exception {
        Path journal = tempDir.resolve("replay.journal");
        ReplayGuard first = new ReplayGuard(journal.toString());
        first.commit(reserve(first, "TX-1", "PAYOUT-1"));
        first.commit(reserve(first, "TX-2", null));
        first.release(reserve(first, "TX-DENIED", "PAYOUT-DENIED"));
        first.close();

        ReplayGuard second = new ReplayGuard(journal.toString());
        try {
            assertThat(second.isJournalled()).isTrue();
            assertThat(second.settledCount()).isEqualTo(2);
            assertThat(second.tryReserve("TX-1", null))
                    .isEqualTo(new ReplayGuard.Refused(ReplayGuard.Key.TRANSACTION_REFERENCE, false));
            assertThat(second.tryReserve("TX-3", "PAYOUT-1"))
                    .isEqualTo(new ReplayGuard.Refused(ReplayGuard.Key.PAYOUT_INSTRUCTION_ID, false));
            assertThat(second.tryReserve("TX-2", null)).isInstanceOf(ReplayGuard.Refused.class);
            assertThat(second.tryReserve("TX-DENIED", "PAYOUT-DENIED"))
                    .as("a released reservation was never journalled").isInstanceOf(ReplayGuard.Reserved.class);
        } finally {
            second.close();
        }
    }

    @Test
    void referencesWithSeparatorsAndNonAsciiCharactersSurviveTheJournal() throws Exception {
        Path journal = tempDir.resolve("replay.journal");
        String awkward = "A\tB\nC%25 +Å|";
        ReplayGuard first = new ReplayGuard(journal.toString());
        first.commit(reserve(first, awkward, "P\tQ"));
        first.close();

        List<String> lines = Files.readAllLines(journal, StandardCharsets.US_ASCII);
        assertThat(lines).hasSize(1);
        assertThat(lines.get(0)).startsWith("v1\t").matches("v1\t[^\t]+\t[^\t]+\t\\S+");

        ReplayGuard second = new ReplayGuard(journal.toString());
        try {
            assertThat(second.isSettled(awkward)).isTrue();
            assertThat(second.isPayoutInstructionSettled("P\tQ")).isTrue();
        } finally {
            second.close();
        }
    }

    @Test
    void anIncompleteLastRecordIsTruncatedAtStartUp() throws Exception {
        Path journal = tempDir.resolve("replay.journal");
        ReplayGuard first = new ReplayGuard(journal.toString());
        first.commit(reserve(first, "TX-1", null));
        first.close();
        String complete = Files.readString(journal, StandardCharsets.US_ASCII);
        Files.writeString(journal, complete + "v1\tTX-TORN\t\t2026-10-30T12:", StandardCharsets.US_ASCII);

        ReplayGuard second = new ReplayGuard(journal.toString());
        try {
            assertThat(Files.readString(journal, StandardCharsets.US_ASCII)).isEqualTo(complete);
            assertThat(second.isSettled("TX-1")).isTrue();
            assertThat(second.isSettled("TX-TORN")).isFalse();
            second.commit(reserve(second, "TX-2", null));
        } finally {
            second.close();
        }
        assertThat(Files.readAllLines(journal)).hasSize(2);
    }

    @Test
    void aJournalWithAnUnreadableLineIsAStartUpFailure() throws Exception {
        Path journal = tempDir.resolve("replay.journal");
        for (String bad : List.of("garbage\n", "v1\tTX\t\n", "v2\tTX\t\t2026-10-30T12:00:00Z\n",
                "v1\t\t\t2026-10-30T12:00:00Z\n", "v1\tTX\t\tnot-a-time\n", "v1\tTX%ZZ\t\t2026-10-30T12:00:00Z\n",
                "\n")) {
            Files.writeString(journal, "v1\tTX-OK\t\t2026-10-30T12:00:00Z\n" + bad, StandardCharsets.UTF_8);
            assertThatThrownBy(() -> new ReplayGuard(journal.toString())).as(bad)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("line 2");
        }
    }

    @Test
    void aJournalAlreadyOpenIsRefused() {
        Path journal = tempDir.resolve("replay.journal");
        ReplayGuard first = new ReplayGuard(journal.toString());
        try {
            assertThatThrownBy(() -> new ReplayGuard(journal.toString()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("already open");
        } finally {
            first.close();
        }
        new ReplayGuard(journal.toString()).close();
    }

    @Test
    void aJournalThatCannotBeOpenedIsAStartUpFailure() {
        assertThatThrownBy(() -> new ReplayGuard(tempDir.resolve("missing-dir").resolve("replay.journal").toString()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("railgate.replay.path");
    }

    @Test
    void aCommitThatCannotBeJournalledFailsAndLeavesTheReservationToRelease() {
        ReplayGuard guard = new ReplayGuard(tempDir.resolve("replay.journal").toString());
        ReplayGuard.Reservation reservation = reserve(guard, "TX-1", "PAYOUT-1");
        guard.close();

        assertThatThrownBy(() -> guard.commit(reservation)).isInstanceOf(ReplayJournalException.class);
        assertThat(guard.isSettled("TX-1")).isFalse();
        assertThat(guard.tryReserve("TX-1", null))
                .isEqualTo(new ReplayGuard.Refused(ReplayGuard.Key.TRANSACTION_REFERENCE, true));
        guard.release(reservation);
        assertThat(guard.tryReserve("TX-1", null)).isInstanceOf(ReplayGuard.Reserved.class);
    }
}
