package eu.gillstrom.railgate.replay;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What makes the replay record durable and what happens when the disk fails:
 * every commit and every truncation is synced, a new journal's directory is
 * synced once, a journal that fails while opening is closed and its lock
 * released, and the journal's lines are restricted to printable ASCII.
 */
class ReplayGuardDurabilityTest {

    private static final String LINE_TIME = "\t2026-10-30T12:00:00Z\n";

    @TempDir
    Path tempDir;

    private final List<RecordingChannel> journals = new ArrayList<>();
    private final List<RecordingChannel> directories = new ArrayList<>();
    private IOException failRead;
    private IOException failWrite;
    private ListAppender<ILoggingEvent> logs;

    private final ReplayGuard.ChannelOpener opener = (Path path, OpenOption... options) -> {
        RecordingChannel channel = new RecordingChannel(FileChannel.open(path, options));
        if (Files.isDirectory(path)) {
            directories.add(channel);
        } else {
            channel.failRead = failRead;
            channel.failWrite = failWrite;
            journals.add(channel);
        }
        return channel;
    };

    @BeforeEach
    void captureLogs() {
        logs = new ListAppender<>();
        logs.start();
        ((Logger) LoggerFactory.getLogger(ReplayGuard.class)).addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        ((Logger) LoggerFactory.getLogger(ReplayGuard.class)).detachAppender(logs);
    }

    private static ReplayGuard.Reservation reserve(ReplayGuard guard, String reference, String payoutId) {
        ReplayGuard.Attempt attempt = guard.tryReserve(reference, payoutId);
        assertThat(attempt).isInstanceOf(ReplayGuard.Reserved.class);
        return ((ReplayGuard.Reserved) attempt).reservation();
    }

    private Path journal() {
        return tempDir.resolve("replay.journal");
    }

    private List<String> messages(Level level) {
        return logs.list.stream().filter(e -> e.getLevel() == level).map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Test
    void aNewJournalSyncsItsDirectoryOnceAndAnExistingJournalDoesNot() {
        new ReplayGuard(journal().toString(), opener).close();
        assertThat(directories).hasSize(1);
        assertThat(directories.get(0).forces).isEqualTo(1);

        new ReplayGuard(journal().toString(), opener).close();
        assertThat(directories).as("no directory sync for a journal that already existed").hasSize(1);
    }

    @Test
    void everyCommitIsSyncedAndACleanJournalIsNeitherSyncedNorTruncatedOnOpening() throws Exception {
        ReplayGuard guard = new ReplayGuard(journal().toString(), opener);
        guard.commit(reserve(guard, "TX-1", "PAYOUT-1"));
        assertThat(journals.get(0).forces).isEqualTo(1);
        guard.commit(reserve(guard, "TX-2", null));
        assertThat(journals.get(0).forces).isEqualTo(2);
        guard.close();
        long size = Files.size(journal());

        ReplayGuard reopened = new ReplayGuard(journal().toString(), opener);
        try {
            assertThat(journals.get(1).forces).isZero();
            assertThat(Files.size(journal())).isEqualTo(size);
            assertThat(messages(Level.WARN)).isEmpty();
            assertThat(messages(Level.INFO)).anyMatch(m -> m.endsWith(
                    "opened: 2 allowed settlement(s) recorded (1 payout instruction id(s))"));
        } finally {
            reopened.close();
        }
    }

    @Test
    void truncatingAnIncompleteRecordIsSyncedAndReported() throws Exception {
        Files.writeString(journal(), "v1\tTX-1\t" + LINE_TIME + "v1\tTX-TO", StandardCharsets.US_ASCII);

        ReplayGuard guard = new ReplayGuard(journal().toString(), opener);
        try {
            assertThat(journals.get(0).forces).isEqualTo(1);
            assertThat(messages(Level.WARN)).singleElement().asString()
                    .contains("ends in an incomplete record (8 byte(s) after the last line feed)");
            assertThat(guard.settledCount()).isEqualTo(1);
        } finally {
            guard.close();
        }
    }

    @Test
    void aJournalLargerThanOneReadIsReplayedWhole() throws Exception {
        StringBuilder text = new StringBuilder();
        int records = 3_000;
        for (int i = 0; i < records; i++) {
            text.append("v1\tTX-").append(i).append('\t').append(LINE_TIME);
        }
        assertThat(text.length()).as("more than one 64 KiB chunk").isGreaterThan(64 * 1024);
        Files.writeString(journal(), text, StandardCharsets.US_ASCII);

        ReplayGuard guard = new ReplayGuard(journal().toString(), opener);
        try {
            assertThat(guard.settledCount()).isEqualTo(records);
            assertThat(guard.isSettled("TX-" + (records - 1))).isTrue();
        } finally {
            guard.close();
        }
    }

    @Test
    void aJournalThatFailsWhileOpeningIsClosedAndItsLockReleased() throws Exception {
        Files.writeString(journal(), "v1\tTX-1\t" + LINE_TIME, StandardCharsets.US_ASCII);
        failRead = new IOException("disk read failed");

        assertThatThrownBy(() -> new ReplayGuard(journal().toString(), opener))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageEndingWith("could not be opened: IOException: disk read failed");
        assertThat(journals.get(0).isOpen()).isFalse();

        new ReplayGuard(journal().toString()).close();
    }

    @Test
    void aFailedWriteDeniesEveryLaterCommitUntilRestartAndAClosedJournalSaysSo() {
        failWrite = new IOException("disk full");
        ReplayGuard guard = new ReplayGuard(journal().toString(), opener);
        assertThatThrownBy(() -> guard.commit(reserve(guard, "TX-1", null)))
                .isInstanceOf(ReplayJournalException.class)
                .hasMessageEndingWith(" could not be written; the record was removed again");
        assertThatThrownBy(() -> guard.commit(reserve(guard, "TX-2", null)))
                .isInstanceOf(ReplayJournalException.class)
                .hasMessageEndingWith(" failed earlier; restart railgate to recover it");
        guard.close();
        assertThatThrownBy(() -> guard.commit(reserve(guard, "TX-3", null)))
                .isInstanceOf(ReplayJournalException.class)
                .hasMessageEndingWith(" is closed");
    }

    /**
     * The settlement whose record could not be synced is denied. Until 1.7.0
     * the complete line stayed in the file, and after a restart the denied
     * settlement counted as allowed.
     */
    @Test
    void aRecordWhoseSyncFailedIsCutOffAgainAndIsNotSettledAfterARestart() throws Exception {
        ReplayGuard guard = new ReplayGuard(journal().toString(), opener);
        guard.commit(reserve(guard, "TX-KEPT", "PAYOUT-KEPT"));
        long sizeBefore = Files.size(journal());
        RecordingChannel channel = journals.get(0);
        int forcesBefore = channel.forces;

        channel.failNextForce = new IOException("fsync failed");
        ReplayGuard.Reservation denied = reserve(guard, "TX-DENIED", "PAYOUT-DENIED");
        assertThatThrownBy(() -> guard.commit(denied))
                .isInstanceOf(ReplayJournalException.class)
                .hasMessage("replay journal " + journal() + " could not be written; the record was removed again")
                .hasCauseInstanceOf(IOException.class);

        assertThat(channel.truncations).isEqualTo(1);
        assertThat(channel.forces).as("the truncation is synced").isEqualTo(forcesBefore + 1);
        assertThat(Files.size(journal())).isEqualTo(sizeBefore);
        assertThat(guard.isSettled("TX-DENIED")).isFalse();
        assertThat(messages(Level.ERROR)).singleElement().asString()
                .contains("could not be written; the record was removed again.");
        guard.release(denied);
        guard.close();

        try (ReplayGuard restarted = new ReplayGuard(journal().toString())) {
            assertThat(restarted.isSettled("TX-KEPT")).isTrue();
            assertThat(restarted.isSettled("TX-DENIED")).as("a denied settlement is not allowed by a restart").isFalse();
            assertThat(restarted.isPayoutInstructionSettled("PAYOUT-DENIED")).isFalse();
            assertThat(restarted.settledCount()).isEqualTo(1);
        }
    }

    @Test
    void theFirstRecordOfANewJournalIsCutOffTheSameWay() throws Exception {
        ReplayGuard guard = new ReplayGuard(journal().toString(), opener);
        journals.get(0).failNextForce = new IOException("fsync failed");

        assertThatThrownBy(() -> guard.commit(reserve(guard, "TX-FIRST", null)))
                .hasMessageEndingWith("the record was removed again");

        assertThat(Files.size(journal())).isZero();
        guard.close();
    }

    @Test
    void whenTheRecordCannotBeCutOffEitherTheErrorSaysWhereToCutTheFile() throws Exception {
        ReplayGuard guard = new ReplayGuard(journal().toString(), opener);
        guard.commit(reserve(guard, "TX-KEPT", null));
        long sizeBefore = Files.size(journal());
        RecordingChannel channel = journals.get(0);

        channel.failNextForce = new IOException("fsync failed");
        channel.failTruncate = new IOException("read-only file system");
        String state = "THE RECORD MAY STILL BE IN THE FILE: truncate it to " + sizeBefore
                + " bytes before restarting, or the denied settlement counts as allowed";
        assertThatThrownBy(() -> guard.commit(reserve(guard, "TX-DENIED", null)))
                .isInstanceOf(ReplayJournalException.class)
                .hasMessage("replay journal " + journal() + " could not be written; " + state);

        assertThat(messages(Level.ERROR)).singleElement().asString().contains(state);
        assertThat(Files.size(journal())).as("the record is still there").isGreaterThan(sizeBefore);
        guard.close();
    }

    @Test
    void journalLinesArePrintableAsciiAndTab() throws Exception {
        Files.writeString(journal(), "v1\tA~B C\t~" + LINE_TIME, StandardCharsets.US_ASCII);
        ReplayGuard guard = new ReplayGuard(journal().toString(), opener);
        try {
            assertThat(guard.isSettled("A~B C")).as("'~' (0x7E) and ' ' (0x20) are the bounds").isTrue();
            assertThat(guard.isPayoutInstructionSettled("~")).isTrue();
        } finally {
            guard.close();
        }

        for (String bad : List.of("A\u007FB", "A\u001FB", "AéB")) {
            Files.write(journal(), ("v1\t" + bad + "\t" + LINE_TIME).getBytes(StandardCharsets.ISO_8859_1));
            assertThatThrownBy(() -> new ReplayGuard(journal().toString()))
                    .as("byte 0x%02X", (int) bad.charAt(1))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("line 1 cannot be parsed");
        }
    }

    @Test
    void aReservationNamesWhatItHoldsAndOnlyCommittedPayoutIdsAreSettled() {
        ReplayGuard guard = ReplayGuard.inMemory();
        ReplayGuard.Reservation reservation = reserve(guard, "TX-1", "PAYOUT-1");
        assertThat(reservation.transactionReference()).isEqualTo("TX-1");
        assertThat(reservation.payoutInstructionId()).isEqualTo("PAYOUT-1");
        assertThat(guard.isPayoutInstructionSettled("PAYOUT-1")).as("held, not committed").isFalse();
        guard.commit(reservation);
        assertThat(guard.isPayoutInstructionSettled("PAYOUT-1")).isTrue();
        assertThat(guard.isPayoutInstructionSettled("PAYOUT-2")).isFalse();
    }
}
