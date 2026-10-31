package eu.gillstrom.railgate.replay;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.Set;

/**
 * Records which settlements railgate has allowed, so that the artefacts of
 * one genuinely signed payout cannot be used to allow a second settlement.
 *
 * <p><b>What is recorded.</b> The transaction reference of every settlement
 * the orchestrator allows with {@code ALLOWED}, and the payment-network
 * operator's {@code payoutInstructionId} when the artefacts carried one
 * ({@code http} payment-network mode). A later settlement whose reference, or
 * whose payout instruction id, is in the record is refused. Settlements passed
 * through as {@code NOT_REGULATED} are neither checked nor recorded.</p>
 *
 * <p><b>Reserve, then commit or release.</b> {@link #tryReserve} claims both
 * keys atomically before the gatekeeper is called. Of two concurrent
 * evaluations with the same reference or payout instruction id, only one can
 * hold the reservation; the other is refused with {@code inProgress=true}.
 * {@link #commit} makes the reservation permanent once the settlement is
 * allowed; {@link #release} drops it when the settlement is denied, so a
 * resubmission after a deny is evaluated afresh.</p>
 *
 * <p><b>Journal.</b> With {@code railgate.replay.path} set, every commit
 * appends one line to that file and calls {@code FileChannel.force(true)}
 * before returning, and the record is rebuilt from the file at start-up. With
 * it unset, the record is held in memory only and is lost on restart. Line
 * format, US-ASCII:</p>
 * <pre>
 * v1 TAB urlencode(transactionReference) TAB urlencode(payoutInstructionId or "") TAB Instant.toString() LF
 * </pre>
 * <p>({@code URLEncoder}, UTF-8). At start-up an incomplete last line — one
 * not ending in LF, left by a write that failed or was interrupted, whose
 * settlement was therefore never allowed — is truncated away with a WARN. Any
 * other line that cannot be parsed stops start-up. The file is held with an
 * exclusive {@link FileLock} while railgate runs, so a second railgate process
 * cannot open the same journal. After a write to the journal fails, every
 * further commit fails too, until restart, so that no record is appended after
 * a partial one.</p>
 *
 * <p><b>Limits.</b> The record is local to one railgate instance: instances
 * that do not share a journal do not see each other's settlements, and a
 * shared network file is not a supported way to share one. Nothing is ever
 * removed: a reference allowed by railgate whose settlement then fails
 * downstream cannot be allowed again, and the journal and the in-memory sets
 * grow with every allowed settlement.</p>
 */
@Component
public class ReplayGuard implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(ReplayGuard.class);

    static final String RECORD_VERSION = "v1";

    /** Which identifier of a refused settlement was already taken. */
    public enum Key {
        TRANSACTION_REFERENCE,
        PAYOUT_INSTRUCTION_ID
    }

    /** Outcome of {@link #tryReserve}. */
    public sealed interface Attempt {
    }

    /** Both identifiers are now held by the caller. */
    public record Reserved(Reservation reservation) implements Attempt {
    }

    /**
     * An identifier is already taken: allowed earlier ({@code inProgress=false})
     * or held by an evaluation that has not finished ({@code inProgress=true}).
     */
    public record Refused(Key key, boolean inProgress) implements Attempt {
    }

    /** A claim on a reference and an optional payout instruction id. */
    public static final class Reservation {
        private final String transactionReference;
        private final String payoutInstructionId;
        private boolean finished;

        private Reservation(String transactionReference, String payoutInstructionId) {
            this.transactionReference = transactionReference;
            this.payoutInstructionId = payoutInstructionId;
        }

        public String transactionReference() {
            return transactionReference;
        }

        public String payoutInstructionId() {
            return payoutInstructionId;
        }
    }

    private final Object lock = new Object();
    private final Set<String> settledReferences = new HashSet<>();
    private final Set<String> settledPayoutInstructionIds = new HashSet<>();
    private final Set<String> reservedReferences = new HashSet<>();
    private final Set<String> reservedPayoutInstructionIds = new HashSet<>();

    /** Opens a file channel; tests substitute one that records syncs or fails. */
    @FunctionalInterface
    interface ChannelOpener {
        FileChannel open(Path path, OpenOption... options) throws IOException;
    }

    private final Object journalLock = new Object();
    private final ChannelOpener opener;
    private final Path journalPath;
    private final FileChannel journal;
    private boolean journalFailed;
    private boolean closed;

    /**
     * @param path {@code railgate.replay.path}; blank keeps the record in
     *     memory only
     * @throws IllegalStateException when the journal cannot be opened, is
     *     locked by another process or by another guard in this JVM, or holds
     *     a line that cannot be parsed
     */
    @Autowired
    public ReplayGuard(@Value("${railgate.replay.path:}") String path) {
        this(path, FileChannel::open);
    }

    ReplayGuard(String path, ChannelOpener opener) {
        this.opener = opener;
        if (path == null || path.isBlank()) {
            this.journalPath = null;
            this.journal = null;
            log.warn("railgate.replay.path is not set: the record of allowed transaction references is "
                    + "held in memory only and is lost on restart, after which a reference allowed "
                    + "before the restart can be allowed again.");
            return;
        }
        this.journalPath = Path.of(path.trim());
        FileChannel channel = null;
        FileLock fileLock = null;
        try {
            boolean existed = Files.exists(journalPath);
            channel = opener.open(journalPath,
                    StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
            try {
                fileLock = channel.tryLock();
            } catch (OverlappingFileLockException e) {
                throw new IllegalStateException("railgate.replay.path " + journalPath
                        + " is already open in this JVM");
            }
            if (fileLock == null) {
                throw new IllegalStateException("railgate.replay.path " + journalPath
                        + " is locked by another process; two railgate instances cannot share a journal");
            }
            if (!existed) {
                forceDirectory(journalPath.toAbsolutePath().getParent());
            }
            int records = rebuild(channel);
            channel.position(channel.size());
            log.info("Replay journal {} opened: {} allowed settlement(s) recorded ({} payout instruction id(s))",
                    journalPath, records, settledPayoutInstructionIds.size());
        } catch (IOException e) {
            closeQuietly(channel);
            throw new IllegalStateException("railgate.replay.path " + journalPath
                    + " could not be opened: " + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
        } catch (RuntimeException e) {
            closeQuietly(channel);
            throw e;
        }
        this.journal = channel;
    }

    /** A guard without a journal, for tests and embedding. */
    public static ReplayGuard inMemory() {
        return new ReplayGuard((String) null);
    }

    /**
     * Claims {@code transactionReference} and, when non-null,
     * {@code payoutInstructionId}, both or neither.
     */
    public Attempt tryReserve(String transactionReference, String payoutInstructionId) {
        if (transactionReference == null) {
            throw new IllegalArgumentException("transactionReference must not be null");
        }
        synchronized (lock) {
            if (settledReferences.contains(transactionReference)) {
                return new Refused(Key.TRANSACTION_REFERENCE, false);
            }
            if (payoutInstructionId != null && settledPayoutInstructionIds.contains(payoutInstructionId)) {
                return new Refused(Key.PAYOUT_INSTRUCTION_ID, false);
            }
            if (reservedReferences.contains(transactionReference)) {
                return new Refused(Key.TRANSACTION_REFERENCE, true);
            }
            if (payoutInstructionId != null && reservedPayoutInstructionIds.contains(payoutInstructionId)) {
                return new Refused(Key.PAYOUT_INSTRUCTION_ID, true);
            }
            reservedReferences.add(transactionReference);
            if (payoutInstructionId != null) {
                reservedPayoutInstructionIds.add(payoutInstructionId);
            }
            return new Reserved(new Reservation(transactionReference, payoutInstructionId));
        }
    }

    /**
     * Makes the reservation permanent: journals it (fsynced) when a journal is
     * configured, then records it as settled.
     *
     * @throws ReplayJournalException when the journal cannot be written. The
     *     reservation is still held; the caller must {@link #release} it and
     *     must not allow the settlement.
     */
    public void commit(Reservation reservation) {
        synchronized (lock) {
            if (reservation.finished) {
                throw new IllegalStateException("reservation already committed or released");
            }
        }
        if (journal != null) {
            append(reservation);
        }
        synchronized (lock) {
            reservedReferences.remove(reservation.transactionReference);
            settledReferences.add(reservation.transactionReference);
            if (reservation.payoutInstructionId != null) {
                reservedPayoutInstructionIds.remove(reservation.payoutInstructionId);
                settledPayoutInstructionIds.add(reservation.payoutInstructionId);
            }
            reservation.finished = true;
        }
    }

    /** Drops an uncommitted reservation; a no-op once committed or released. */
    public void release(Reservation reservation) {
        synchronized (lock) {
            if (reservation.finished) {
                return;
            }
            reservedReferences.remove(reservation.transactionReference);
            if (reservation.payoutInstructionId != null) {
                reservedPayoutInstructionIds.remove(reservation.payoutInstructionId);
            }
            reservation.finished = true;
        }
    }

    /** Whether the reference has been committed (allowed). */
    public boolean isSettled(String transactionReference) {
        synchronized (lock) {
            return settledReferences.contains(transactionReference);
        }
    }

    /** Whether the payout instruction id has been committed (allowed). */
    public boolean isPayoutInstructionSettled(String payoutInstructionId) {
        synchronized (lock) {
            return settledPayoutInstructionIds.contains(payoutInstructionId);
        }
    }

    /** Number of committed transaction references. */
    public int settledCount() {
        synchronized (lock) {
            return settledReferences.size();
        }
    }

    /** Whether a journal file backs this guard. */
    public boolean isJournalled() {
        return journal != null;
    }

    private void append(Reservation reservation) {
        String line = RECORD_VERSION
                + '\t' + encode(reservation.transactionReference)
                + '\t' + encode(reservation.payoutInstructionId == null ? "" : reservation.payoutInstructionId)
                + '\t' + Instant.now()
                + '\n';
        ByteBuffer buffer = ByteBuffer.wrap(line.getBytes(StandardCharsets.US_ASCII));
        synchronized (journalLock) {
            if (journalFailed || closed) {
                throw new ReplayJournalException("replay journal " + journalPath
                        + (closed ? " is closed" : " failed earlier; restart railgate to recover it"), null);
            }
            try {
                while (buffer.hasRemaining()) {
                    journal.write(buffer);
                }
                journal.force(true);
            } catch (IOException e) {
                journalFailed = true;
                log.error("Replay journal {} could not be written; every further settlement that would be "
                        + "allowed is denied until railgate is restarted", journalPath, e);
                throw new ReplayJournalException("replay journal " + journalPath + " could not be written", e);
            }
        }
    }

    /**
     * Reads the journal record by record, in chunks, so its size is bounded
     * only by the file system. Bytes after the last line feed are an
     * incomplete record left by a write that did not complete; they are
     * truncated away.
     */
    private int rebuild(FileChannel channel) throws IOException {
        channel.position(0);
        ByteBuffer chunk = ByteBuffer.allocate(64 * 1024);
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        long read = 0;
        long end = 0;
        int records = 0;
        while (channel.read(chunk) != -1) {
            chunk.flip();
            while (chunk.hasRemaining()) {
                byte b = chunk.get();
                read++;
                if (b == '\n') {
                    records++;
                    parse(line.toString(StandardCharsets.ISO_8859_1), records);
                    line.reset();
                    end = read;
                } else {
                    line.write(b);
                }
            }
            chunk.clear();
        }
        if (end < read) {
            log.warn("Replay journal {} ends in an incomplete record ({} byte(s) after the last line feed), "
                    + "left by a write that did not complete; its settlement was not allowed. Truncating it.",
                    journalPath, read - end);
            channel.truncate(end);
            channel.force(true);
        }
        return records;
    }

    private void parse(String line, int lineNumber) {
        String[] fields = line.split("\t", -1);
        try {
            if (fields.length != 4 || !RECORD_VERSION.equals(fields[0]) || !isAscii(line)) {
                throw new IllegalArgumentException("unexpected shape");
            }
            String reference = decode(fields[1]);
            String payoutInstructionId = decode(fields[2]);
            Instant.parse(fields[3]);
            if (reference.isEmpty()) {
                throw new IllegalArgumentException("empty reference");
            }
            settledReferences.add(reference);
            if (!payoutInstructionId.isEmpty()) {
                settledPayoutInstructionIds.add(payoutInstructionId);
            }
        } catch (IllegalArgumentException | DateTimeParseException e) {
            throw new IllegalStateException("replay journal " + journalPath + " line " + lineNumber
                    + " cannot be parsed. railgate does not start on a journal it cannot read, because "
                    + "it could not tell which transaction references were already allowed.");
        }
    }

    private static boolean isAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c > 0x7E || (c < 0x20 && c != '\t')) {
                return false;
            }
        }
        return true;
    }

    static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private void forceDirectory(Path directory) {
        if (directory == null) {
            return;
        }
        try (FileChannel dir = opener.open(directory, StandardOpenOption.READ)) {
            dir.force(true);
        } catch (IOException | UnsupportedOperationException e) {
            // Not every platform can sync a directory; the file itself is
            // still synced on every write.
            log.debug("Could not sync directory {} after creating the replay journal", directory, e);
        }
    }

    /** Closes the channel, which also releases the file lock taken on it. */
    private static void closeQuietly(FileChannel channel) {
        if (channel == null) {
            return;
        }
        try {
            channel.close();
        } catch (IOException ignored) {
            // nothing more to do
        }
    }

    /** Releases the journal's file lock and closes it; idempotent. */
    @Override
    public void close() {
        synchronized (journalLock) {
            if (closed) {
                return;
            }
            closed = true;
            closeQuietly(journal);
        }
    }
}
