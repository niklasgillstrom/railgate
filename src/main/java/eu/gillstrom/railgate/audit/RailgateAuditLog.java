package eu.gillstrom.railgate.audit;

import eu.gillstrom.railgate.model.SettlementDecision;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Append-only audit record of railgate settlement decisions.
 *
 * <p>Records every {@link SettlementDecision} (allowed and denied) with
 * timestamp and reason code, supporting the supervisor's retrospective
 * audit of railgate enforcement. Production deployments would back this
 * with a tamper-evident persistent log; the in-memory implementation here
 * is suitable for the reference-implementation demonstration flow and for
 * integration tests.
 *
 * <p>Note: railgate's audit log is intentionally minimal. The
 * authoritative compliance record lives in gatekeeper. railgate only
 * records what railgate itself decided — not transaction payload content,
 * not signature material, not certificate detail. Just the binary decision
 * and the reason code, indexed by transaction reference.
 *
 * <p>This minimisation aligns with GDPR Art 5(1)(c) and avoids creating
 * an unnecessary secondary record of payment activity at the central-bank
 * rail.
 */
@Component
@Slf4j
public class RailgateAuditLog {

    public record AuditEntry(
            Instant timestamp,
            String transactionReference,
            boolean allowed,
            String reasonCode,
            String message,
            String gatekeeperAuditEntryId
    ) {}

    /**
     * Operational counters for the bounded log, exposed so that eviction is
     * visible to a monitoring system rather than only to whoever reads the
     * log file.
     *
     * @param entryCount   entries currently retained
     * @param maxEntries   retention cap
     * @param evictedCount entries discarded since start-up
     */
    public record AuditLogHealth(int entryCount, int maxEntries, long evictedCount) {}

    /**
     * Bounded ring buffer.
     *
     * <p>{@code CopyOnWriteArrayList} copies the entire backing array on every
     * add, so cost grew linearly with the number of settlements and the total
     * work was quadratic — on a settlement rail, the worst possible place for
     * it. Memory was unbounded too. A deque gives O(1) append, and the cap
     * bounds heap use; a production deployment backs this with the
     * tamper-evident persistent log described above rather than raising the
     * cap.</p>
     *
     * <p>Reaching the cap means audit records are being discarded. That is a
     * loss of the supervisory record, so it is counted and reported rather
     * than performed silently.</p>
     */
    private static final int MAX_ENTRIES = 10_000;

    /** One WARN per this many discarded entries. */
    private static final int EVICTION_WARN_INTERVAL = 1_000;

    /** Ceiling on the stored and logged decision message. */
    private static final int MAX_MESSAGE_LENGTH = 512;

    private final Deque<AuditEntry> entries = new ConcurrentLinkedDeque<>();
    private final AtomicInteger entryCount = new AtomicInteger();
    private final AtomicLong evictedCount = new AtomicLong();

    public void record(SettlementDecision decision) {
        // The transaction reference comes from an upstream settlement message
        // and the message can carry a gatekeeper-supplied reason. Both end up
        // in a line-oriented log, where an embedded CR or LF lets the writer
        // forge additional log lines. Neutralised once, before the value is
        // either stored or logged, so the stored entry and the log line agree.
        String transactionReference = sanitise(decision.getTransactionReference(), Integer.MAX_VALUE);
        String message = sanitise(decision.getMessage(), MAX_MESSAGE_LENGTH);

        AuditEntry entry = new AuditEntry(
                Instant.now(),
                transactionReference,
                decision.isAllow(),
                decision.getReasonCode(),
                message,
                decision.getAuditEntryId()
        );
        entries.addLast(entry);
        if (entryCount.incrementAndGet() > MAX_ENTRIES && entries.pollFirst() != null) {
            entryCount.decrementAndGet();
            long evicted = evictedCount.incrementAndGet();
            if (evicted % EVICTION_WARN_INTERVAL == 1) {
                log.warn("Railgate audit log is at its {}-entry cap and is discarding the "
                        + "oldest records; {} discarded since start-up. The supervisory "
                        + "record is now incomplete. Back the audit log with a persistent "
                        + "tamper-evident store before production use.",
                        MAX_ENTRIES, evicted);
            }
        }

        if (decision.isAllow()) {
            log.info("Settlement ALLOWED: ref={} reason={} gatekeeperEntry={}",
                    transactionReference, decision.getReasonCode(), decision.getAuditEntryId());
        } else {
            log.warn("Settlement DENIED: ref={} reason={} message={}",
                    transactionReference, decision.getReasonCode(), message);
        }
    }

    /** Returns an immutable snapshot of all audit entries (for inspection). */
    public List<AuditEntry> snapshot() {
        return List.copyOf(new ArrayList<>(entries));
    }

    /** Retained, capped and discarded counts for the bounded log. */
    public AuditLogHealth health() {
        return new AuditLogHealth(entryCount.get(), MAX_ENTRIES, evictedCount.get());
    }

    /** Number of audit entries discarded at the retention cap since start-up. */
    public long getEvictedCount() {
        return evictedCount.get();
    }

    /**
     * Replaces CR and LF with a space and truncates to {@code maxLength}.
     * Returns null unchanged so that an absent value stays absent rather than
     * becoming an empty string.
     */
    private static String sanitise(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        String flattened = value.replace('\r', ' ').replace('\n', ' ');
        if (maxLength != Integer.MAX_VALUE && flattened.length() > maxLength) {
            return flattened.substring(0, maxLength);
        }
        return flattened;
    }
}
