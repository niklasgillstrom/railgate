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
     * Bounded ring buffer.
     *
     * <p>{@code CopyOnWriteArrayList} copies the entire backing array on every
     * add, so cost grew linearly with the number of settlements and the total
     * work was quadratic — on a settlement rail, the worst possible place for
     * it. Memory was unbounded too. A deque gives O(1) append, and the cap
     * bounds heap use; a production deployment backs this with the
     * tamper-evident persistent log described above rather than raising the
     * cap.</p>
     */
    private static final int MAX_ENTRIES = 10_000;

    private final Deque<AuditEntry> entries = new ConcurrentLinkedDeque<>();
    private final AtomicInteger entryCount = new AtomicInteger();

    public void record(SettlementDecision decision) {
        AuditEntry entry = new AuditEntry(
                Instant.now(),
                decision.getTransactionReference(),
                decision.isAllow(),
                decision.getReasonCode(),
                decision.getMessage(),
                decision.getAuditEntryId()
        );
        entries.addLast(entry);
        if (entryCount.incrementAndGet() > MAX_ENTRIES && entries.pollFirst() != null) {
            entryCount.decrementAndGet();
        }

        if (decision.isAllow()) {
            log.info("Settlement ALLOWED: ref={} reason={} gatekeeperEntry={}",
                    decision.getTransactionReference(), decision.getReasonCode(), decision.getAuditEntryId());
        } else {
            log.warn("Settlement DENIED: ref={} reason={} message={}",
                    decision.getTransactionReference(), decision.getReasonCode(), decision.getMessage());
        }
    }

    /** Returns an immutable snapshot of all audit entries (for inspection). */
    public List<AuditEntry> snapshot() {
        return List.copyOf(new ArrayList<>(entries));
    }
}
