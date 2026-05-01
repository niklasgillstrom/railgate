package eu.gillstrom.railgate.audit;

import eu.gillstrom.railgate.model.SettlementDecision;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

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

    private final List<AuditEntry> entries = new CopyOnWriteArrayList<>();

    public void record(SettlementDecision decision) {
        AuditEntry entry = new AuditEntry(
                Instant.now(),
                decision.getTransactionReference(),
                decision.isAllow(),
                decision.getReasonCode(),
                decision.getMessage(),
                decision.getAuditEntryId()
        );
        entries.add(entry);

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
        return List.copyOf(entries);
    }
}
