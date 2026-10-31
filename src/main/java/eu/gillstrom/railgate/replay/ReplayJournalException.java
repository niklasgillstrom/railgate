package eu.gillstrom.railgate.replay;

/**
 * The replay journal could not record an allowed settlement. The settlement
 * must not be allowed: an allow that is not in the journal would be allowed
 * again after a restart.
 */
public class ReplayJournalException extends RuntimeException {

    public ReplayJournalException(String message, Throwable cause) {
        super(message, cause);
    }
}
