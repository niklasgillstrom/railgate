package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link PaymentNetworkClient} for development,
 * integration tests, and the reference-implementation demonstration flow.
 *
 * <p>Production deployments would substitute an HTTP-based client that
 * calls the payment-network operator's signature-retrieval endpoint
 * (Getswish AB in the Swedish deployment).
 *
 * <p>This component is registered only when {@code railgate.payment-network.mode}
 * is set to {@code in-memory} (the default). To use a different client, set
 * the property to a different value and provide an alternative bean.
 */
@Component
@ConditionalOnProperty(
        prefix = "railgate.payment-network",
        name = "mode",
        havingValue = "in-memory",
        matchIfMissing = true)
public class InMemoryPaymentNetworkClient implements PaymentNetworkClient {

    private final Map<String, PaymentSignature> registry = new ConcurrentHashMap<>();

    /** Test endpoint used by integration flows to seed the registry. */
    public void register(String transactionReference, PaymentSignature signature) {
        registry.put(transactionReference, signature);
    }

    @Override
    public Optional<PaymentSignature> getSignature(String transactionReference) {
        return Optional.ofNullable(registry.get(transactionReference));
    }
}
