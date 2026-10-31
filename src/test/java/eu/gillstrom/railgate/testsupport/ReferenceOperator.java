package eu.gillstrom.railgate.testsupport;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import eu.gillstrom.railgate.signing.OperatorArtefactsCanonicalizer;
import eu.gillstrom.railgate.signing.TrustedCertificates;
import tools.jackson.databind.json.JsonMapper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.UnaryOperator;

/**
 * A payment-network operator implementing
 * {@code api/payment-network-operator.openapi.yaml} on the JDK's
 * {@link HttpServer}, signing every 200 answer per {@code op1} with a test key.
 *
 * <p>The knobs below make it misbehave in the ways railgate must catch: sign
 * with another key or algorithm, echo another reference (validly signed),
 * alter the body after signing, answer with another status or a raw body, or
 * answer slowly.</p>
 */
public final class ReferenceOperator implements AutoCloseable {

    public record Artefacts(String transactionReference, String payoutInstructionId, String certSerial,
                            String issuerDn, String digestHex, String signatureBase64, String issuedAt) {
    }

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final Map<String, Artefacts> registry = new ConcurrentHashMap<>();
    private final List<String> rawPaths = new CopyOnWriteArrayList<>();

    public volatile PrivateKey signingKey = TestKeys.privateKey(TestKeys.OPERATOR_KEY);
    public volatile X509Certificate signingCertificate = TestKeys.certificate(TestKeys.OPERATOR_CERT);
    public volatile String algorithm = "SHA256withRSA";
    /** When set, the response (and the signature) carry this reference instead of the requested one. */
    public volatile String echoedReference;
    /** Applied to the response properties after signing. */
    public volatile UnaryOperator<Map<String, String>> tamper = UnaryOperator.identity();
    /** When set, answered instead of a lookup. */
    public volatile Integer status;
    /** When set, sent as the 200 body instead of the signed artefacts. */
    public volatile String rawBody;
    public volatile long delayMillis;

    private ReferenceOperator(HttpServer server) {
        this.server = server;
        server.createContext("/", this::handle);
        server.setExecutor(executor);
        server.start();
    }

    public static ReferenceOperator start() throws IOException {
        return new ReferenceOperator(HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0));
    }

    /** An HTTPS operator that requires a client certificate (mTLS). */
    public static ReferenceOperator startMutualTls(SSLContext serverContext) throws IOException {
        HttpsServer https = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        https.setHttpsConfigurator(new HttpsConfigurator(serverContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters parameters = serverContext.getDefaultSSLParameters();
                parameters.setNeedClientAuth(true);
                params.setSSLParameters(parameters);
            }
        });
        return new ReferenceOperator(https);
    }

    public String baseUrl() {
        String scheme = server instanceof HttpsServer ? "https" : "http";
        String host = server instanceof HttpsServer ? "localhost" : "127.0.0.1";
        return scheme + "://" + host + ":" + server.getAddress().getPort();
    }

    public void register(Artefacts artefacts) {
        registry.put(artefacts.transactionReference(), artefacts);
    }

    /** Raw request paths received, in order. */
    public List<String> rawPaths() {
        return rawPaths;
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            rawPaths.add(exchange.getRequestURI().getRawPath());
            if (delayMillis > 0) {
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (status != null) {
                send(exchange, status, "{}");
                return;
            }
            String prefix = "/v1/payout-artefacts/";
            String path = exchange.getRequestURI().getPath();
            if (!"GET".equals(exchange.getRequestMethod()) || !path.startsWith(prefix)) {
                send(exchange, 405, "{}");
                return;
            }
            Artefacts artefacts = registry.get(path.substring(prefix.length()));
            if (artefacts == null) {
                send(exchange, 404, "{\"error\":\"unknown transaction reference\"}");
                return;
            }
            if (rawBody != null) {
                send(exchange, 200, rawBody);
                return;
            }
            send(exchange, 200, JSON.writeValueAsString(tamper.apply(signedResponse(artefacts))));
        }
    }

    /** The ten {@code PayoutArtefacts} properties, signed with the current knobs. */
    public Map<String, String> signedResponse(Artefacts artefacts) {
        String reference = echoedReference != null ? echoedReference : artefacts.transactionReference();
        byte[] canonical = OperatorArtefactsCanonicalizer.canonicalBytes(reference,
                artefacts.payoutInstructionId(), artefacts.certSerial(), artefacts.issuerDn(),
                artefacts.digestHex(), artefacts.signatureBase64(), artefacts.issuedAt());
        Map<String, String> body = new java.util.LinkedHashMap<>();
        body.put("transactionReference", reference);
        body.put("payoutInstructionId", artefacts.payoutInstructionId());
        body.put("certSerial", artefacts.certSerial());
        body.put("issuerDn", artefacts.issuerDn());
        body.put("digestHex", artefacts.digestHex());
        body.put("signatureBase64", artefacts.signatureBase64());
        body.put("issuedAt", artefacts.issuedAt());
        body.put("operatorSignatureBase64", TestKeys.signBase64(algorithm, signingKey, canonical));
        body.put("operatorSignatureAlgorithm", algorithm);
        body.put("operatorKeyFingerprintHex", TrustedCertificates.fingerprintHex(signingCertificate));
        return body;
    }

    private static void send(HttpExchange exchange, int code, String body) throws IOException {
        if (code == 204 || code == 304) {
            exchange.sendResponseHeaders(code, -1);
            return;
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(code, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
