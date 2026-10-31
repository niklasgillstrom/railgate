package eu.gillstrom.railgate.testsupport;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A gatekeeper {@code POST /api/v1/verify} that answers every request with a
 * verdict signed per {@code sv1} over the request it received, with
 * {@code verifiedAt} = {@code Instant.now().toString()}.
 */
public final class ReferenceGatekeeper implements AutoCloseable {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final AtomicInteger calls = new AtomicInteger();

    public volatile boolean signatureValid = true;
    public volatile boolean compliant = true;
    public volatile String reason = "OK";

    private ReferenceGatekeeper(HttpServer server) {
        this.server = server;
        server.createContext("/api/v1/verify", this::handle);
        server.setExecutor(executor);
        server.start();
    }

    public static ReferenceGatekeeper start() throws IOException {
        return new ReferenceGatekeeper(HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0));
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public int calls() {
        return calls.get();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            calls.incrementAndGet();
            JsonNode request = JSON.readTree(exchange.getRequestBody().readAllBytes());
            VerdictSigner signer = new VerdictSigner(request.get("certSerial").stringValue(),
                    request.get("issuerDn").stringValue(), request.get("digestHex").stringValue());
            signer.verifiedAt = Instant.now().toString();
            signer.signatureValid = signatureValid;
            signer.compliant = compliant;
            signer.reason = reason;
            signer.auditEntryId = "AE-REF";
            byte[] body = signer.json().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
