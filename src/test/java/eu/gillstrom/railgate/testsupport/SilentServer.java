package eu.gillstrom.railgate.testsupport;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A server that accepts connections and then keeps the caller waiting: it
 * either sends nothing at all, or sends an answer one byte at a time with a
 * pause before each byte, so that no single read of the caller times out and
 * the answer never ends.
 */
public final class SilentServer implements AutoCloseable {

    private final ServerSocket server;
    private final List<Socket> accepted = new CopyOnWriteArrayList<>();
    private final byte[] drip;
    private final long pauseMillis;
    private volatile boolean closed;

    private SilentServer(byte[] drip, long pauseMillis) throws IOException {
        this.server = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        this.drip = drip;
        this.pauseMillis = pauseMillis;
        Thread acceptor = new Thread(this::accept, "silent-server");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    /** Accepts and never answers. */
    public static SilentServer silent() throws IOException {
        return new SilentServer(new byte[0], 0);
    }

    /**
     * Accepts, sends {@code head} at once and then repeats {@code filler} for
     * ever, one byte every {@code pauseMillis} milliseconds.
     */
    public static SilentServer dripping(String head, long pauseMillis) throws IOException {
        return new SilentServer(head.getBytes(StandardCharsets.US_ASCII), pauseMillis);
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getLocalPort();
    }

    private void accept() {
        while (!closed) {
            try {
                Socket socket = server.accept();
                accepted.add(socket);
                if (drip.length > 0) {
                    Thread writer = new Thread(() -> drip(socket), "silent-server-drip");
                    writer.setDaemon(true);
                    writer.start();
                }
            } catch (IOException e) {
                return;
            }
        }
    }

    private void drip(Socket socket) {
        try {
            OutputStream out = socket.getOutputStream();
            out.write(drip);
            out.flush();
            while (!closed) {
                Thread.sleep(pauseMillis);
                out.write(' ');
                out.flush();
            }
        } catch (IOException | InterruptedException e) {
            // The caller hung up, which is what the tests wait for.
        }
    }

    @Override
    public void close() throws IOException {
        closed = true;
        server.close();
        for (Socket socket : accepted) {
            socket.close();
        }
    }
}
