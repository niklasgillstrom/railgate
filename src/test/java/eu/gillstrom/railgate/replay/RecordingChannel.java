package eu.gillstrom.railgate.replay;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/**
 * A file channel that counts {@code force} calls and can fail reads, writes, syncs or truncations; everything
 * else is delegated.
 */
final class RecordingChannel extends FileChannel {

    private final FileChannel delegate;
    int forces;
    IOException failRead;
    IOException failWrite;
    /** Thrown by the next {@code force}, once, after the bytes written so far have reached the file. */
    IOException failNextForce;
    IOException failTruncate;
    int truncations;

    RecordingChannel(FileChannel delegate) {
        this.delegate = delegate;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        if (failRead != null) {
            throw failRead;
        }
        return delegate.read(dst);
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        return delegate.read(dsts, offset, length);
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        if (failWrite != null) {
            throw failWrite;
        }
        return delegate.write(src);
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        return delegate.write(srcs, offset, length);
    }

    @Override
    public long position() throws IOException {
        return delegate.position();
    }

    @Override
    public FileChannel position(long newPosition) throws IOException {
        delegate.position(newPosition);
        return this;
    }

    @Override
    public long size() throws IOException {
        return delegate.size();
    }

    @Override
    public FileChannel truncate(long size) throws IOException {
        if (failTruncate != null) {
            throw failTruncate;
        }
        truncations++;
        delegate.truncate(size);
        return this;
    }

    @Override
    public void force(boolean metaData) throws IOException {
        if (failNextForce != null) {
            IOException failure = failNextForce;
            failNextForce = null;
            throw failure;
        }
        forces++;
        delegate.force(metaData);
    }

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        return delegate.transferTo(position, count, target);
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        return delegate.transferFrom(src, position, count);
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        return delegate.read(dst, position);
    }

    @Override
    public int write(ByteBuffer src, long position) throws IOException {
        return delegate.write(src, position);
    }

    @Override
    public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
        return delegate.map(mode, position, size);
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) throws IOException {
        return delegate.lock(position, size, shared);
    }

    @Override
    public FileLock tryLock(long position, long size, boolean shared) throws IOException {
        return delegate.tryLock(position, size, shared);
    }

    @Override
    protected void implCloseChannel() throws IOException {
        delegate.close();
    }
}
