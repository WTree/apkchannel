package com.cobra.zip.Util;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
public class ApkVerityBuilder {

    private ApkVerityBuilder() {}
    private static final int CHUNK_SIZE_BYTES = 4096;  // Typical Linux block size
    private static final int DIGEST_SIZE_BYTES = 32;  // SHA-256 size
    private static final int FSVERITY_HEADER_SIZE_BYTES = 64;
    private static final int ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_SIZE = 4;
    private static final int ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16;
    private static final String JCA_DIGEST_ALGORITHM = "SHA-256";
    private static final byte[] DEFAULT_SALT = new byte[8];
    public static class ApkVerityResult {
        public final ByteBuffer fsverityData;
        public final byte[] rootHash;
        ApkVerityResult(ByteBuffer fsverityData, byte[] rootHash) {
            this.fsverityData = fsverityData;
            this.rootHash = rootHash;
        }
    }



    /**
     * A helper class to consume and digest data by block continuously, and write into a buffer.
     */
    private static class BufferedDigester implements DataDigester {
        /** Amount of the data to digest in each cycle before writting out the digest. */
        private static final int BUFFER_SIZE = CHUNK_SIZE_BYTES;
        /**
         * Amount of data the {@link MessageDigest} has consumed since the last reset. This must be
         * always less than BUFFER_SIZE since {@link MessageDigest} is reset whenever it has
         * consumed BUFFER_SIZE of data.
         */
        private int mBytesDigestedSinceReset;
        /** The final output {@link ByteBuffer} to write the digest to sequentially. */
        private final ByteBuffer mOutput;
        private final MessageDigest mMd;
        private final byte[] mDigestBuffer = new byte[DIGEST_SIZE_BYTES];
        private final byte[] mSalt;
        private BufferedDigester(byte[] salt, ByteBuffer output) throws NoSuchAlgorithmException {
            mSalt = salt;
            mOutput = output.slice();
            mMd = MessageDigest.getInstance(JCA_DIGEST_ALGORITHM);
            mMd.update(mSalt);
            mBytesDigestedSinceReset = 0;
        }
        /**
         * Consumes and digests data up to BUFFER_SIZE (may continue from the previous remaining),
         * then writes the final digest to the output buffer.  Repeat until all data are consumed.
         * If the last consumption is not enough for BUFFER_SIZE, the state will stay and future
         * consumption will continuous from there.
         */
        @Override
        public void consume(ByteBuffer buffer) throws DigestException {
            int offset = buffer.position();
            int remaining = buffer.remaining();
            while (remaining > 0) {
                int allowance = (int) Math.min(remaining, BUFFER_SIZE - mBytesDigestedSinceReset);
                // Optimization: set the buffer limit to avoid allocating a new ByteBuffer object.
                buffer.limit(buffer.position() + allowance);
                mMd.update(buffer);
                offset += allowance;
                remaining -= allowance;
                mBytesDigestedSinceReset += allowance;
                if (mBytesDigestedSinceReset == BUFFER_SIZE) {
                    mMd.digest(mDigestBuffer, 0, mDigestBuffer.length);
                    mOutput.put(mDigestBuffer);
                    // After digest, MessageDigest resets automatically, so no need to reset again.
                    mMd.update(mSalt);
                    mBytesDigestedSinceReset = 0;
                }
            }
        }
        public void assertEmptyBuffer() throws DigestException {
            if (mBytesDigestedSinceReset != 0) {
                throw new IllegalStateException("Buffer is not empty: " + mBytesDigestedSinceReset);
            }
        }
        private void fillUpLastOutputChunk() {
            int lastBlockSize = (int) (mOutput.position() % BUFFER_SIZE);
            if (lastBlockSize == 0) {
                return;
            }
            mOutput.put(ByteBuffer.allocate(BUFFER_SIZE - lastBlockSize));
        }
    }

    // Rationale: 1) 1 MB should fit in memory space on all devices. 2) It is not too granular
    // thus the syscall overhead is not too big.
    private static final int MMAP_REGION_SIZE_BYTES = 1024 * 1024;



    /** Returns a slice of the buffer which shares content with the provided buffer. */
    private static ByteBuffer slice(ByteBuffer buffer, int begin, int end) {
        ByteBuffer b = buffer.duplicate();
        b.position(0);  // to ensure position <= limit invariant.
        b.limit(end);
        b.position(begin);
        return b.slice();
    }
    /** Skip the {@code ByteBuffer} position by {@code bytes}. */
    private static void skip(ByteBuffer buffer, int bytes) {
        buffer.position(buffer.position() + bytes);
    }
    /** Divides a number and round up to the closest integer. */
    private static long divideRoundup(long dividend, long divisor) {
        return (dividend + divisor - 1) / divisor;
    }
}
