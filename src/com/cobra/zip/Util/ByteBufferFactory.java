package com.cobra.zip.Util;

import java.nio.ByteBuffer;

public interface ByteBufferFactory {

    /** Initiates a {@link ByteBuffer} with the given size. */
    ByteBuffer create(int capacity);
}
