package com.cobra.zip.Util;

import java.nio.ByteBuffer;
import java.security.DigestException;

public interface DataDigester {
    void consume(ByteBuffer buffer) throws DigestException;
}
