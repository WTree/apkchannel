package com.cobra.zip.Util;

import java.io.IOException;
import java.security.DigestException;

public interface DataSource {

    /**
     * Returns the size (in bytes) of the data offered by this source.
     */
    long size();
    /**
     * Feeds the specified region of this source's data into the provided digester.
     *
     * @param offset offset of the region inside this data source.
     * @param size size (in bytes) of the region.
     */
    void feedIntoDataDigester(DataDigester md, long offset, int size)
            throws IOException, DigestException;
}
