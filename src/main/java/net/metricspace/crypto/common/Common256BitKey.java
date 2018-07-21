/* Copyright (c) 2018, Eric McCorkle.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.metricspace.crypto.common;

import java.security.Key;

import javax.crypto.SecretKey;

/**
 * A common class for 256-bit {@link Key} implementations.  This is
 * common to almost all symmetric ciphers.
 */
public abstract class Common256BitKey implements Key, SecretKey {
    /**
     * Length of the key in bits.
     */
    public static final int KEY_BITS = 256;

    /**
     * Length of the key in bytes.
     */
    public static final int KEY_LEN = KEY_BITS / 8;

    /**
     * Length of the key in 4-byte words.
     */
    public static final int KEY_WORDS = KEY_BITS / 32;

    /**
     * The key data.
     */
    protected final int[] data;

    /**
     * Initialize this key with the given array.  The key takes
     * possession of the {@code data} array.
     *
     * @param data The key material.
     */
    protected Common256BitKey(final int[] data) {
        this.data = data;
    }

    public final int[] getData() {
        return data;
    }

    /**
     * Initialize this key with the given byte array.  The byte
     * array needs to be zeroed out afterwards.
     *
     * @param data The key material.
     */
    protected Common256BitKey(final byte[] data) {
        this.data = new int[KEY_WORDS];
        this.data[0] =
            data[0] | data[1] << 8 |
            data[2] << 16 | data[3] << 24;
        this.data[1] =
            data[4] | data[5] << 8 |
            data[6] << 16 | data[7] << 24;
        this.data[2] =
            data[8] | data[9] << 8 |
            data[10] << 16 | data[11] << 24;
        this.data[3] =
            data[12] | data[13] << 8 |
            data[14] << 16 | data[15] << 24;
        this.data[4] =
            data[16] | data[17] << 8 |
            data[18] << 16 | data[19] << 24;
        this.data[5] =
            data[20] | data[21] << 8 |
            data[22] << 16 | data[23] << 24;
        this.data[6] =
            data[24] | data[25] << 8 |
            data[26] << 16 | data[27] << 24;
        this.data[7] =
            data[28] | data[29] << 8 |
            data[30] << 16 | data[31] << 24;
    }

    /**
     * Returns the name of the primary encoding format, which is
     * {@code "RAW"}.
     *
     * @return The string {@code "RAW"}
     */
    @Override
    public final String getFormat() {
        return "RAW";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final byte[] getEncoded() {
        final byte[] out = new byte[KEY_LEN];

        out[0] = (byte)(data[0] & 0xff);
        out[1] = (byte)((data[0] >>> 8) & 0xff);
        out[2] = (byte)((data[0] >>> 16) & 0xff);
        out[3] = (byte)((data[0] >>> 24) & 0xff);
        out[4] = (byte)(data[1] & 0xff);
        out[5] = (byte)((data[1] >>> 8) & 0xff);
        out[6] = (byte)((data[1] >>> 16) & 0xff);
        out[7] = (byte)((data[1] >>> 24) & 0xff);
        out[8] = (byte)(data[2] & 0xff);
        out[9] = (byte)((data[2] >>> 8) & 0xff);
        out[10] = (byte)((data[2] >>> 16) & 0xff);
        out[11] = (byte)((data[2] >>> 24) & 0xff);
        out[12] = (byte)(data[3] & 0xff);
        out[13] = (byte)((data[3] >>> 8) & 0xff);
        out[14] = (byte)((data[3] >>> 16) & 0xff);
        out[15] = (byte)((data[3] >>> 24) & 0xff);
        out[16] = (byte)(data[4] & 0xff);
        out[17] = (byte)((data[4] >>> 8) & 0xff);
        out[18] = (byte)((data[4] >>> 16) & 0xff);
        out[19] = (byte)((data[4] >>> 24) & 0xff);
        out[20] = (byte)(data[5] & 0xff);
        out[21] = (byte)((data[5] >>> 8) & 0xff);
        out[22] = (byte)((data[5] >>> 16) & 0xff);
        out[23] = (byte)((data[5] >>> 24) & 0xff);
        out[24] = (byte)(data[6] & 0xff);
        out[25] = (byte)((data[6] >>> 8) & 0xff);
        out[26] = (byte)((data[6] >>> 16) & 0xff);
        out[27] = (byte)((data[6] >>> 24) & 0xff);
        out[28] = (byte)(data[7] & 0xff);
        out[29] = (byte)((data[7] >>> 8) & 0xff);
        out[30] = (byte)((data[7] >>> 16) & 0xff);
        out[31] = (byte)((data[7] >>> 24) & 0xff);

        return out;
    }
}
