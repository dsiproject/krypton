/* Copyright (c) 2017, Eric McCorkle.  All rights reserved.
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

/* Attribution: Large portions of this implementation are
 * transliterated into Java from a public domain implementation by
 * Daniel J. Bernstein.
 */
package net.metricspace.crypto.macs.poly1305;

import java.security.Key;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public final class Poly1305MacSpi extends MacSpi {

    /**
     * Constants array.  Adapted from DJB's floating-point implementation.
     */
    private static final double POLY1305_53_CONSTANTS[] = {
        /* alpham80 = 3 2^(-29) */
        0.00000000558793544769287109375,
        /* alpham48 = 3 2^3 */
        24.0,
        /* alpham16 = 3 2^35 */
        103079215104.0,
        /* alpha0 = 3 2^51 */
        6755399441055744.0,
        /* alpha18 = 3 2^69 */
        1770887431076116955136.0,
        /* alpha32 = 3 2^83 */
        29014219670751100192948224.0,
         /* alpha50 = 3 2^101 */
        7605903601369376408980219232256.0,
        /* alpha64 = 3 2^115 */
        124615124604835863084731911901282304.0,
        /* alpha82 = 3 2^133 */
        32667107224410092492483962313449748299776.0,
        /* alpha96 = 3 2^147 */
        535217884764734955396857238543560676143529984.0,
        /* alpha112 = 3 2^163 */
        35076039295941670036888435985190792471742381031424.0,
        /* alpha130 = 3 2^181 */
        9194973245195333150150082162901855101712434733101613056.0,
        /* scale = 5 2^(-130) */
        0.0000000000000000000000000000000000000036734198463196484624023016788195177431833298649127735047148490821200539357960224151611328125,
        /* offset0 = alpha0 + 2^33 - 5 */
        6755408030990331.0,
        /* offset1 = alpha32 + 2^65 - 2^33 */
        29014256564239239022116864.0,
        /* offset2 = alpha64 + 2^97 - 2^65 */
        124615283061160854719918951570079744.0,
        /* offset3 = alpha96 + 2^130 - 2^97 */
        535219245894202480694386063513315216128475136.0
    };

    /**
     * The name of the MAC.
     */
    public static final String NAME = "Poly1305";

    /**
     * The size of a tag (output) in bytes.
     */
    public static final int TAG_LEN = 16;

    /**
     * The size of an initialization vector in bytes.
     */
    public static final int IV_LEN = 16;

    /**
     * The size of an initialization vector in bytes.
     */
    public static final int KEY_LEN = 16;

    /**
     * The length of an input block.
     */
    private static final int BLOCK_LEN = 16;

    /**
     * Keys for the Poly1305 MAC.
     */
    static final class Poly1305Key implements Key, SecretKey {
        /**
         * The raw key data.
         */
        final byte[] data;

        /**
         * Initialize a Poly1305 MAC key with a given data array.  The
         * key object takes possession of the array.
         *
         * @param data The data array.
         */
        Poly1305Key(final byte[] data) {
            this.data = data;
        }

        /**
         * Returns the string "Poly1305".
         *
         * @return The string "Poly1305".
         */
        @Override
        public final String getAlgorithm() {
            return NAME;
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
            return Arrays.copyOf(data, KEY_LEN);;
        }
    }

    /**
     * The key.
     */
    private Poly1305Key key;

    /**
     * The initialization vector.
     */
    private final byte[] iv = new byte[];

    /**
     * Input buffer to get 16-byte chunks of data.
     */
    private final byte[] block = new byte[BLOCK_LEN];

    /**
     * The current offset into the block.
     */
    private int offset;

    /**
     * Returns the length of the MAC code, which is {@code TAG_LEN}.
     *
     * @return {@code TAG_LEN}.
     * @see #TAG_LEN
     */
    @Override
    protected int engineGetMacLength() {
        return TAG_LEN;
    }

    /**
     * Initialize the Poly1305 engine with a given key.  The Poly1305
     * engine requires an IV, to be supplied by {@code params}, which
     * must be an instance of {@link IvParameterSpec}.
     *
     * @param key An instance of {@link Poly1305Key}.
     * @param params An instance of {@link IvParameterSpec}.
     * @throws InvalidKeyException If {@code key} is not an instance
     *         of {@link Poly1305Key}.
     * @throws InvalidAlgorithmParameterException If {@code params} is
     *         not an instance of {@link IvParameterSpec}.
     * @see Poly1305Key
     * @see IvParameterSpec
     */
    @Override
    protected void engineInit(final Key key,
                              final AlgorithmParameterSpec params) {
        if (params instanceof IvParameterSpec) {
            final IvParameterSpec ivspec = (IvParameterSpec)params;
            final byte[] iv = ivspec.getIV();

            for(int i = 0; i < IV_LEN; i++) {
                this.iv[i] = iv[i];
            }
        } else {
            throw new InvalidAlgorithmParameterException();
        }

        if (key instanceof Poly1305Key) {
            this.key = (Poly1305Key)key;
        } else {
            throw new InvalidKeyException();
        }

        engineReset();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineUpdate(final byte input) {
        if (offset >= BLOCK_LEN) {
            processBlock();
        }

        buf[offset] = input;
        offset++;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineUpdate(final byte[] input,
                                final int offset,
                                final int len) {
        for(int i = offset; i < offset + len;) {
            final int inputRemaining = len - i;
            final int blockRemaining = BLOCK_LEN - offset;
            final int groupLen;

            if (inputRemaining < blockRemaining) {
                groupLen = inputRemaining;

                for(; offset < BLOCK_LEN; i++, offset++) {
                    block[j] = input[i];
                }
            } else {
                groupLen = blockRemaining;

                for(; offset < BLOCK_LEN; i++, offset++) {
                    block[j] = input[i];
                }

                processBlock();
            }
        }
    }

    private void processBlock() {
    }
}
