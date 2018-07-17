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
package net.metricspace.crypto.ciphers.stream.salsa;

import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import net.metricspace.crypto.ciphers.stream.PositionParameterSpec;
import net.metricspace.crypto.ciphers.stream.SeekableKeystreamCipherSpi;

/**
 * A {@link javax.crypto.CipherSpi} base class for Salsa family
 * ciphers.  This includes Salsa{@code N} as well as ChaCha{@code N}
 * variants.  This provides most of the underlying implementation,
 * leaving only the round functions up to the variants.
 */
abstract class
    SalsaFamilyCipherSpi<K extends SalsaFamilyCipherSpi.SalsaFamilyKey>
    extends SeekableKeystreamCipherSpi<K, SalsaFamilyParameterSpec> {
    /**
     * Length of the initialization vector in bytes.
     */
    public static final int IV_LEN = 8;

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
     * Keys for the Salsa cipher family.
     */
    static abstract class SalsaFamilyKey implements SecretKey, Key {
        /**
         * The key data.
         */
        final int[] data;

        /**
         * Initialize this key with the given array.  The key takes
         * possession of the {@code data} array.
         *
         * @param data The key material.
         */
        SalsaFamilyKey(final int[] data) {
            this.data = data;
        }

        /**
         * Initialize this key with the given byte array.  The byte
         * array needs to be zeroed out afterwards.
         *
         * @param data The key material.
         */
        SalsaFamilyKey(final byte[] data) {
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

    /**
     * The number of words in the cipher state;
     */
    protected static final int STATE_WORDS = 16;

    /**
     * The number of bytes in the cipher state;
     */
    protected static final int STATE_BYTES = STATE_WORDS * 4;

    /**
     * Initialize the cipher engine.
     */
    protected SalsaFamilyCipherSpi() {
        super(SalsaFamilyParameterSpec.class,
              new int[STATE_WORDS], new byte[IV_LEN]);
    }

    protected final void engineInit(final K key,
                                    final SalsaFamilyParameterSpec spec) {
        engineInit(key, spec.getPosition(), spec);
    }

    /**
     * Initialize from a well-typed key and a generally-typed spec.
     * If {@code spec} is a {@link SalsaFamilyParameterSpec}, both the
     * IV and position will be initialized.  If {@code spec} is an
     * {@link IvParameterSpec}, the IV will be initialized and the
     * position will be set to {@code 0}.  If {@code spec} is a {@link
     * PositionParameterSpec}, the positior will be initialized and
     * the IV will be initialized from {@code random}.  Otherwise, an
     * {@link InvalidAlgorithmparameterException} will be thrown.
     *
     * @param key The key.
     * @param spec The parameter spec.
     * @throws InvalidAlgorithmparameterException if {@code spec} is
     * not a {@link SalsaFamilyParameterSpec}, an {@link
     * IvParameterSpec}, or a {@link PositionParameterSpec}
     */
    protected final void engineInit(final K key,
                                    final AlgorithmParameterSpec spec,
                                    final SecureRandom random)
        throws InvalidAlgorithmParameterException {
        final long pos;
        final byte[] iv;

        if (spec instanceof SalsaFamilyParameterSpec) {
            engineInit(key, (SalsaFamilyParameterSpec)spec);
        } else if (spec instanceof IvParameterSpec) {
            engineInit(key, 0, (IvParameterSpec)spec);
        } else if (spec instanceof PositionParameterSpec) {
            final PositionParameterSpec ps =
                (PositionParameterSpec)spec;

            engineInit(key, ps.getPosition(), random);
        } else {
            throw new InvalidAlgorithmParameterException();
        }
    }

    protected final void engineInit(final int opmode,
                                    final K key,
                                    final AlgorithmParameterSpec spec,
                                    final SecureRandom random)
        throws InvalidAlgorithmParameterException {
        engineInit(key, spec, random);
    }

    protected final void engineInit(final int opmode,
                                    final K key,
                                    final SecureRandom random) {
        final byte[] iv = new byte[IV_LEN];
        random.nextBytes(iv);

        engineInit(key, iv);
    }


    /**
     * Get the {@link java.security.spec.AlgorithmParameterSpec} to
     * initialize {@link java.security.AlgorithmParameters} from the
     * current state of the cipher.
     *
     * @return A {@link SalsaFamilyParameterSpec} representing the
     *         current state of the cipher.
     */
    protected final SalsaFamilyParameterSpec parameterSpec() {
        final long pos = (blockIdx * STATE_BYTES) + blockOffset;

        return new SalsaFamilyParameterSpec(iv, pos);
    }

    /**
     * Compute the current stream block.
     */
    @Override
    protected final void streamBlock() {
        initBlock();
        rounds();
        addBlock();
    }

    /**
     * Compute all cipher rounds on {@code block}.
     */
    protected abstract void rounds();

    /**
     * Add the initial block state to the final state.
     */
    protected abstract void addBlock();

    /**
     * Initialize the stream block state.
     */
    protected abstract void initBlock();
}
