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

import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import net.metricspace.crypto.ciphers.stream.PositionParameterSpec;

/**
 * A {@link javax.crypto.CipherSpi} base class for Salsa family
 * ciphers.  This includes Salsa{@code N} as well as ChaCha{@code N}
 * variants.  This provides most of the underlying implementation,
 * leaving only the round functions up to the variants.
 */
abstract class SalsaFamilyCipherSpi<K extends
                                          SalsaFamilyCipherSpi.SalsaFamilyKey>
    extends CipherSpi {
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
     * The current cipher stream block.
     */
    protected final int[] block = new int[STATE_WORDS];

    /**
     * The initialization vector.
     */
    protected final byte[] iv = new byte[IV_LEN];

    /**
     * The current block index.
     */
    protected long blockIdx;

    /**
     * The key.
     */
    protected K key;

    /**
     * The offset into the current stream block that's been used.
     */
    int blockOffset;

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
     * {@inheritDoc}
     */
    @Override
    protected final byte[] engineDoFinal(final byte[] input,
                                         final int inputOffset,
                                         final int inputLen) {
        final byte[] out = new byte[inputLen];

        engineDoFinal(input, inputOffset, inputLen, out, 0);

        return out;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final int engineDoFinal(final byte[] input,
                                      final int inputOffset,
                                      final int inputLen,
                                      final byte[] output,
                                      final int outputOffset) {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Initialize the engine with a key and a random initialization
     * vector.
     *
     * @param opmode Ignored.
     * @param key The key.
     * @param random The {@link SecureRandom} to use to generate the
     *               initialization vector.
     * @throws InvalidKeyException If {@code key} is not of type {@code K}.
     */
    @Override
    protected final void engineInit(final int opmode,
                                    final Key key,
                                    final SecureRandom random)
        throws InvalidKeyException {
        try {
            random.nextBytes(iv);
            init((K)key, 0);
        } catch(final ClassCastException e) {
            throw new InvalidKeyException("Cannot accept key for " +
                                          key.getAlgorithm());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineInit(final int opmode,
                                    final Key key,
                                    final AlgorithmParameters params,
                                    final SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            final SalsaFamilyParameterSpec spec =
                params.getParameterSpec(SalsaFamilyParameterSpec.class);

            final byte[] iv = spec.getIV();

            for(int i = 0; i < IV_LEN; i++) {
                this.iv[i] = iv[i];
            }

            init((K)key, spec.getPosition());
        } catch(final ClassCastException e) {
            throw new InvalidKeyException("Cannot accept key for " +
                                          key.getAlgorithm());
        } catch(final InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineInit(final int opmode,
                                    final Key key,
                                    final AlgorithmParameterSpec spec,
                                    final SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        if (spec instanceof SalsaFamilyParameterSpec) {
            final SalsaFamilyParameterSpec salsaSpec =
                (SalsaFamilyParameterSpec)spec;
            final byte[] iv = salsaSpec.getIV();

            for(int i = 0; i < IV_LEN; i++) {
                this.iv[i] = iv[i];
            }

            try {
                init((K)key, salsaSpec.getPosition());
            } catch(final ClassCastException e) {
                throw new InvalidKeyException("Cannot accept key for " +
                                              key.getAlgorithm());
            }
        } else {
            throw new InvalidAlgorithmParameterException();
        }
    }

    /**
     * Internal initialization procedure.
     *
     * @param key The key.
     * @param pos The stream position in bytes.
     */
    private void init(final K key,
                      final long pos) {
        this.key = key;

        // Figure out the block index and offsets
        this.blockIdx = pos / STATE_BYTES;
        this.blockOffset = (int)(pos % STATE_BYTES);

        // Compute the stream block
        streamBlock();
    }

    /**
     * Get the enigne block size.  This is {@code 1} byte, as the
     * Salsa family are stream ciphers.
     *
     * @return {@code 1}.
     */
    @Override
    protected final int engineGetBlockSize() {
        return 1;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final byte[] engineGetIV() {
        return Arrays.copyOf(iv, IV_LEN);
    }

    /**
     * Returns {@code inputLen} (its argument).  Salsa family ciphers
     * are stream ciphers, and thus don't need extra output size.
     *
     * @param inputLen The length of input.
     * @return {@code inputLen}.
     */
    @Override
    protected final int engineGetOutputSize(final int inputLen) {
        return inputLen;
    }

    /**
     * Throws {@link java.security.NoSuchAlgorithmException}.  Salsa
     * family ciphers are stream ciphers, and do not support modes.
     *
     * @throws java.security.NoSuchAlgorithmException Always.
     */
    @Override
    protected final void engineSetMode(final String mode)
        throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Salsa family ciphers " +
                                           "do not support modes");
    }

    /**
     * Throws {@link java.security.NoSuchAlgorithmException}.  Salsa
     * family ciphers are stream ciphers, and do not support padding.
     *
     * @throws javax.crypto.NoSuchPaddingException Unless {@code
     * "NoPadding"} is specified.
     */
    @Override
    protected final void engineSetPadding(final String padding)
        throws NoSuchPaddingException {
        if (!padding.equals("NoPadding")) {
            throw new NoSuchPaddingException("Salsa family ciphers " +
                                             "do not support padding");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final byte[] engineUpdate(final byte[] input,
                                        final int inputOffset,
                                        final int inputLen) {
        final byte[] out = new byte[inputLen];

        engineUpdate(input, inputOffset, inputLen, out, 0);

        return out;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final int engineUpdate(final byte[] input,
                                     final int inputOffset,
                                     final int inputLen,
                                     final byte[] output,
                                     final int outputOffset) {
        for(int i = inputOffset; i < inputLen;) {
            final int inputRemaining = inputLen - i;
            final int blockRemaining = STATE_BYTES - blockOffset;
            final int groupLen;

            if (inputRemaining < blockRemaining) {
                groupLen = inputRemaining;
                innerUpdate(input, inputOffset + i, groupLen,
                            output, outputOffset + i);
                i += groupLen;
            } else {
                groupLen = blockRemaining;
                innerUpdate(input, inputOffset + i, groupLen,
                            output, outputOffset + i);
                i += groupLen;
                nextBlock();
            }
        }

        return inputLen;
    }

    /**
     * Apply the cipher without crossing a cipher block boundary.
     *
     * @param input The input.
     * @param inputOffset The offset at which input begins.
     * @param inputLen The length of input.
     * @param output The output array.
     * @param outputOffset The offset at which output begins.
     * @see #engineUpdate
     */
    private void innerUpdate(final byte[] input,
                             final int inputOffset,
                             final int inputLen,
                             final byte[] output,
                             final int outputOffset) {
        for(int i = 0; i < inputLen; i++) {
            final int shift = (blockOffset % 4) * 8;
            final int blockWord = blockOffset / 4;
            final byte blockByte = (byte)((block[blockWord] >> shift) & 0xff);
            final byte out = (byte)(blockByte ^ input[inputOffset + i]);

            output[outputOffset + i] = out;
            blockOffset++;
        }
    }

    /**
     * Compute all cipher rounds on {@code block}.
     */
    protected abstract void rounds();

    /**
     * Compute the current stream block.
     */
    void streamBlock() {
        initBlock();
        rounds();
        addBlock();
    }

    /**
     * Advance to the next stream block and compute it.
     */
    private void nextBlock() {
        blockIdx++;
        blockOffset = 0;
        streamBlock();
    }

    /**
     * Add the initial block state to the final state.
     */
    private void addBlock() {
        block[0] += 0x61707865;
        block[1] += key.data[0];
        block[2] += key.data[1];
        block[3] += key.data[2];
        block[4] += key.data[3];
        block[5] += 0x3320646e;
        block[6] += iv[0] | iv[1] << 8 | iv[2] << 16 | iv[3] << 24;
        block[7] += iv[4] | iv[5] << 8 | iv[6] << 16 | iv[7] << 24;
        block[8] += (int)(blockIdx & 0xffffffffL);
        block[9] += (int)((blockIdx >> 32) & 0xffffffffL);
        block[10] += 0x79622d32;
        block[11] += key.data[4];
        block[12] += key.data[5];
        block[13] += key.data[6];
        block[14] += key.data[7];
        block[15] += 0x6b206574;
    }

    /**
     * Initialize the stream block state.
     */
    void initBlock() {
        block[0] = 0x61707865;
        block[1] = key.data[0];
        block[2] = key.data[1];
        block[3] = key.data[2];
        block[4] = key.data[3];
        block[5] = 0x3320646e;
        block[6] = iv[0] | iv[1] << 8 | iv[2] << 16 | iv[3] << 24;
        block[7] = iv[4] | iv[5] << 8 | iv[6] << 16 | iv[7] << 24;
        block[8] = (int)(blockIdx & 0xffffffffL);
        block[9] = (int)((blockIdx >> 32) & 0xffffffffL);
        block[10] = 0x79622d32;
        block[11] = key.data[4];
        block[12] = key.data[5];
        block[13] = key.data[6];
        block[14] = key.data[7];
        block[15] = 0x6b206574;
    }
}
