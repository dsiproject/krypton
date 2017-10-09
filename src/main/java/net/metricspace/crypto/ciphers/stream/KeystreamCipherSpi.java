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
package net.metricspace.crypto.ciphers.stream;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

/**
 * Common superclass of ciphers that generate a stream of blocks that
 * get XORed with plaintext/ciphertext.  This class of ciphers
 * includes almost all stream ciphers as well as block ciphers
 * operating in CTR or OFB mode.
 */
public abstract class KeystreamCipherSpi<K extends SecretKey & Key,
                                         S extends IvParameterSpec>
    extends CipherSpi {
    /**
     * Cached keystream block size in bytes.
     */
    protected final int blockBytes;

    /**
     * The current cipher stream block.
     */
    protected final int[] block;

    /**
     * The {@link Class} of parameter specs.  Used to get specs out of
     * an {@link AlgolithmParameters}.
     */
    protected final Class<S> paramSpecClass;

    /**
     * The current block index.
     */
    protected long blockIdx;

    /**
     * The offset into the current stream block that's been used.
     */
    protected int blockOffset;

    /**
     * The initialization vector buffer.
     */
    protected final byte[] iv;

    /**
     * The key.
     */
    protected K key;


    /**
     * Initialize the engine with a block buffer and an IV buffer.
     * This takes possession of the arrays.
     *
     * @param paramSpecClass The {@link Class} of parameter specs.
     * @param block The array that will become the block buffer.
     * @param iv The array that will become the IV buffer.
     */
    protected KeystreamCipherSpi(final Class<S> paramSpecClass,
                                 final int[] block,
                                 final byte[] iv) {
        this.paramSpecClass = paramSpecClass;
        this.block = block;
        this.iv = iv;
        this.blockBytes = block.length * 4;
    }

    /**
     * Get the enigne block size.  This is {@code 1} byte, as ciphers
     * of this kind aren't block ciphers, and we don't have to XOR by
     * an entire stream block.  We can XOR by however many bytes we
     * want.
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
        return Arrays.copyOf(iv, iv.length);
    }

    /**
     * Returns {@code inputLen} (its argument).  Ciphers of this kind
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
     * Throws {@link java.security.NoSuchAlgorithmException}.  Ciphers
     * of this kind are stream ciphers, and do not support modes.
     *
     * @throws java.security.NoSuchAlgorithmException Always.
     */
    @Override
    protected final void engineSetMode(final String mode)
        throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("This engine does " +
                                           "not support modes");
    }

    /**
     * Throws {@link java.security.NoSuchAlgorithmException}.  Ciphers
     * of this kind are stream ciphers, and do not support padding.
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
     * Initialize from a generally-typed key and a properly-typed
     * parameter spec.
     *
     * @param key The key;
     * @param spec The parameter spec.
     * @throws InvalidKeyException If the key is ill-typed.
     */
    protected abstract void engineInit(final Key key,
                                       final S spec)
        throws InvalidKeyException;

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineInit(final int opmode,
                                    final Key key,
                                    final AlgorithmParameters params,
                                    final SecureRandom random)
        throws InvalidAlgorithmParameterException, InvalidKeyException {
        try {
            final S spec = params.getParameterSpec(paramSpecClass);

            engineInit(key, spec);
        } catch(final InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException(e);
        }
    }

    /**
     * Initialize the engine with a key and a random initialization
     * vector.  This also recomputes the stream block.
     *
     * @param key The key.
     * @param random The {@link SecureRandom} to use to generate the
     *               initialization vector.
     * @throws InvalidKeyException If {@code key} is not of type {@code K}.
     */
    protected void engineInit(final K key,
                              final SecureRandom random) {
        random.nextBytes(iv);
        this.key = key;

        // Compute the stream block
        streamBlock();
    }

    /**
     * Set the key and IV.  This also recomputes the stream block.
     *
     * @param key The key
     * @param iv The IV.
     */
    protected void engineInit(final K key,
                              final byte[] iv) {
        for(int i = 0; i < iv.length; i++) {
            this.iv[i] = iv[i];
        }

        this.key = key;

        // Compute the stream block
        streamBlock();
    }

    /**
     * Set the key and IV from a well-typed key and spec.  This also
     * recomputes the stream block.
     *
     * @param key The key
     * @param spec A parameter spec containing the IV.
     */
    protected void engineInit(final K key,
                              final S spec) {
        engineInit(key, spec.getIV());
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
        for(int i = 0; i < inputLen;) {
            final int inputRemaining = inputLen - i;
            final int blockRemaining = blockBytes - blockOffset;
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
     * Compute the current stream block.
     */
    protected abstract void streamBlock();

    /**
     * Advance to the next stream block and compute it.
     */
    private void nextBlock() {
        blockIdx++;
        blockOffset = 0;
        streamBlock();
    }

}
