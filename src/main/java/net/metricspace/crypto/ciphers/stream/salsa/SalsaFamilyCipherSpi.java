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

import net.metricspace.crypto.common.Common256BitKey;
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
     * Keys for the Salsa cipher family.
     */
    static abstract class SalsaFamilyKey extends Common256BitKey {
        /**
         * Initialize this key with the given array.  The key takes
         * possession of the {@code data} array.
         *
         * @param data The key material.
         */
        SalsaFamilyKey(final int[] data) {
            super(data);
        }

        /**
         * Initialize this key with the given byte array.  The byte
         * array needs to be zeroed out afterwards.
         *
         * @param data The key material.
         */
        SalsaFamilyKey(final byte[] data) {
            super(data);
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

    @Override
    protected final void initState() {}

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
