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
package net.metricspace.crypto.ciphers.stream.hc;

import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import net.metricspace.crypto.common.Common256BitKey;
import net.metricspace.crypto.ciphers.stream.PositionParameterSpec;
import net.metricspace.crypto.ciphers.stream.KeystreamCipherSpi;
import net.metricspace.crypto.providers.KryptonProvider;

/**
 * A {@link javax.crypto.CipherSpi} implementation for the HC-256
 * cipher. HC-256 was introduced in 2004 by Hongjun Wu, and is one of
 * the finalists in the eSTREAM cipher competition.
 * <h2>Usage</h2>
 *
 * This class should not be used directly.  It provides the underlying
 * implementation for the Java Cryptography Architecture (JCA).  See
 * the {@link javax.crypto.Cipher} class documentation for information
 * on how to use this cipher.
 * <h2>Misuses</h2>
 *
 * The following are possible misuses of the HC-256 cipher.
 * <ul>
 * <li> <b>Encrypting multiple plaintexts with the same cipher
 * stream</b>: As with other stream ciphers, the HC-256 cipher stream
 * is generated solely from the key and IV, and is XORed with the
 * plaintext to produce the cipher stream.  Thus, if multiple
 * plaintexts are encrypted with the same cipher stream, attackers can
 * recover information about the plaintexts as well as the cipher
 * stream.
 * <li> <b>Re-using initialization vectors</b>: Reuse of
 * initialization vectors leads to encryption of multiple plaintexts
 * with the same IV.
 * <li> <b>Ciphertext Manipulation</b>: Since encryption/decryption
 * consists of XORing the plaintext/ciphertext by the cipher stream,
 * an attacker can flip bits in the plaintext by flipping them in the
 * ciphertext, unless the message is also protected by a message
 * authentication code (MAC).
 * </ul>
 *
 * @see net.metricspace.crypto.providers.KryptonProvider
 * @see javax.crypto.Cipher
 */
public final class HC256CipherSpi
    extends KeystreamCipherSpi<HC256CipherSpi.HC256Key, IvParameterSpec> {
    /**
     * The name of this cipher.
     */
    public static final String NAME = "HC-256";

    /**
     * Length of the initialization vector in bytes.
     */
    public static final int IV_BITS = 256;

    /**
     * Length of the initialization vector in bytes.
     */
    public static final int IV_LEN = IV_BITS / 8;

    /**
     * Length of the initialization vector in bytes.
     */
    public static final int IV_WORDS = IV_BITS / 32;

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

    private static final int TABLE_SIZE = 1024;

    private static final int TABLE_MASK = TABLE_SIZE - 1;

    private static final int INIT_SIZE = 2660;

    private static final int BLOCK_SIZE = 16;

    static final class HC256Key extends Common256BitKey {
        /**
         * Initialize this key with the given array.  The key takes
         * possession of the {@code data} array.
         *
         * @param data The key material.
         */
        HC256Key(final int[] data) {
            super(data);
        }

        /**
         * Initialize this key with the given byte array.  The byte
         * array needs to be zeroed out afterwards.
         *
         * @param data The key material.
         */
        HC256Key(final byte[] data) {
            super(data);
        }

        /**
         * Returns the string "HC-256".
         *
         * @return The string "HC-256".
         */
        @Override
        public final String getAlgorithm() {
            return NAME;
        }
    }

    private final int[] ptable = new int[TABLE_SIZE];

    private final int[] qtable = new int[TABLE_SIZE];

    private int idx = 0;

    /**
     * Initialize the cipher engine.
     */
    public HC256CipherSpi() {
        super(IvParameterSpec.class,
              new int[BLOCK_SIZE], new byte[IV_LEN]);
    }

    /**
     * The function {@code f1} from the HC-256 paper.
     *
     * @param x The input word.
     * @return The output word.
     */
    private static int f1(final int x) {
        return ((x >>> 7) | (x << 25)) ^
               ((x >>> 18) | (x << 14)) ^
               (x >>> 3);
    }

    /**
     * The function {@code f2} from the HC-256 paper.
     *
     * @param x The input word.
     * @return The output word.
     */
    private static int f2(final int x) {
        return ((x >>> 17) | (x << 15)) ^
               ((x >>> 19) | (x << 13)) ^
               (x >>> 10);
    }

    private int g1(final int x,
                   final int y) {
        return (((x >>> 10) | (x << 22)) ^
                ((y >>> 23) | (y << 9))) +
               qtable[(x ^ y) & TABLE_MASK];
    }

    private int g2(final int x,
                   final int y) {
        return (((x >>> 10) | (x << 22)) ^
                ((y >>> 23) | (y << 9))) +
               ptable[(x ^ y) & TABLE_MASK];
    }

    private int h1(final int x) {
        return qtable[x & 0xff] +
               qtable[256 + ((x >>> 8) & 0xff)] +
               qtable[512 + ((x >>> 16) & 0xff)] +
               qtable[768 + ((x >>> 24) & 0xff)];
    }

    private int h2(final int x) {
        return ptable[x & 0xff] +
               ptable[256 + ((x >>> 8) & 0xff)] +
               ptable[512 + ((x >>> 16) & 0xff)] +
               ptable[768 + ((x >>> 24) & 0xff)];
    }

    @Override
    protected void initState() {
        final int[] keydata = key.getData();
        final int[] data = new int[INIT_SIZE];

        for(int i = 0; i < KEY_WORDS; i++) {
            data[i] = keydata[i];
        }

        for(int i = 0; i < IV_WORDS; i++) {
            data[i + KEY_WORDS] =
                (iv[(4 * i)]) |
                (iv[(4 * i) + 1]) << 8 |
                (iv[(4 * i) + 2]) << 16 |
                (iv[(4 * i) + 3]) << 24;
        }

        for(int i = IV_WORDS + KEY_WORDS; i < INIT_SIZE; i++) {
            data[i] = f2(data[i - 2]) + data[i - 7] +
                f1(data[i - 15]) + data[i - 16] + i;
        }

        for(int i = 0; i < TABLE_SIZE; i++) {
            ptable[i] = data[i + 512];
        }

        for(int i = 0; i < TABLE_SIZE; i++) {
            qtable[i] = data[i + 1536];
        }

        Arrays.fill(data, 0);
        blockOffset = 0;
        idx = 0;

        for(int i = 0; i < 4096; i++) {
            generateWord();
        }
    }

    private static int subMod(final int lhs,
                              final int rhs) {
        return (((lhs - rhs) & TABLE_MASK) + TABLE_SIZE) % TABLE_SIZE;
    }

    private int generateWord() {
        final int i = idx;
        final int j = idx & TABLE_MASK;

        idx = (idx + 1) & (2048 - 1);

        if (i < 1024) {
            ptable[j] = ptable[j] + ptable[(j - 10) & TABLE_MASK] +
                        g1(ptable[(j - 3) & TABLE_MASK],
                           ptable[(j - 1023) & TABLE_MASK]);
            return h1(ptable[(j - 12) & TABLE_MASK]) ^ ptable[j];
        } else {
            qtable[j] = qtable[j] + qtable[(j - 10) & TABLE_MASK] +
                        g2(qtable[(j - 3) & TABLE_MASK],
                           qtable[(j - 1023) & TABLE_MASK]);
            return h2(qtable[(j - 12) & TABLE_MASK]) ^ qtable[j];
        }
    }

    @Override
    protected void streamBlock() {
        for(int i = 0; i < BLOCK_SIZE; i++) {
            block[i] = generateWord();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineInit(final Key key,
                                    final IvParameterSpec spec)
        throws InvalidKeyException {
        try {
            engineInit((HC256Key)key, spec);
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
                                    final AlgorithmParameterSpec spec,
                                    final SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            engineInit(opmode, (HC256Key)key, spec, random);
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
                                    final SecureRandom random)
        throws InvalidKeyException {
        try {
            engineInit(opmode, (HC256Key)key, random);
        } catch(final ClassCastException e) {
            throw new InvalidKeyException("Cannot accept key for " +
                                          key.getAlgorithm());
        }
    }

    protected final void engineInit(final HC256Key key,
                                    final AlgorithmParameterSpec spec,
                                    final SecureRandom random)
        throws InvalidAlgorithmParameterException {
        if (spec instanceof IvParameterSpec) {
            engineInit(key, (IvParameterSpec)spec);
        } else {
            throw new InvalidAlgorithmParameterException();
        }
    }

    protected final void engineInit(final int opmode,
                                    final HC256Key key,
                                    final AlgorithmParameterSpec spec,
                                    final SecureRandom random)
        throws InvalidAlgorithmParameterException {
        engineInit(key, spec, random);
    }

    protected final void engineInit(final int opmode,
                                    final HC256Key key,
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
     * @return A {@link IvParameterSpec} representing the
     *         current state of the cipher.
     */
    protected final IvParameterSpec parameterSpec() {
        return new IvParameterSpec(iv);
    }

    /**
     * Returns an {@link HC256ParameterSpec} containing the IV.
     *
     * @return An {@link HC256ParameterSpec} containing the IV.
     */
    @Override
    protected final AlgorithmParameters engineGetParameters() {
        final AlgorithmParameters out;

        try {
            out = AlgorithmParameters.getInstance(HC256CipherSpi.NAME,
                                                  KryptonProvider.NAME);
            out.init(parameterSpec());
        } catch(final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch(final NoSuchProviderException e) {
            throw new IllegalStateException(e);
        } catch(final InvalidParameterSpecException e) {
            throw new IllegalStateException(e);
        }

        return out;
    }
}
