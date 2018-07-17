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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import net.metricspace.crypto.providers.KryptonProvider;

/**
 * A {@link javax.crypto.CipherSpi} implementation for the Salsa20
 * cipher.  Salsa20 is the 20-round version of the Salsa cipher
 * introduced by Daniel J. Bernstein in 2007 for the eSTREAM
 * competition.
 * <h2>Usage</h2>
 *
 * This class should not be used directly.  It provides the underlying
 * implementation for the Java Cryptography Architecture (JCA).  See
 * the {@link javax.crypto.Cipher} class documentation for information
 * on how to use this cipher.
 * <h2>Misuses</h2>
 *
 * The following are possible misuses of the Salsa20 cipher.
 * <ul>
 * <li> <b>Encrypting multiple plaintexts with the same cipher
 * stream</b>: As with other stream ciphers, Salsa20's cipher
 * stream is generated solely from the key, IV, and starting position,
 * and is XORed with the plaintext to produce the cipher stream.
 * Thus, if multiple plaintexts are encrypted with the same cipher
 * stream, attackers can recover information about the plaintexts as
 * well as the cipher stream.
 * <li> <b>Re-using initialization vecctors</b>: Reuse of
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
public final class Salsa20CipherSpi
    extends SalsaCipherSpi<Salsa20CipherSpi.Salsa20Key> {
    /**
     * The name of this cipher.
     */
    public static final String NAME = "Salsa20";

    /**
     * Keys for the Salsa20 cipher.
     */
    static final class Salsa20Key extends SalsaFamilyCipherSpi.SalsaFamilyKey {
        /**
         * Initialize this key with the given array.  The key takes
         * possession of the {@code data} array.
         *
         * @param data The key material.
         */
        Salsa20Key(final int[] data) {
            super(data);
        }

        /**
         * Initialize this key with the given byte array.  The byte
         * array needs to be zeroed out afterwards.
         *
         * @param data The key material.
         */
        Salsa20Key(final byte[] data) {
            super(data);
        }

        /**
         * Returns the string "Salsa20".
         *
         * @return The string "Salsa20".
         */
        @Override
        public final String getAlgorithm() {
            return NAME;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineInit(final Key key,
                                    final SalsaFamilyParameterSpec spec)
        throws InvalidKeyException {
        try {
            engineInit((Salsa20Key)key, spec);
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
            engineInit(opmode, (Salsa20Key)key, spec, random);
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
            engineInit(opmode, (Salsa20Key)key, random);
        } catch(final ClassCastException e) {
            throw new InvalidKeyException("Cannot accept key for " +
                                          key.getAlgorithm());
        }
    }

    /**
     * Returns a {@link SalsaFamilyParameterSpec} containing the IV
     * and current position.  Note that the position of the return
     * value will vary if the stream is advanced.
     *
     * @return A {@link SalsaFamilyParameterSpec} containing the IV
     * and current position.
     */
    @Override
    protected final AlgorithmParameters engineGetParameters() {
        final AlgorithmParameters out;

        try {
            out = AlgorithmParameters.getInstance(Salsa20CipherSpi.NAME,
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

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void rounds() {
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
    }
}
