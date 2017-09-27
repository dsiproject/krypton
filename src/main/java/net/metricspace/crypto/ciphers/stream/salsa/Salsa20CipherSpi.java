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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidParameterSpecException;

import net.metricspace.crypto.providers.KryptonProvider;

/**
 * A {@link javax.crypto.CipherSpi} implementation for the Salsa20 cipher.
 */
public final class Salsa20CipherSpi
    extends SalsaCipherSpi<Salsa20CipherSpi.Key> {
    /**
     * The name of this cipher.
     */
    public static final String NAME = "Salsa20";

    /**
     * Keys for the Salsa20 cipher.
     */
    static final class Key extends SalsaFamilyCipherSpi.SalsaFamilyKey {
        /**
         * Initialize this key with the given array.  The key takes
         * possession of the {@code data} array.
         *
         * @param data The key material.
         */
        Key(final int[] data) {
            super(data);
        }

        /**
         * {@inheritDoc}
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
