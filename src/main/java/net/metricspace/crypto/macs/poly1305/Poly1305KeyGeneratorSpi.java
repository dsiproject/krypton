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
package net.metricspace.crypto.macs.poly1305;

import java.security.spec.AlgorithmParameterSpec;
import java.security.SecureRandom;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

import net.metricspace.crypto.providers.KryptonProvider;

/**
 * A key generate for the Poly1305 MAC.  This generator produces keys
 * that satisfy the requirements on cleared bits.  The 3rd, 7th, 11th,
 * and 15th bytes must have their top four bits clear, and the 4th,
 * 8th, and 12th bytes must have their bottom two bits cleared.
 * <h2>Usage</h2>
 *
 * This class should not be used directly.  It provides the underlying
 * implementation for the Java Cryptography Architecture (JCA).  See
 * the {@link javax.crypto.KeyGenerator} class documentation for information
 * on how to use this key generator.
 *
 * @see net.metricspace.crypto.providers.KryptonProvider
 * @see javax.crypto.KeyGenerator
 */
public class Poly1305KeyGeneratorSpi extends KeyGeneratorSpi {
    /**
     * The random source.
     */
    private SecureRandom random;

    /**
     * {@inheritDoc}
     */
    @Override
    protected Poly1305MacSpi.Poly1305Key engineGenerateKey() {
        final byte[] data = new byte[Poly1305MacSpi.KEY_LEN];

        random.nextBytes(data);

        // Clear the required bits
        data[3] &= 0x0f;
        data[4] &= 0xfc;
        data[7] &= 0x0f;
        data[8] &= 0xfc;
        data[11] &= 0x0f;
        data[12] &= 0xfc;
        data[15] &= 0x0f;

        return new Poly1305MacSpi.Poly1305Key(data);
    }

    /**
     * Initialize the engine.
     *
     * @param params Ignored.
     * @param random The random source to use.
     */
    @Override
    protected void engineInit(final AlgorithmParameterSpec params,
                              final SecureRandom random) {
        engineInit(random);
    }

    /**
     * Initialize the engine.
     *
     * @param keysize Ignored.
     * @param random The random source to use.
     */
    @Override
    protected void engineInit(final int keysize,
                              final SecureRandom random) {
        engineInit(random);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineInit(final SecureRandom random) {
        this.random = random;
    }
}
