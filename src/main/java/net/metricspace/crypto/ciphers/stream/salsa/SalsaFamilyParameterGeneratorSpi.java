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
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import net.metricspace.crypto.ciphers.stream.PositionParameterSpec;

/**
 * A base class for {@link
 * java.security.AlgorithmParameterGeneratorSpi} instances for
 * Salsa-family ciphers.  This provides basic functionality, leaving
 * only the creation of parameter objects to subclasses.
 */
abstract class SalsaFamilyParameterGeneratorSpi
    extends AlgorithmParameterGeneratorSpi {

    /**
     * Random source to use.
     */
    private SecureRandom random;

    /**
     * Starting position to use.
     */
    private long pos;

    /**
     * Create an empty {@link java.security.AlgorithmParameters} to be
     * initialized.  This is used by {@link #engineGenerateParameters}
     * to create an appropriate {@link
     * java.security.AlgorithmParameters}, which it then initializes.
     *
     * @return An empty {@link java.security.AlgorithmParameters} to
     *         be initialized.
     * @throws java.security.NoSuchProviderException If the Krypton
     *         provider isn't registered.
     */
    protected abstract AlgorithmParameters createParameters()
        throws NoSuchProviderException;

    /**
     * {@inheritDoc}
     */
    @Override
    protected final AlgorithmParameters engineGenerateParameters() {
        final byte[] iv = new byte[SalsaFamilyCipherSpi.IV_LEN];
        final AlgorithmParameters out;

        try {
            random.nextBytes(iv);
            out = createParameters();
            out.init(new SalsaFamilyParameterSpec(iv, pos));

            return out;
        } catch(final NoSuchProviderException |
                      InvalidParameterSpecException e) {
            throw new IllegalStateException(e);
        } finally {
            Arrays.fill(iv, (byte)0);
        }
    }

    /**
     * Initialize this generator to use the given secure random source
     * and a starting position of {@code 0}.  The {@code size}
     * parameter is ignored.
     *
     * @param size Ignored.
     * @param random The random source to use.
     */
    @Override
    protected final void engineInit(final int size,
                                    final SecureRandom random) {
        this.random = random;
        this.pos = 0;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineInit(final AlgorithmParameterSpec spec,
                                    final SecureRandom random)
        throws InvalidAlgorithmParameterException {
        if (spec instanceof PositionParameterSpec) {
            final PositionParameterSpec pss = (PositionParameterSpec)spec;

            this.pos = pss.getPosition();
            this.random = random;
        } else {
            throw new InvalidAlgorithmParameterException();
        }
    }
}
