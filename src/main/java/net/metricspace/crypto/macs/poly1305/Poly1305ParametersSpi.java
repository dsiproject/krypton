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

import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

/**
 * The {@link java.security.AlgorithmParametersSpi} implementation for
 * the Poly1305 MAC.
 */
public class Poly1305ParametersSpi extends AlgorithmParametersSpi {
    /**
     * The initialization vector.
     */
    private final byte[] iv = new byte[Poly1305MacSpi.IV_LEN];

    /**
     * {@inheritDoc}
     */
    @Override
    protected byte[] engineGetEncoded() {
        return Arrays.copyOf(iv, Poly1305MacSpi.IV_LEN);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected byte[] engineGetEncoded(final String format) {
        return engineGetEncoded();
    }

    /**
     * Get a {@link IvParameterSpec} instance describing
     * these parameters.
     *
     * @param paramSpec {@link IvParameterSpec}.
     * @return An {@link IvParameterSpec} specifying the
     *         initialization vector.
     */
    @Override
    protected <T extends AlgorithmParameterSpec>
        T engineGetParameterSpec(final Class<T> paramSpec)
        throws InvalidParameterSpecException {
        if (paramSpec.equals(IvParameterSpec.class)) {
            return (T) new IvParameterSpec(iv);
        } else {
            throw new InvalidParameterSpecException();
        }
    }

    /**
     * Fully initialize the parameters.
     *
     * @param spec The parameter spec.
     */
    private void engineInit(final IvParameterSpec spec) {
        engineInit(spec.getIV());
    }

    /**
     * Initialize the parameters from a parameter spec.  This must be
     * an {@link IvParameterSpec}, which specifies an initialization
     * vector.
     *
     * @param spec An {@link IvParameterSpec}.
     */
    @Override
    protected void engineInit(final AlgorithmParameterSpec spec)
        throws InvalidParameterSpecException {
        if (spec instanceof IvParameterSpec) {
            engineInit(((IvParameterSpec)spec).getIV());
        } else {
            throw new InvalidParameterSpecException();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineInit(final byte[] data) {
        for(int i = 0; i < Poly1305MacSpi.IV_LEN; i++) {
            this.iv[i] = iv[i];
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineInit(final byte[] data,
                              final String format) {
        engineInit(data);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String engineToString() {
        final StringBuilder sb = new StringBuilder();

        sb.append(" iv: ");

        for(int i = 0; i < iv.length; i++) {
            sb.append(String.format("%02x", iv[i]));
        }

        return sb.toString();
    }
}
