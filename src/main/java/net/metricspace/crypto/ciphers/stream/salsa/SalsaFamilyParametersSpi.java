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

import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

import net.metricspace.crypto.ciphers.stream.PositionParameterSpec;

/**
 * The {@link java.security.AlgorithmParametersSpi} implementation for
 * Salsa family ciphers.
 */
public class SalsaFamilyParametersSpi extends AlgorithmParametersSpi {
    /**
     * The initialization vector.
     */
    private final byte[] iv = new byte[SalsaFamilyCipherSpi.IV_LEN];

    /**
     * The stream position in bytes.
     */
    private long pos;

    /**
     * {@inheritDoc}
     */
    @Override
    protected byte[] engineGetEncoded() {
        final int posstart = SalsaFamilyCipherSpi.IV_LEN;
        final byte[] out = Arrays.copyOf(iv, posstart + 8);

        out[posstart] = (byte)(pos & 0xffL);
        out[posstart + 1] = (byte)((pos >> 8) & 0xffL);
        out[posstart + 2] = (byte)((pos >> 16) & 0xffL);
        out[posstart + 3] = (byte)((pos >> 24) & 0xffL);
        out[posstart + 4] = (byte)((pos >> 32) & 0xffL);
        out[posstart + 5] = (byte)((pos >> 40) & 0xffL);
        out[posstart + 6] = (byte)((pos >> 48) & 0xffL);
        out[posstart + 7] = (byte)((pos >> 56) & 0xffL);

        return out;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected byte[] engineGetEncoded(final String format) {
        return engineGetEncoded();
    }

    /**
     * Get a {@link SalsaFamilyParameterSpec} instance describing
     * these parameters.  Valid arguments are {@link
     * SalsaFamilyParameterSpec}, {@link PositionParameterSpec}, or
     * {@link IvParameterSpec}.  A {@link SalsaFamilyParameterSpec}
     * instance is returned regardless, as {@link
     * SalsaFamilyParameterSpec} extends both {@link
     * PositionParameterSpec} and {@link IvParameterSpec}
     *
     * @param paramSpec Either {@link SalsaFamilyParameterSpec},
     *                  {@link PositionParameterSpec}, or {@link
     *                  IvParameterSpec}.
     * @return A {@link SalsaFamilyParameterSpec} instance describing
     * these parameters
     */
    @Override
    protected <T extends AlgorithmParameterSpec>
        T engineGetParameterSpec(final Class<T> paramSpec)
        throws InvalidParameterSpecException {
        if (paramSpec.equals(SalsaFamilyParameterSpec.class) ||
            paramSpec.equals(PositionParameterSpec.class) ||
            paramSpec.equals(IvParameterSpec.class)) {
            return (T) new SalsaFamilyParameterSpec(iv, pos);
        } else {
            throw new InvalidParameterSpecException();
        }
    }

    /**
     * Set the parameters from raw values.
     *
     * @param iv The IV.
     * @param pos The position in bytes.
     */
    private void engineInit(final byte[] iv,
                            final long pos) {
        for(int i = 0; i < SalsaFamilyCipherSpi.IV_LEN; i++) {
            this.iv[i] = iv[i];
        }

        this.pos = pos;
    }

    /**
     * Fully initialize the parameters.
     *
     * @param spec The parameter spec.
     */
    private void engineInit(final SalsaFamilyParameterSpec spec) {
        engineInit(spec.getIV(), spec.getPosition());
    }

    /**
     * Initialize the parameters from a parameter spec.  If {@code
     * spec} is an instance of {@link SalsaFamilyParameterSpec}, then
     * the parameters are fully initialized with an IV and position.
     * Otherwise, if {@code spec} is an instance of {@link
     * IvParameterSpec}, then the IV is initialized from {@code spec}
     * and the position is initialized to 0.
     *
     * @param spec Either a {@link SalsaFamilyParameterSpec} or an
     *             {@link IvParameterSpec}
     */
    @Override
    protected void engineInit(final AlgorithmParameterSpec spec)
        throws InvalidParameterSpecException {
        if (spec instanceof SalsaFamilyParameterSpec) {
            engineInit((SalsaFamilyParameterSpec)spec);
        } else if (spec instanceof IvParameterSpec) {
            engineInit((IvParameterSpec)spec.getIV(), 0);
        } else {
            throw new InvalidParameterSpecException();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineInit(final byte[] data) {
        final int posstart = SalsaFamilyCipherSpi.IV_LEN;
        final long pos =
            (long)data[posstart] | (long)data[posstart + 1] << 8 |
            (long)data[posstart + 2] << 16 | (long)data[posstart + 3] << 24 |
            (long)data[posstart + 4] << 32 | (long)data[posstart + 5] << 40 |
            (long)data[posstart + 6] << 48 | (long)data[posstart + 7] << 56;

        engineInit(data, pos);
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

        sb.append("pos: ");
        sb.append(pos);
        sb.append(" iv: ");

        for(int i = 0; i < iv.length; i++) {
            sb.append(String.format("%02x", iv[i]));
        }

        return sb.toString();
    }
}
