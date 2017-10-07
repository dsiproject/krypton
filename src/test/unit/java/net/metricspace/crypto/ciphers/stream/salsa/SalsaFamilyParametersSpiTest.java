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

import java.security.spec.InvalidParameterSpecException;

import org.testng.Assert;
import org.testng.annotations.Test;

public class SalsaFamilyParametersSpiTest {
    private static final byte[] IV = new byte[] {
        (byte)3, (byte)1, (byte)4, (byte)1,
        (byte)5, (byte)9, (byte)2, (byte)6
    };

    private static final long POS = 17;

    private static final SalsaFamilyParameterSpec SPEC =
        new SalsaFamilyParameterSpec(IV, POS);

    @Test
    public void engineInitSpecTest()
        throws InvalidParameterSpecException {
        final SalsaFamilyParametersSpi spi = new SalsaFamilyParametersSpi();

        spi.engineInit(SPEC);

        final SalsaFamilyParameterSpec specout =
            spi.engineGetParameterSpec(SalsaFamilyParameterSpec.class);

        Assert.assertEquals(specout.getIV(), SPEC.getIV());
        Assert.assertEquals(specout.getPosition(), SPEC.getPosition());
    }

    @Test
    public void engineGetEncodedTest()
        throws InvalidParameterSpecException {
        final SalsaFamilyParametersSpi spi = new SalsaFamilyParametersSpi();

        spi.engineInit(SPEC);
        spi.engineInit(spi.engineGetEncoded());

        final SalsaFamilyParameterSpec specout =
            spi.engineGetParameterSpec(SalsaFamilyParameterSpec.class);

        Assert.assertEquals(specout.getIV(), SPEC.getIV());
        Assert.assertEquals(specout.getPosition(), SPEC.getPosition());
    }
}
