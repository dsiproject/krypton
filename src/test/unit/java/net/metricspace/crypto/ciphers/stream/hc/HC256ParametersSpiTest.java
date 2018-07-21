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
package net.metricspace.crypto.ciphers.stream.hc;

import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.testng.Assert;
import org.testng.annotations.Test;

public class HC256ParametersSpiTest {
    private static final byte[] IV = new byte[] {
        (byte)16, (byte)11, (byte)25, (byte)7,
        (byte)4, (byte)22, (byte)1, (byte)15,
        (byte)27, (byte)32, (byte)19, (byte)20,
        (byte)10, (byte)5, (byte)26, (byte)8,
        (byte)21, (byte)9, (byte)23, (byte)31,
        (byte)2, (byte)17, (byte)30, (byte)14,
        (byte)18, (byte)24, (byte)12, (byte)28,
        (byte)6, (byte)13, (byte)29, (byte)3
    };

    private static final IvParameterSpec SPEC =
        new IvParameterSpec(IV);

    @Test
    public void engineInitSpecTest()
        throws InvalidParameterSpecException {
        final HC256ParametersSpi spi = new HC256ParametersSpi();

        spi.engineInit(SPEC);

        final IvParameterSpec specout =
            spi.engineGetParameterSpec(IvParameterSpec.class);

        Assert.assertEquals(specout.getIV(), SPEC.getIV());
    }

    @Test
    public void engineGetEncodedTest()
        throws InvalidParameterSpecException {
        final HC256ParametersSpi spi = new HC256ParametersSpi();

        spi.engineInit(SPEC);
        spi.engineInit(spi.engineGetEncoded());

        final IvParameterSpec specout =
            spi.engineGetParameterSpec(IvParameterSpec.class);

        Assert.assertEquals(specout.getIV(), SPEC.getIV());
    }
}
