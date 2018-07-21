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

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import net.metricspace.crypto.ciphers.stream.KeystreamCipherTestUtils;
import net.metricspace.crypto.providers.KryptonProvider;

public class HC256CipherSpiTest {
    private static final HC256CipherSpi.HC256Key KEY =
        new HC256CipherSpi.HC256Key(new int[] {
                0x04030201, 0x08070605, 0x0c0b0a09, 0x100f0e0d,
                0x14131211, 0x18171615, 0x1c1b1a19, 0x201f1e1d,
            });

    private static final byte[] KEY_EXPECTED = new byte[] {
        (byte)1, (byte)2, (byte)3, (byte)4,
        (byte)5, (byte)6, (byte)7, (byte)8,
        (byte)9, (byte)10, (byte)11, (byte)12,
        (byte)13, (byte)14, (byte)15, (byte)16,
        (byte)17, (byte)18, (byte)19, (byte)20,
        (byte)21, (byte)22, (byte)23, (byte)24,
        (byte)25, (byte)26, (byte)27, (byte)28,
        (byte)29, (byte)30, (byte)31, (byte)32
    };

    private static final HC256CipherSpi.HC256Key FROM_BYTES =
        new HC256CipherSpi.HC256Key(KEY_EXPECTED);

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

    private static HC256CipherSpi makeTestInstance() {
        final HC256CipherSpi spi = new HC256CipherSpi();

        KeystreamCipherTestUtils.setKey(spi, KEY);

        final byte[] iv = KeystreamCipherTestUtils.getIV(spi);

        for(int i = 0; i < IV.length; i++) {
            iv[i] = IV[i];
        }

        return spi;
    }

    @BeforeClass
    public static void init() {
        KryptonProvider.register();
    }

    @AfterClass
    public static void fini() {
        KryptonProvider.unregister();
    }

    @Test
    public static void keyTest() {
        Assert.assertEquals(KEY.getEncoded(), KEY_EXPECTED);
        Assert.assertEquals(FROM_BYTES.getEncoded(), KEY_EXPECTED);
    }

    @Test
    public static void getParametersTest()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final HC256CipherSpi spi = makeTestInstance();

        final AlgorithmParameters params = spi.engineGetParameters();
        final IvParameterSpec spec =
            params.getParameterSpec(IvParameterSpec.class);

        final HC256CipherSpi newspi = new HC256CipherSpi();

        KeystreamCipherTestUtils.engineInit(newspi, 0, KEY, params, null);

        Assert.assertEquals(KeystreamCipherTestUtils.getIV(newspi), IV);
    }

    @Test
    public static void initParameterSpecTest()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final HC256CipherSpi spi = new HC256CipherSpi();
        final IvParameterSpec spec = new IvParameterSpec(IV);

        spi.engineInit(0, KEY, spec, null);

        Assert.assertEquals(KeystreamCipherTestUtils.getIV(spi), IV);
    }

    private static final HC256CipherSpi.HC256Key PAPER_KEY0 =
        new HC256CipherSpi.HC256Key(new int[] {
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000
            });
    private static final HC256CipherSpi.HC256Key PAPER_KEY1 =
        new HC256CipherSpi.HC256Key(new int[] {
                0x00000055, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000
            });

    private static final byte[] PAPER_IV0 = new byte[] {
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0
    };

    private static final byte[] PAPER_IV1 = new byte[] {
        (byte)1, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0
    };

    private static final byte[] EXPECTED_PAPER_KEY0_IV0 = new byte[] {
        (byte)0x5b, (byte)0x07, (byte)0x89, (byte)0x85,
        (byte)0xd8, (byte)0xf6, (byte)0xf3, (byte)0x0d,
        (byte)0x42, (byte)0xc5, (byte)0xc0, (byte)0x2f,
        (byte)0xa6, (byte)0xb6, (byte)0x79, (byte)0x51,
        (byte)0x53, (byte)0xf0, (byte)0x65, (byte)0x34,
        (byte)0x80, (byte)0x1f, (byte)0x89, (byte)0xf2,
        (byte)0x4e, (byte)0x74, (byte)0x24, (byte)0x8b,
        (byte)0x72, (byte)0x0b, (byte)0x48, (byte)0x18,
        (byte)0xcd, (byte)0x92, (byte)0x27, (byte)0xec,
        (byte)0xeb, (byte)0xcf, (byte)0x4d, (byte)0xbf,
        (byte)0x8d, (byte)0xbf, (byte)0x69, (byte)0x77,
        (byte)0xe4, (byte)0xae, (byte)0x14, (byte)0xfa,
        (byte)0xe8, (byte)0x50, (byte)0x4c, (byte)0x7b,
        (byte)0xc8, (byte)0xa9, (byte)0xf3, (byte)0xea,
        (byte)0x6c, (byte)0x01, (byte)0x06, (byte)0xf5,
        (byte)0x32, (byte)0x7e, (byte)0x69, (byte)0x81
    };

    private static final byte[] EXPECTED_PAPER_KEY0_IV1 = new byte[] {
        (byte)0xaf, (byte)0xe2, (byte)0xa2, (byte)0xbf,
        (byte)0x4f, (byte)0x17, (byte)0xce, (byte)0xe9,
        (byte)0xfe, (byte)0xc2, (byte)0x05, (byte)0x8b,
        (byte)0xd1, (byte)0xb1, (byte)0x8b, (byte)0xb1,
        (byte)0x5f, (byte)0xc0, (byte)0x42, (byte)0xee,
        (byte)0x71, (byte)0x2b, (byte)0x31, (byte)0x01,
        (byte)0xdd, (byte)0x50, (byte)0x1f, (byte)0xc6,
        (byte)0x0b, (byte)0x08, (byte)0x2a, (byte)0x50,
        (byte)0x06, (byte)0xc7, (byte)0xfe, (byte)0xed,
        (byte)0x41, (byte)0x92, (byte)0x3d, (byte)0x63,
        (byte)0x48, (byte)0xc4, (byte)0xda, (byte)0xa6,
        (byte)0xff, (byte)0x61, (byte)0x85, (byte)0xaf,
        (byte)0x5a, (byte)0x13, (byte)0x04, (byte)0x5e,
        (byte)0x34, (byte)0xc4, (byte)0x48, (byte)0x94,
        (byte)0xf3, (byte)0xe9, (byte)0xe7, (byte)0x2d,
        (byte)0xdf, (byte)0x0b, (byte)0x52, (byte)0x37
    };

    private static final byte[] EXPECTED_PAPER_KEY1_IV0 = new byte[] {
        (byte)0x1c, (byte)0x40, (byte)0x4a, (byte)0xfe,
        (byte)0x4f, (byte)0xe2, (byte)0x5f, (byte)0xed,
        (byte)0x95, (byte)0x8f, (byte)0x9a, (byte)0xd1,
        (byte)0xae, (byte)0x36, (byte)0xc0, (byte)0x6f,
        (byte)0x88, (byte)0xa6, (byte)0x5a, (byte)0x3c,
        (byte)0xc0, (byte)0xab, (byte)0xe2, (byte)0x23,
        (byte)0xae, (byte)0xb3, (byte)0x90, (byte)0x2f,
        (byte)0x42, (byte)0x0e, (byte)0xd3, (byte)0xa8,
        (byte)0x6c, (byte)0x3a, (byte)0xf0, (byte)0x59,
        (byte)0x44, (byte)0xeb, (byte)0x39, (byte)0x6e,
        (byte)0xfb, (byte)0x79, (byte)0x75, (byte)0x8f,
        (byte)0x5e, (byte)0x7a, (byte)0x13, (byte)0x70,
        (byte)0xd8, (byte)0xb7, (byte)0x10, (byte)0x6d,
        (byte)0xcd, (byte)0xf7, (byte)0xd0, (byte)0xad,
        (byte)0xda, (byte)0x23, (byte)0x34, (byte)0x72,
        (byte)0xe6, (byte)0xdd, (byte)0x75, (byte)0xf5
    };

    @Test
    public static void ietfTestVectorKey0IV0()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final int len = EXPECTED_PAPER_KEY0_IV0.length;
        final HC256CipherSpi spi = new HC256CipherSpi();
        final byte[] actual = new byte[len];

        spi.engineInit(0, PAPER_KEY0, new IvParameterSpec(PAPER_IV0), null);
        KeystreamCipherTestUtils.engineUpdate(spi, actual, 0, len, actual, 0);

        Assert.assertEquals(actual, EXPECTED_PAPER_KEY0_IV0);

    }

    @Test
    public static void ietfTestVectorKey0IV1()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final int len = EXPECTED_PAPER_KEY0_IV1.length;
        final HC256CipherSpi spi = new HC256CipherSpi();
        final byte[] actual = new byte[len];

        spi.engineInit(0, PAPER_KEY0, new IvParameterSpec(PAPER_IV1), null);
        KeystreamCipherTestUtils.engineUpdate(spi, actual, 0, len, actual, 0);

        Assert.assertEquals(actual, EXPECTED_PAPER_KEY0_IV1);

    }

    @Test
    public static void ietfTestVectorKey1IV0()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final int len = EXPECTED_PAPER_KEY1_IV0.length;
        final HC256CipherSpi spi = new HC256CipherSpi();
        final byte[] actual = new byte[len];

        spi.engineInit(0, PAPER_KEY1, new IvParameterSpec(PAPER_IV0), null);
        KeystreamCipherTestUtils.engineUpdate(spi, actual, 0, len, actual, 0);

        Assert.assertEquals(actual, EXPECTED_PAPER_KEY1_IV0);

    }
}
