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
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import net.metricspace.crypto.providers.KryptonProvider;

public class ChaCha20CipherSpiTest {
    private static final ChaCha20CipherSpi.Key KEY =
        new ChaCha20CipherSpi.Key(new int[] {
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

    private static final byte[] IV = new byte[] {
        (byte)3, (byte)1, (byte)4, (byte)1,
        (byte)5, (byte)9, (byte)2, (byte)6
    };

    private static final int BLOCK_IDX = 7;

    private static final int BLOCK_OFFSET = 3;

    private static final int POS =
        (BLOCK_IDX * SalsaFamilyCipherSpi.STATE_BYTES) + BLOCK_OFFSET;

    private static ChaCha20CipherSpi makeTestInstance() {
        final ChaCha20CipherSpi spi = new ChaCha20CipherSpi();

        spi.key = KEY;
        spi.blockIdx = BLOCK_IDX;

        for(int i = 0; i < IV.length; i++) {
            spi.iv[i] = IV[i];
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
    }
    /*
    @Test
    public static void getParametersTest()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final ChaCha20CipherSpi spi = makeTestInstance();

        spi.blockOffset = BLOCK_OFFSET;

        final AlgorithmParameters params =
            spi.engineGetParameters();
        final SalsaFamilyParameterSpec spec =
            params.getParameterSpec(SalsaFamilyParameterSpec.class);

        Assert.assertEquals(spec.getPosition(), POS);

        final ChaCha20CipherSpi newspi = new ChaCha20CipherSpi();

        newspi.engineInit(0, KEY, params, null);

        Assert.assertEquals(newspi.iv, IV);
        Assert.assertEquals(newspi.blockIdx, BLOCK_IDX);
        Assert.assertEquals(newspi.blockOffset, BLOCK_OFFSET);
    }

    @Test
    public static void initParameterSpecTest()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final ChaCha20CipherSpi spi = new ChaCha20CipherSpi();
        final SalsaFamilyParameterSpec spec =
            new SalsaFamilyParameterSpec(IV, POS);

        spi.engineInit(0, KEY, spec, null);

        Assert.assertEquals(spi.iv, IV);
        Assert.assertEquals(spi.blockIdx, BLOCK_IDX);
        Assert.assertEquals(spi.blockOffset, BLOCK_OFFSET);
    }
    */
    private static final ChaCha20CipherSpi.Key IETF_KEY0 =
        new ChaCha20CipherSpi.Key(new int[] {
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
            });

    private static final ChaCha20CipherSpi.Key IETF_KEY1 =
        new ChaCha20CipherSpi.Key(new int[] {
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x01000000,
            });

    private static final byte[] IETF_IV0 = new byte[] {
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0
    };

    private static final byte[] IETF_IV1 = new byte[] {
        (byte)1, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)0
    };

    private static final byte[] IETF_IVHI = new byte[] {
        (byte)0, (byte)0, (byte)0, (byte)0,
        (byte)0, (byte)0, (byte)0, (byte)1
    };

    private static final byte[] EXPECTED_IETF_KEY0_IV0 = new byte[] {
        (byte)0x76, (byte)0xb8, (byte)0xe0, (byte)0xad,
        (byte)0xa0, (byte)0xf1, (byte)0x3d, (byte)0x90,
        (byte)0x40, (byte)0x5d, (byte)0x6a, (byte)0xe5,
        (byte)0x53, (byte)0x86, (byte)0xbd, (byte)0x28,
        (byte)0xbd, (byte)0xd2, (byte)0x19, (byte)0xb8,
        (byte)0xa0, (byte)0x8d, (byte)0xed, (byte)0x1a,
        (byte)0xa8, (byte)0x36, (byte)0xef, (byte)0xcc,
        (byte)0x8b, (byte)0x77, (byte)0x0d, (byte)0xc7,
        (byte)0xda, (byte)0x41, (byte)0x59, (byte)0x7c,
        (byte)0x51, (byte)0x57, (byte)0x48, (byte)0x8d,
        (byte)0x77, (byte)0x24, (byte)0xe0, (byte)0x3f,
        (byte)0xb8, (byte)0xd8, (byte)0x4a, (byte)0x37,
        (byte)0x6a, (byte)0x43, (byte)0xb8, (byte)0xf4,
        (byte)0x15, (byte)0x18, (byte)0xa1, (byte)0x1c,
        (byte)0xc3, (byte)0x87, (byte)0xb6, (byte)0x69,
        (byte)0xb2, (byte)0xee, (byte)0x65, (byte)0x86
    };

    private static final byte[] EXPECTED_IETF_KEY1_IV0 = new byte[] {
        (byte)0x45, (byte)0x40, (byte)0xf0, (byte)0x5a,
        (byte)0x9f, (byte)0x1f, (byte)0xb2, (byte)0x96,
        (byte)0xd7, (byte)0x73, (byte)0x6e, (byte)0x7b,
        (byte)0x20, (byte)0x8e, (byte)0x3c, (byte)0x96,
        (byte)0xeb, (byte)0x4f, (byte)0xe1, (byte)0x83,
        (byte)0x46, (byte)0x88, (byte)0xd2, (byte)0x60,
        (byte)0x4f, (byte)0x45, (byte)0x09, (byte)0x52,
        (byte)0xed, (byte)0x43, (byte)0x2d, (byte)0x41,
        (byte)0xbb, (byte)0xe2, (byte)0xa0, (byte)0xb6,
        (byte)0xea, (byte)0x75, (byte)0x66, (byte)0xd2,
        (byte)0xa5, (byte)0xd1, (byte)0xe7, (byte)0xe2,
        (byte)0x0d, (byte)0x42, (byte)0xaf, (byte)0x2c,
        (byte)0x53, (byte)0xd7, (byte)0x92, (byte)0xb1,
        (byte)0xc4, (byte)0x3f, (byte)0xea, (byte)0x81,
        (byte)0x7e, (byte)0x9a, (byte)0xd2, (byte)0x75,
        (byte)0xae, (byte)0x54, (byte)0x69, (byte)0x63
    };

    private static final byte[] EXPECTED_IETF_KEY0_IV1 = new byte[] {
        (byte)0xef, (byte)0x3f, (byte)0xdf, (byte)0xd6,
        (byte)0xc6, (byte)0x15, (byte)0x78, (byte)0xfb,
        (byte)0xf5, (byte)0xcf, (byte)0x35, (byte)0xbd,
        (byte)0x3d, (byte)0xd3, (byte)0x3b, (byte)0x80,
        (byte)0x09, (byte)0x63, (byte)0x16, (byte)0x34,
        (byte)0xd2, (byte)0x1e, (byte)0x42, (byte)0xac,
        (byte)0x33, (byte)0x96, (byte)0x0b, (byte)0xd1,
        (byte)0x38, (byte)0xe5, (byte)0x0d, (byte)0x32,
        (byte)0x11, (byte)0x1e, (byte)0x4c, (byte)0xaf,
        (byte)0x23, (byte)0x7e, (byte)0xe5, (byte)0x3c,
        (byte)0xa8, (byte)0xad, (byte)0x64, (byte)0x26,
        (byte)0x19, (byte)0x4a, (byte)0x88, (byte)0x54,
        (byte)0x5d, (byte)0xdc, (byte)0x49, (byte)0x7a,
        (byte)0x0b, (byte)0x46, (byte)0x6e, (byte)0x7d,
        (byte)0x6b, (byte)0xbd, (byte)0xb0, (byte)0x04,
        (byte)0x1b, (byte)0x2f, (byte)0x58, (byte)0x6b
    };

    private static final byte[] EXPECTED_IETF_KEY0_IVHI = new byte[] {
        (byte)0xde, (byte)0x9c, (byte)0xba, (byte)0x7b,
        (byte)0xf3, (byte)0xd6, (byte)0x9e, (byte)0xf5,
        (byte)0xe7, (byte)0x86, (byte)0xdc, (byte)0x63,
        (byte)0x97, (byte)0x3f, (byte)0x65, (byte)0x3a,
        (byte)0x0b, (byte)0x49, (byte)0xe0, (byte)0x15,
        (byte)0xad, (byte)0xbf, (byte)0xf7, (byte)0x13,
        (byte)0x4f, (byte)0xcb, (byte)0x7d, (byte)0xf1,
        (byte)0x37, (byte)0x82, (byte)0x10, (byte)0x31,
        (byte)0xe8, (byte)0x5a, (byte)0x05, (byte)0x02,
        (byte)0x78, (byte)0xa7, (byte)0x08, (byte)0x45,
        (byte)0x27, (byte)0x21, (byte)0x4f, (byte)0x73,
        (byte)0xef, (byte)0xc7, (byte)0xfa, (byte)0x5b,
        (byte)0x52, (byte)0x77, (byte)0x06, (byte)0x2e,
        (byte)0xb7, (byte)0xa0, (byte)0x43, (byte)0x3e,
        (byte)0x44, (byte)0x5f, (byte)0x41, (byte)0xe3
    };

    @Test
    public static void ietfTestVectorKey0IV0()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final int len = EXPECTED_IETF_KEY0_IV0.length;
        final ChaCha20CipherSpi spi = new ChaCha20CipherSpi();
        final byte[] actual = new byte[len];

        spi.engineInit(0, IETF_KEY0, new IvParameterSpec(IETF_IV0), null);
        spi.engineUpdate(actual, 0, len, actual, 0);

        Assert.assertEquals(actual, EXPECTED_IETF_KEY0_IV0);

    }

    @Test
    public static void ietfTestVectorKey1IV0()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final int len = EXPECTED_IETF_KEY1_IV0.length;
        final ChaCha20CipherSpi spi = new ChaCha20CipherSpi();
        final byte[] actual = new byte[len];

        spi.engineInit(0, IETF_KEY1, new IvParameterSpec(IETF_IV0), null);
        spi.engineUpdate(actual, 0, len, actual, 0);

        Assert.assertEquals(actual, EXPECTED_IETF_KEY1_IV0);

    }

    @Test
    public static void ietfTestVectorKey0IV1()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final int len = EXPECTED_IETF_KEY0_IV1.length;
        final ChaCha20CipherSpi spi = new ChaCha20CipherSpi();
        final byte[] actual = new byte[len];

        spi.engineInit(0, IETF_KEY0, new IvParameterSpec(IETF_IV1), null);
        spi.engineUpdate(actual, 0, len, actual, 0);

        Assert.assertEquals(actual, EXPECTED_IETF_KEY0_IV1);

    }

    @Test
    public static void ietfTestVectorKey0IVHI()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final int len = EXPECTED_IETF_KEY0_IVHI.length;
        final ChaCha20CipherSpi spi = new ChaCha20CipherSpi();
        final byte[] actual = new byte[len];

        spi.engineInit(0, IETF_KEY0, new IvParameterSpec(IETF_IVHI), null);
        spi.engineUpdate(actual, 0, len, actual, 0);

        Assert.assertEquals(actual, EXPECTED_IETF_KEY0_IVHI);

    }
}
