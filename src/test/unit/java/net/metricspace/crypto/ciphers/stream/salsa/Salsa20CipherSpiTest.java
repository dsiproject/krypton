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

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import net.metricspace.crypto.providers.KryptonProvider;

public class Salsa20CipherSpiTest {
    private static final Salsa20CipherSpi.Key KEY =
        new Salsa20CipherSpi.Key(new int[] {
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

    private static final int[] EXPECTED = new int[] {
        0xb9a205a3, 0x0695e150, 0xaa94881a, 0xadb7b12c,
        0x798942d4, 0x26107016, 0x64edb1a4, 0x2d27173f,
        0xb1c7f1fa, 0x62066edc, 0xe035fa23, 0xc4496f04,
        0x2131e6b3, 0x810bde28, 0xf62cb407, 0x6bdede3d
    };

    private static final byte[] TEST_DATA = new byte[256];

    private static final byte[] TEST_EXPECTED = new byte[] {
        (byte)110, (byte)-68, (byte)-67, (byte)-65,
        (byte)118, (byte)-4, (byte)-52, (byte)100,
        (byte)-85, (byte)5, (byte)84, (byte)43,
        (byte)-18, (byte)-118, (byte)103, (byte)-53,
        (byte)-62, (byte)-113, (byte)-94, (byte)-31,
        (byte)65, (byte)-5, (byte)-17, (byte)-69,
        (byte)58, (byte)47, (byte)-101, (byte)34,
        (byte)25, (byte)9, (byte)-56, (byte)-41,
        (byte)-44, (byte)41, (byte)82, (byte)88,
        (byte)-53, (byte)83, (byte)-105, (byte)112,
        (byte)-35, (byte)36, (byte)-41, (byte)-84,
        (byte)52, (byte)67, (byte)118, (byte)-97,
        (byte)-6, (byte)39, (byte)-91, (byte)14,
        (byte)96, (byte)100, (byte)66, (byte)100,
        (byte)-36, (byte)-117, (byte)107, (byte)97,
        (byte)38, (byte)-125, (byte)55, (byte)46,
        (byte)8, (byte)93, (byte)10, (byte)18,
        (byte)-65, (byte)36, (byte)11, (byte)24,
        (byte)-100, (byte)-30, (byte)-73, (byte)-126,
        (byte)-119, (byte)-122, (byte)43, (byte)86,
        (byte)-3, (byte)-55, (byte)-4, (byte)-1,
        (byte)-61, (byte)59, (byte)-17, (byte)-109,
        (byte)37, (byte)-94, (byte)-24, (byte)27,
        (byte)-104, (byte)-5, (byte)63, (byte)-71,
        (byte)-86, (byte)4, (byte)-49, (byte)67,
        (byte)70, (byte)21, (byte)-50, (byte)-1,
        (byte)-21, (byte)-104, (byte)92, (byte)28,
        (byte)-80, (byte)-115, (byte)-124, (byte)64,
        (byte)-23, (byte)11, (byte)29, (byte)86,
        (byte)-35, (byte)-22, (byte)-22, (byte)22,
        (byte)-39, (byte)-31, (byte)90, (byte)-1,
        (byte)-1, (byte)31, (byte)105, (byte)-116,
        (byte)72, (byte)60, (byte)122, (byte)70,
        (byte)106, (byte)-15, (byte)-2, (byte)6,
        (byte)37, (byte)116, (byte)-83, (byte)-3,
        (byte)43, (byte)6, (byte)-90, (byte)43,
        (byte)77, (byte)-104, (byte)68, (byte)7,
        (byte)25, (byte)-22, (byte)119, (byte)99,
        (byte)-123, (byte)-60, (byte)112, (byte)52,
        (byte)-102, (byte)126, (byte)-42, (byte)-106,
        (byte)-107, (byte)-125, (byte)70, (byte)62,
        (byte)-43, (byte)-46, (byte)107, (byte)-113,
        (byte)-17, (byte)-52, (byte)-78, (byte)5,
        (byte)-38, (byte)15, (byte)91, (byte)-6,
        (byte)-104, (byte)-57, (byte)120, (byte)18,
        (byte)-2, (byte)117, (byte)107, (byte)9,
        (byte)-22, (byte)-52, (byte)40, (byte)42,
        (byte)-92, (byte)47, (byte)75, (byte)-81,
        (byte)-89, (byte)-106, (byte)51, (byte)24,
        (byte)-112, (byte)70, (byte)-30, (byte)-78,
        (byte)15, (byte)53, (byte)-77, (byte)-32,
        (byte)-27, (byte)74, (byte)-93, (byte)-71,
        (byte)41, (byte)-30, (byte)60, (byte)15,
        (byte)71, (byte)-36, (byte)123, (byte)-51,
        (byte)79, (byte)-110, (byte)-117, (byte)42,
        (byte)-105, (byte)100, (byte)-66, (byte)125,
        (byte)75, (byte)-118, (byte)80, (byte)-7,
        (byte)-128, (byte)-91, (byte)11, (byte)53,
        (byte)-83, (byte)-128, (byte)-121, (byte)55,
        (byte)94, (byte)12, (byte)85, (byte)110,
        (byte)-53, (byte)-26, (byte)-89, (byte)22,
        (byte)30, (byte)-122, (byte)83, (byte)-50,
        (byte)-109, (byte)-111, (byte)-31, (byte)-26,
        (byte)113, (byte)14, (byte)-44, (byte)-15
    };

    @Test
    public static void verifyExpectedLen() {
        Assert.assertEquals(TEST_EXPECTED.length, TEST_DATA.length);
    }

    private static Salsa20CipherSpi makeTestInstance() {
        final Salsa20CipherSpi spi = new Salsa20CipherSpi();

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

    @Test
    public static void doubleRoundTest() {
        final Salsa20CipherSpi spi = makeTestInstance();

        spi.streamBlock();

        for(int i = 0; i < EXPECTED.length; i++) {
            Assert.assertEquals(spi.block[i], EXPECTED[i]);
        }
    }

    @Test
    public static void getParametersTest()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final Salsa20CipherSpi spi = makeTestInstance();

        spi.blockOffset = BLOCK_OFFSET;

        final AlgorithmParameters params =
            spi.engineGetParameters();
        final SalsaFamilyParameterSpec spec =
            params.getParameterSpec(SalsaFamilyParameterSpec.class);

        Assert.assertEquals(spec.getPosition(), POS);

        final Salsa20CipherSpi newspi = new Salsa20CipherSpi();

        newspi.engineInit(0, KEY, params, null);

        Assert.assertEquals(newspi.iv, IV);
        Assert.assertEquals(newspi.blockIdx, BLOCK_IDX);
        Assert.assertEquals(newspi.blockOffset, BLOCK_OFFSET);
    }

    @Test
    public static void initParameterSpecTest()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final Salsa20CipherSpi spi = new Salsa20CipherSpi();
        final SalsaFamilyParameterSpec spec =
            new SalsaFamilyParameterSpec(IV, POS);

        spi.engineInit(0, KEY, spec, null);

        Assert.assertEquals(spi.iv, IV);
        Assert.assertEquals(spi.blockIdx, BLOCK_IDX);
        Assert.assertEquals(spi.blockOffset, BLOCK_OFFSET);
    }


    private static void doUpdateTest(final int pos,
                                     final int len)
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        final Salsa20CipherSpi spi = new Salsa20CipherSpi();
        final SalsaFamilyParameterSpec spec =
            new SalsaFamilyParameterSpec(IV, pos);
        final byte[] expected =
            Arrays.copyOfRange(TEST_EXPECTED, pos, pos + len);
        final byte[] actual =
            Arrays.copyOfRange(TEST_DATA, pos, pos + len);

        spi.engineInit(0, KEY, spec, null);
        spi.engineUpdate(actual, 0, len, actual, 0);
        Assert.assertEquals(actual, expected);
    }

    @Test
    private static void updateTest()
        throws InvalidKeyException, InvalidAlgorithmParameterException,
               InvalidParameterSpecException {
        for(int i = 0; i < 256; i++) {
            for(int j = 0; j < 256 - i; j++) {
                doUpdateTest(i, j);
            }
        }
    }
}
