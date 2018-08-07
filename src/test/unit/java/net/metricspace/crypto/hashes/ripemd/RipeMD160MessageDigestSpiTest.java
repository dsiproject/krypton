/* Copyright (c) 2018, Eric McCorkle.  All rights reserved.
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
package net.metricspace.crypto.hashes.ripemd;

import java.util.Arrays;

import java.security.DigestException;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.hashes.ripemd.RipeMD160MessageDigestSpi;
import net.metricspace.crypto.providers.KryptonProvider;

@Test(groups = "unit")
public class RipeMD160MessageDigestSpiTest {
    @BeforeClass
    public static void init() {
        KryptonProvider.register();
    }

    @AfterClass
    public static void fini() {
        KryptonProvider.unregister();
    }

    private static final byte[] EXPECTED_EMPTY_HASH = new byte[] {
        (byte)0x9c, (byte)0x11, (byte)0x85, (byte)0xa5,
        (byte)0xc5, (byte)0xe9, (byte)0xfc, (byte)0x54,
        (byte)0x61, (byte)0x28, (byte)0x08, (byte)0x97,
        (byte)0x7e, (byte)0xe8, (byte)0xf5, (byte)0x48,
        (byte)0xb2, (byte)0x25, (byte)0x8d, (byte)0x31
    };

    private static final Object[][] HASH_CASES = new Object[][] {
        new Object[] {
            new byte[] {},
            EXPECTED_EMPTY_HASH
        },
        new Object[] {
            new byte[] { (byte)0x61 },
            new byte[] {
                (byte)0x0b, (byte)0xdc, (byte)0x9d, (byte)0x2d,
                (byte)0x25, (byte)0x6b, (byte)0x3e, (byte)0xe9,
                (byte)0xda, (byte)0xae, (byte)0x34, (byte)0x7b,
                (byte)0xe6, (byte)0xf4, (byte)0xdc, (byte)0x83,
                (byte)0x5a, (byte)0x46, (byte)0x7f, (byte)0xfe
            }
        },
        new Object[] {
            new byte[] {
                (byte)0x61, (byte)0x62, (byte)0x63
            },
            new byte[] {
                (byte)0x8e, (byte)0xb2, (byte)0x08, (byte)0xf7,
                (byte)0xe0, (byte)0x5d, (byte)0x98, (byte)0x7a,
                (byte)0x9b, (byte)0x04, (byte)0x4a, (byte)0x8e,
                (byte)0x98, (byte)0xc6, (byte)0xb0, (byte)0x87,
                (byte)0xf1, (byte)0x5a, (byte)0x0b, (byte)0xfc
            }
        },
        new Object[] {
            new byte[] {
                (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64,
                (byte)0x65, (byte)0x66, (byte)0x67, (byte)0x68,
                (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c,
                (byte)0x6d, (byte)0x6e, (byte)0x6f, (byte)0x70,
                (byte)0x71, (byte)0x72, (byte)0x73, (byte)0x74,
                (byte)0x75, (byte)0x76, (byte)0x77, (byte)0x78,
                (byte)0x79, (byte)0x7a
            },
            new byte[] {
                (byte)0xf7, (byte)0x1c, (byte)0x27, (byte)0x10,
                (byte)0x9c, (byte)0x69, (byte)0x2c, (byte)0x1b,
                (byte)0x56, (byte)0xbb, (byte)0xdc, (byte)0xeb,
                (byte)0x5b, (byte)0x9d, (byte)0x28, (byte)0x65,
                (byte)0xb3, (byte)0x70, (byte)0x8d, (byte)0xbc
            }
        },
        new Object[] {
            new byte[] {
                (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44,
                (byte)0x45, (byte)0x46, (byte)0x47, (byte)0x48,
                (byte)0x49, (byte)0x4a, (byte)0x4b, (byte)0x4c,
                (byte)0x4d, (byte)0x4e, (byte)0x4f, (byte)0x50,
                (byte)0x51, (byte)0x52, (byte)0x53, (byte)0x54,
                (byte)0x55, (byte)0x56, (byte)0x57, (byte)0x58,
                (byte)0x59, (byte)0x5a,
                (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64,
                (byte)0x65, (byte)0x66, (byte)0x67, (byte)0x68,
                (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c,
                (byte)0x6d, (byte)0x6e, (byte)0x6f, (byte)0x70,
                (byte)0x71, (byte)0x72, (byte)0x73, (byte)0x74,
                (byte)0x75, (byte)0x76, (byte)0x77, (byte)0x78,
                (byte)0x79, (byte)0x7a,
                (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
                (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
                (byte)0x38, (byte)0x39
            },
            new byte[] {
                (byte)0xb0, (byte)0xe2, (byte)0x0b, (byte)0x6e,
                (byte)0x31, (byte)0x16, (byte)0x64, (byte)0x02,
                (byte)0x86, (byte)0xed, (byte)0x3a, (byte)0x87,
                (byte)0xa5, (byte)0x71, (byte)0x30, (byte)0x79,
                (byte)0xb2, (byte)0x1f, (byte)0x51, (byte)0x89
            }
        },
        new Object[] {
            new byte[] {
                (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                (byte)0x39, (byte)0x30,
                (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                (byte)0x39, (byte)0x30,
                (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                (byte)0x39, (byte)0x30,
                (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                (byte)0x39, (byte)0x30,
                (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                (byte)0x39, (byte)0x30,
                (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                (byte)0x39, (byte)0x30,
                (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                (byte)0x39, (byte)0x30,
                (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
                (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38,
                (byte)0x39, (byte)0x30
            },
            new byte[] {
                (byte)0x9b, (byte)0x75, (byte)0x2e, (byte)0x45,
                (byte)0x57, (byte)0x3d, (byte)0x4b, (byte)0x39,
                (byte)0xf4, (byte)0xdb, (byte)0xd3, (byte)0x32,
                (byte)0x3c, (byte)0xab, (byte)0x82, (byte)0xbf,
                (byte)0x63, (byte)0x32, (byte)0x6b, (byte)0xfb
            }
        },
    };

    @Test(description = "Test an empty hash")
    public static void emptyHashTest()
        throws DigestException {
        final RipeMD160MessageDigestSpi spi = new RipeMD160MessageDigestSpi();
        final byte[] actual = new byte[20];

        spi.engineDigest(actual, 0, 20);
        Assert.assertEquals(actual, EXPECTED_EMPTY_HASH);
    }

    @DataProvider(name = "hash")
    private static Object[][] hashProvider() {
        return HASH_CASES;
    }

    @Test(dataProvider = "hash",
          description = "Test hash")
    public static void hashTest(final byte[] input,
                                final byte[] expected)
        throws DigestException {
        final RipeMD160MessageDigestSpi spi = new RipeMD160MessageDigestSpi();
        final byte[] actual = new byte[20];

        spi.engineUpdate(input, 0, input.length);
        spi.engineDigest(actual, 0, 20);
        Assert.assertEquals(actual, expected);
    }
}
