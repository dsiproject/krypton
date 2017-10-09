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
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.testng.Assert;
import org.testng.annotations.Test;

public class SalsaCipherSpiTest {
    private static final TestKey KEY =
        new TestKey(new int[] {
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

    private static final int[] EXPECTED = new int[] {
        0xba2409b1, 0x1b7cce6a, 0x29115dcf, 0x5037e027,
        0x37b75378, 0x348d94c8, 0x3ea582b3, 0xc3a9a148,
        0x825bfcb9, 0x226ae9eb, 0x63dd7748, 0x7129a215,
        0x4effd1ec, 0x5f25dc72, 0xa6c3d164, 0x152a26d8
    };

    private static class TestKey extends SalsaFamilyCipherSpi.SalsaFamilyKey {
        TestKey(final int[] data) {
            super(data);
        }

        @Override
        public final String getAlgorithm() {
            return "Test";
        }

    }

    private static SalsaCipherSpi<TestKey> cipherInstance() {
        return new SalsaCipherSpi<TestKey>() {
            @Override
            protected void rounds() {}

            @Override
            protected AlgorithmParameters engineGetParameters() {
                return null;
            }

            @Override
            protected final void engineInit(final Key key,
                                            final SalsaFamilyParameterSpec spec)
                throws InvalidKeyException {
                try {
                    engineInit((SalsaFamilyKey)key, spec);
                } catch(final ClassCastException e) {
                    throw new InvalidKeyException("Cannot accept key for " +
                                                  key.getAlgorithm());
                }
            }

            @Override
            protected final void engineInit(final int opmode,
                                            final Key key,
                                            final AlgorithmParameterSpec spec,
                                            final SecureRandom random)
                throws InvalidKeyException {
                try {
                    engineInit(opmode, (SalsaFamilyKey)key, spec, random);
                } catch(final ClassCastException e) {
                    throw new InvalidKeyException("Cannot accept key for " +
                                                  key.getAlgorithm());
                }
            }

            @Override
            protected final void engineInit(final int opmode,
                                            final Key key,
                                            final SecureRandom random)
                throws InvalidKeyException {
                try {
                    engineInit(opmode, (SalsaFamilyKey)key, random);
                } catch(final ClassCastException e) {
                    throw new InvalidKeyException("Cannot accept key for " +
                                                  key.getAlgorithm());
                }
            }


            {
                key = KEY;
                blockIdx = BLOCK_IDX;

                for(int i = 0; i < IV.length; i++) {
                    iv[i] = IV[i];
                }
            }
        };
    }

    @Test
    public static void doubleRoundTest() {
        final SalsaCipherSpi<TestKey> spi = cipherInstance();

        spi.initBlock();
        spi.doubleRound();

        final int[] block = spi.getBlock();

        for(int i = 0; i < EXPECTED.length; i++) {
            Assert.assertEquals(block[i], EXPECTED[i]);
        }
    }

    private static final int[] INIT_EXPECTED = new int[] {
        0x61707865, 0x04030201, 0x08070605, 0x0c0b0a09,
        0x100f0e0d, 0x3320646e, 0x01040103, 0x06020905,
        0x00000007, 0x00000000, 0x79622d32, 0x14131211,
        0x18171615, 0x1c1b1a19, 0x201f1e1d, 0x6b206574
    };

    @Test
    public static void initBlockTest() {
        final SalsaFamilyCipherSpi<TestKey> spi = cipherInstance();

        spi.initBlock();

        final int[] block = spi.getBlock();

        for(int i = 0; i < INIT_EXPECTED.length; i++) {
            Assert.assertEquals(block[i], INIT_EXPECTED[i]);
        }
    }
}
