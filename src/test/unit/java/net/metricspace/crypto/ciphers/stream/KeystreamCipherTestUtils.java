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
package net.metricspace.crypto.ciphers.stream;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;

public class KeystreamCipherTestUtils {
    public static void setIV(final KeystreamCipherSpi<?, ?> spi,
                             final byte[] iv) {
        for(int i = 0; i < iv.length; i++) {
            spi.iv[i] = iv[i];
        }
    }

    public static <K extends SecretKey & Key>
        void setKey(final KeystreamCipherSpi<K, ?> spi,
                    final K key) {
        spi.key = key;
    }

    public static void setBlockIdx(final KeystreamCipherSpi<?, ?> spi,
                           final long blockIdx) {
        spi.blockIdx = blockIdx;
    }

    public static void setBlockOffset(final KeystreamCipherSpi<?, ?> spi,
                              final int blockOffset) {
        spi.blockOffset = blockOffset;
    }

    public static byte[] getIV(final KeystreamCipherSpi<?, ?> spi) {
        return spi.iv;
    }

    public static int[] getBlock(final KeystreamCipherSpi<?, ?> spi) {
        return spi.block;
    }

    public static long getBlockIdx(final KeystreamCipherSpi<?, ?> spi) {
        return spi.blockIdx;
    }

    public static int getBlockOffset(final KeystreamCipherSpi<?, ?> spi) {
        return spi.blockOffset;
    }

    public static void engineInit(final KeystreamCipherSpi<?, ?> spi,
                                  final int opmode,
                                  final Key key,
                                  final AlgorithmParameters params,
                                  final SecureRandom random)
        throws InvalidAlgorithmParameterException, InvalidKeyException {
        spi.engineInit(opmode, key, params, random);
    }

    public static void engineUpdate(final KeystreamCipherSpi<?, ?> spi,
                                    final byte[] input,
                                    final int inputOffset,
                                    final int inputLen,
                                    final byte[] output,
                                    final int outputOffset) {
        spi.engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }
}
