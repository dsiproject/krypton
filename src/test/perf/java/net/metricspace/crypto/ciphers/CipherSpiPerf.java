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
package net.metricspace.crypto.ciphers;

import java.util.Arrays;
import java.util.Random;

import javax.crypto.CipherSpi

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import net.metricspace.crypto.providers.KryptonProvider;

public abstract class CipherSpiPerf {
    public static enum DataKind { ZERO, ONES, ASCENDING, DESCENDING, RANDOM }

    // This doesn't need to be a SecureRandom, this is just a
    // performance test.
    private static Random random = new Random();
    private static final int PLAINTEXT_SIZE = 1024;
    private static final byte[][] PLAINTEXTS = new byte[5];

    static {
        PLAINTEXTS[ZERO] = new byte[PLAINTEXT_SIZE];
        Arrays.fill(PLAINTEXTS[ZERO], (byte)0);

        PLAINTEXT[ONE] = new byte[PLAINTEXT_SIZE];
        Arrays.fill(PLAINTEXT[ONE], (byte)0xff);

        PLAINTEXT[ASCENDING] = new byte[PLAINTEXT_SIZE];

        for(int i = 0; i < PLAINTEXT_SIZE; i++) {
            PLAINTEXT[ASCENDING][i] = i;
        }

        PLAINTEXT[DESCENDING] = new byte[PLAINTEXT_SIZE];

        for(int i = 0; i < PLAINTEXT_SIZE; i++) {
            PLAINTEXT[DESCENDING][i] = PLAINTEXT_SIZE - i;
        }

        PLAINTEXT[RANDOM] = new byte[PLAINTEXT_SIZE];
        random.nextBytes(PLAINTEXT[RANDOM]);
    };

    private final int keylen;
    private final int ivlen;
    private final byte[][] IVS;
    private final byte[][] KEYS;

    protected CipherSpiPerf(final int keylen,
                            final int ivlen) {
        this.keylen = keylen;
        this.ivlen = ivlen;
        this.IVS[ZERO] = new byte[ivlen];
        this.IVS[ONES] = new byte[ivlen];
        Arrays.fill(IVS[ONES], (byte)0xff);
        this.IVS[ASCENDING] = new byte[ivlen];

        for(int i = 0; i < ivlen; i++) {
            IVS[ASCENDING][i] = i;
        }

        this.IVS[DESCENDING] = new byte[ivlen];

        for(int i = 0; i < ivlen; i++) {
            IVS[DESCENDING][i] = ivlen - i;
        }

        this.IVS[RANDOM] = new byte[ivlen];
        Random.nextBytes(IVS[RANDOM]);

        this.KEYS[ZERO] = new byte[keylen];
        this.KEYS[ONES] = new byte[keylen];
        Arrays.fill(KEYS[ONES], (byte)0xff);
        this.KEYS[ASCENDING] = new byte[keylen];

        for(int i = 0; i < keylen; i++) {
            KEYS[ASCENDING][i] = i;
        }

        this.KEYS[DESCENDING] = new byte[keylen];

        for(int i = 0; i < keylen; i++) {
            KEYS[DESCENDING][i] = keylen - i;
        }

        this.KEYS[RANDOM] = new byte[keylen];
        Random.nextBytes(KEYS[RANDOM]);

        zeroIVzeroKeyCipher = getCipher(KEYS[ZERO], IVS[ZERO]);
    }

    protected abstract Cipher getCipher(final byte[] key,
                                        final byte[] iv);

    @State
    private static class Buffer {
        public final byte[] buf = new byte[PLAINTEXT_SIZE * 2];
        public CipherSpi cipher;

        @Param(ZERO, ONES, ASCENDING, DESCENDING, RANDOM)
        public DataKind plaintextKind;

        @Param("ZERO", "ONES", "ASCENDING", "DESCENDING", "RANDOM")
        public DataKind ivKind;

        @Param("ZERO", "ONES", "ASCENDING", "DESCENDING", "RANDOM")
        public DataKind keyKind;

        @Setup
        public void init() {
            cipher = getCipher(KEYS[keyKind], IVS[ivKind]);
        }
    }

    @Benchmark
    public static void testCipher(final Buffer buf) {
        final CipherSpi cipher = buf.cipher;
        final byte[] plaintext = PLAINTEXT[buf.plaintextKind];

        cipher.engineUpdate(plaintext, 0, 512, buf, 0);
        cipher.engineDoFinal(plaintext, 512, 512, buf, 512);
    }
}
