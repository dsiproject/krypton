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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

import net.metricspace.crypto.providers.KryptonProvider;

public abstract class CipherSpiPerf {
    public static enum DataKind { ZERO, ONES, ASCENDING, DESCENDING, RANDOM }

    // This doesn't need to be a SecureRandom, this is just a
    // performance test.
    private static Random random = new Random();
    private static final int PLAINTEXT_SIZE = 1024;
    private static final byte[][] PLAINTEXTS = new byte[5][];

    static {
        PLAINTEXTS[DataKind.ZERO.ordinal()] = new byte[PLAINTEXT_SIZE];
        Arrays.fill(PLAINTEXTS[DataKind.ZERO.ordinal()], (byte)0);

        PLAINTEXTS[DataKind.ONES.ordinal()] = new byte[PLAINTEXT_SIZE];
        Arrays.fill(PLAINTEXTS[DataKind.ONES.ordinal()], (byte)0xff);

        PLAINTEXTS[DataKind.ASCENDING.ordinal()] = new byte[PLAINTEXT_SIZE];

        for(int i = 0; i < PLAINTEXT_SIZE; i++) {
            PLAINTEXTS[DataKind.ASCENDING.ordinal()][i] = (byte)i;
        }

        PLAINTEXTS[DataKind.DESCENDING.ordinal()] = new byte[PLAINTEXT_SIZE];

        for(int i = 0; i < PLAINTEXT_SIZE; i++) {
            PLAINTEXTS[DataKind.DESCENDING.ordinal()][i] =
                (byte)(PLAINTEXT_SIZE - i);
        }

        PLAINTEXTS[DataKind.RANDOM.ordinal()] = new byte[PLAINTEXT_SIZE];
        random.nextBytes(PLAINTEXTS[DataKind.RANDOM.ordinal()]);
    };

    private final int keylen;
    private final int ivlen;
    private final byte[][] IVS;
    private final byte[][] KEYS;

    protected CipherSpiPerf(final int keylen,
                            final int ivlen) {
        this.keylen = keylen;
        this.ivlen = ivlen;
        this.IVS = new byte[5][];
        this.KEYS = new byte[5][];
        this.IVS[DataKind.ZERO.ordinal()] = new byte[ivlen];
        this.IVS[DataKind.ONES.ordinal()] = new byte[ivlen];
        Arrays.fill(IVS[DataKind.ONES.ordinal()], (byte)0xff);
        this.IVS[DataKind.ASCENDING.ordinal()] = new byte[ivlen];

        for(int i = 0; i < ivlen; i++) {
            IVS[DataKind.ASCENDING.ordinal()][i] = (byte)i;
        }

        this.IVS[DataKind.DESCENDING.ordinal()] = new byte[ivlen];

        for(int i = 0; i < ivlen; i++) {
            IVS[DataKind.DESCENDING.ordinal()][i] = (byte)(ivlen - i);
        }

        this.IVS[DataKind.RANDOM.ordinal()] = new byte[ivlen];
        random.nextBytes(IVS[DataKind.RANDOM.ordinal()]);

        this.KEYS[DataKind.ZERO.ordinal()] = new byte[keylen];
        this.KEYS[DataKind.ONES.ordinal()] = new byte[keylen];
        Arrays.fill(KEYS[DataKind.ONES.ordinal()], (byte)0xff);
        this.KEYS[DataKind.ASCENDING.ordinal()] = new byte[keylen];

        for(int i = 0; i < keylen; i++) {
            KEYS[DataKind.ASCENDING.ordinal()][i] = (byte)i;
        }

        this.KEYS[DataKind.DESCENDING.ordinal()] = new byte[keylen];

        for(int i = 0; i < keylen; i++) {
            KEYS[DataKind.DESCENDING.ordinal()][i] = (byte)(keylen - i);
        }

        this.KEYS[DataKind.RANDOM.ordinal()] = new byte[keylen];
        random.nextBytes(KEYS[DataKind.RANDOM.ordinal()]);
    }

    protected abstract Cipher getCipher(final byte[] key,
                                        final byte[] iv)
        throws InvalidKeyException, NoSuchAlgorithmException,
               NoSuchProviderException, InvalidAlgorithmParameterException,
               NoSuchPaddingException;

    @State(Scope.Benchmark)
    private class Buffer {
        public final byte[] buf = new byte[PLAINTEXT_SIZE * 2];
        public Cipher cipher;

        @Param({ "ZERO", "ONES", "ASCENDING", "DESCENDING", "RANDOM" })
        public DataKind plaintextKind;

        @Param({ "ZERO", "ONES", "ASCENDING", "DESCENDING", "RANDOM" })
        public DataKind ivKind;

        @Param({ "ZERO", "ONES", "ASCENDING", "DESCENDING", "RANDOM" })
        public DataKind keyKind;

        public byte[] plaintext;

        @Setup
        public void setup()
            throws InvalidKeyException, NoSuchAlgorithmException,
                   NoSuchProviderException, InvalidAlgorithmParameterException,
                   NoSuchPaddingException {
            KryptonProvider.register();
            cipher = getCipher(KEYS[keyKind.ordinal()],
                               IVS[ivKind.ordinal()]);
            plaintext = PLAINTEXTS[plaintextKind.ordinal()];
        }

        @TearDown
        public void fini() {
            KryptonProvider.unregister();
        }
    }

    @Benchmark
    public static void testCipher(final Buffer buf)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {
        final Cipher cipher = buf.cipher;
        final byte[] plaintext = buf.plaintext;

        cipher.update(plaintext, 0, 512, buf.buf, 0);
        cipher.doFinal(plaintext, 512, 512, buf.buf, 512);
    }
}
