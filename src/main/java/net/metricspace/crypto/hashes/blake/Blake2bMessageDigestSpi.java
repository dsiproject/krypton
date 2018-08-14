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
package net.metricspace.crypto.hashes.blake;

import java.security.DigestException;
import java.security.MessageDigestSpi;

import java.util.Arrays;

import net.metricspace.crypto.hashes.BlockMessageDigestSpi;

/**
 * A {@link MessageDigestSpi} implementation for the Blake2b
 * cryptographic hash family.  Blake was introduced in Aumasson,
 * Henzen, Meier, and Phan in 2008 as a submission to the SHA-3
 * competition.  Blake2 was an update by Aumasson, Neves, O'Hearn, and
 * Winnerlein designed to address flaws in Blake.  Blake2b is the
 * 64-bit variant of Blake2.  Details can be found in <a
 * href="https://tools.ietf.org/html/rfc7693">RFC-7693</a>.
 */
abstract class Blake2bMessageDigestSpi extends BlockMessageDigestSpi {
    private static final int BLOCK_BYTES = 128;
    private static final int BLOCK_WORDS = BLOCK_BYTES / 8;
    private static final int HASH_WORDS = 8;
    private static final int IV_WORDS = 8;
    private static final int STATE_WORDS = HASH_WORDS + IV_WORDS;

    private static final long[] IV =
        new long[] {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
        };

    private final long[] state = new long[STATE_WORDS];
    private final long[] hash = new long[HASH_WORDS];
    private final long[] message = new long[BLOCK_WORDS];
    private final byte[] key;
    private final int hashBytes;

    /**
     * Initialize a {@code Blake2bMessageDigestSpi} with a hash size.
     *
     * @param hashBytes The number of bytes in a hash value.
     */
    protected Blake2bMessageDigestSpi(final int hashBytes) {
        this(hashBytes, new byte[0]);
    }

    /**
     * Initialize a {@code Blake2bMessageDigestSpi} with a hash size
     * and a key.
     *
     * @param hashBytes The number of bytes in a hash value.
     * @param key The key, which can be {@code null} or a zero-length
     *            array for no key.
     */
    protected Blake2bMessageDigestSpi(final int hashBytes,
                                      final byte[] key) {
        super(BLOCK_BYTES);

        if (key.length > BLOCK_BYTES) {
            throw new IllegalArgumentException("Key length exceeds " +
                                               "block length");
        }

        this.hashBytes = hashBytes;
        this.key = key == null ? new byte[0] : key;

        engineReset();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineReset() {
        super.engineReset();

        System.arraycopy(IV, 0, hash, 0, IV_WORDS);
        hash[0] ^= 0x01010000 ^ (key.length << 8) ^ hashBytes;

        if (key.length > 0) {
            System.arraycopy(key, 0, block, 0, key.length);
            Arrays.fill(block, key.length, BLOCK_BYTES, (byte)0);
            inputBytes = BLOCK_BYTES;
            blockOffset = BLOCK_BYTES;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected int engineGetDigestLength() {
        return hashBytes;
    }

    private void mix(final int a,
                     final int b,
                     final int c,
                     final int d,
                     final long x,
                     final long y) {
        state[a] = (state[a] + state[b] + x);
        state[d] = (state[d] ^ state[a]);
        state[d] = (state[d] >>> 32) | (state[d] << 32);
        state[c] = (state[c] + state[d]);
        state[b] = (state[b] ^ state[c]);
        state[b] = (state[b] >>> 24) | (state[b] << 40);
        state[a] = (state[a] + state[b] + y);
        state[d] = (state[d] ^ state[a]);
        state[d] = (state[d] >>> 16) | (state[d] << 48);
        state[c] = (state[c] + state[d]);
        state[b] = (state[b] ^ state[c]);
        state[b] = (state[b] >>> 63) | (state[b] << 1);
    }

    private void processBlock(final boolean last) {
        System.arraycopy(hash, 0, state, 0, HASH_WORDS);
        System.arraycopy(IV, 0, state, HASH_WORDS, IV_WORDS);

        for(int i = 0; i < BLOCK_WORDS; i++) {
            message[i] = ((long)block[8 * i]) & 0xff |
                         (((long)block[(8 * i) + 1]) & 0xff) << 8 |
                         (((long)block[(8 * i) + 2]) & 0xff) << 16 |
                         (((long)block[(8 * i) + 3]) & 0xff) << 24 |
                         (((long)block[(8 * i) + 4]) & 0xff) << 32 |
                         (((long)block[(8 * i) + 5]) & 0xff) << 40 |
                         (((long)block[(8 * i) + 6]) & 0xff) << 48 |
                         (((long)block[(8 * i) + 7]) & 0xff) << 56;
        }

        state[12] ^= inputBytes;

        if (last) {
            state[14] ^= 0xffffffffffffffffL;
        }

        // Round 1

        mix(0, 4,  8, 12, message[0], message[1]);
        mix(1, 5,  9, 13, message[2], message[3]);
        mix(2, 6, 10, 14, message[4], message[5]);
        mix(3, 7, 11, 15, message[6], message[7]);
        mix(0, 5, 10, 15, message[8], message[9]);
        mix(1, 6, 11, 12, message[10], message[11]);
        mix(2, 7,  8, 13, message[12], message[13]);
        mix(3, 4,  9, 14, message[14], message[15]);

        // Round 2

        mix(0, 4,  8, 12, message[14], message[10]);
        mix(1, 5,  9, 13, message[4], message[8]);
        mix(2, 6, 10, 14, message[9], message[15]);
        mix(3, 7, 11, 15, message[13], message[6]);
        mix(0, 5, 10, 15, message[1], message[12]);
        mix(1, 6, 11, 12, message[0], message[2]);
        mix(2, 7,  8, 13, message[11], message[7]);
        mix(3, 4,  9, 14, message[5], message[3]);

        // Round 3

        mix(0, 4,  8, 12, message[11], message[8]);
        mix(1, 5,  9, 13, message[12], message[0]);
        mix(2, 6, 10, 14, message[5], message[2]);
        mix(3, 7, 11, 15, message[15], message[13]);
        mix(0, 5, 10, 15, message[10], message[14]);
        mix(1, 6, 11, 12, message[3], message[6]);
        mix(2, 7,  8, 13, message[7], message[1]);
        mix(3, 4,  9, 14, message[9], message[4]);

        // Round 4

        mix(0, 4,  8, 12, message[7], message[9]);
        mix(1, 5,  9, 13, message[3], message[1]);
        mix(2, 6, 10, 14, message[13], message[12]);
        mix(3, 7, 11, 15, message[11], message[14]);
        mix(0, 5, 10, 15, message[2], message[6]);
        mix(1, 6, 11, 12, message[5], message[10]);
        mix(2, 7,  8, 13, message[4], message[0]);
        mix(3, 4,  9, 14, message[15], message[8]);

        // Round 5

        mix(0, 4,  8, 12, message[9], message[0]);
        mix(1, 5,  9, 13, message[5], message[7]);
        mix(2, 6, 10, 14, message[2], message[4]);
        mix(3, 7, 11, 15, message[10], message[15]);
        mix(0, 5, 10, 15, message[14], message[1]);
        mix(1, 6, 11, 12, message[11], message[12]);
        mix(2, 7,  8, 13, message[6], message[8]);
        mix(3, 4,  9, 14, message[3], message[13]);

        // Round 6

        mix(0, 4,  8, 12, message[2], message[12]);
        mix(1, 5,  9, 13, message[6], message[10]);
        mix(2, 6, 10, 14, message[0], message[11]);
        mix(3, 7, 11, 15, message[8], message[3]);
        mix(0, 5, 10, 15, message[4], message[13]);
        mix(1, 6, 11, 12, message[7], message[5]);
        mix(2, 7,  8, 13, message[15], message[14]);
        mix(3, 4,  9, 14, message[1], message[9]);

        // Round 7

        mix(0, 4,  8, 12, message[12], message[5]);
        mix(1, 5,  9, 13, message[1], message[15]);
        mix(2, 6, 10, 14, message[14], message[13]);
        mix(3, 7, 11, 15, message[4], message[10]);
        mix(0, 5, 10, 15, message[0], message[7]);
        mix(1, 6, 11, 12, message[6], message[3]);
        mix(2, 7,  8, 13, message[9], message[2]);
        mix(3, 4,  9, 14, message[8], message[11]);

        // Round 8

        mix(0, 4,  8, 12, message[13], message[11]);
        mix(1, 5,  9, 13, message[7], message[14]);
        mix(2, 6, 10, 14, message[12], message[1]);
        mix(3, 7, 11, 15, message[3], message[9]);
        mix(0, 5, 10, 15, message[5], message[0]);
        mix(1, 6, 11, 12, message[15], message[4]);
        mix(2, 7,  8, 13, message[8], message[6]);
        mix(3, 4,  9, 14, message[2], message[10]);

        // Round 9

        mix(0, 4,  8, 12, message[6], message[15]);
        mix(1, 5,  9, 13, message[14], message[9]);
        mix(2, 6, 10, 14, message[11], message[3]);
        mix(3, 7, 11, 15, message[0], message[8]);
        mix(0, 5, 10, 15, message[12], message[2]);
        mix(1, 6, 11, 12, message[13], message[7]);
        mix(2, 7,  8, 13, message[1], message[4]);
        mix(3, 4,  9, 14, message[10], message[5]);

        // Round 10

        mix(0, 4,  8, 12, message[10], message[2]);
        mix(1, 5,  9, 13, message[8], message[4]);
        mix(2, 6, 10, 14, message[7], message[6]);
        mix(3, 7, 11, 15, message[1], message[5]);
        mix(0, 5, 10, 15, message[15], message[11]);
        mix(1, 6, 11, 12, message[9], message[14]);
        mix(2, 7,  8, 13, message[3], message[12]);
        mix(3, 4,  9, 14, message[13], message[0]);

        // Round 11

        mix(0, 4,  8, 12, message[0], message[1]);
        mix(1, 5,  9, 13, message[2], message[3]);
        mix(2, 6, 10, 14, message[4], message[5]);
        mix(3, 7, 11, 15, message[6], message[7]);
        mix(0, 5, 10, 15, message[8], message[9]);
        mix(1, 6, 11, 12, message[10], message[11]);
        mix(2, 7,  8, 13, message[12], message[13]);
        mix(3, 4,  9, 14, message[14], message[15]);

        // Round 12

        mix(0, 4,  8, 12, message[14], message[10]);
        mix(1, 5,  9, 13, message[4], message[8]);
        mix(2, 6, 10, 14, message[9], message[15]);
        mix(3, 7, 11, 15, message[13], message[6]);
        mix(0, 5, 10, 15, message[1], message[12]);
        mix(1, 6, 11, 12, message[0], message[2]);
        mix(2, 7,  8, 13, message[11], message[7]);
        mix(3, 4,  9, 14, message[5], message[3]);

        for(int i = 0; i < 8; i++) {
            hash[i] ^= state[i] ^ state[i + 8];
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final int engineDigest(final byte[] output,
                                     final int outputOffset,
                                     final int outputLen)
        throws DigestException {
        if (outputLen < hashBytes) {
            throw new DigestException("Insufficient space for digest");
        }

        Arrays.fill(block, blockOffset, BLOCK_BYTES, (byte)0);
        processBlock(true);

        for(int i = 0; i < HASH_WORDS; i++) {
            output[8 * i] = (byte)(hash[i] & 0xff);
            output[(8 * i) + 1] = (byte)((hash[i] >>> 8) & 0xff);
            output[(8 * i) + 2] = (byte)((hash[i] >>> 16) & 0xff);
            output[(8 * i) + 3] = (byte)((hash[i] >>> 24) & 0xff);
            output[(8 * i) + 4] = (byte)((hash[i] >>> 32) & 0xff);
            output[(8 * i) + 5] = (byte)((hash[i] >>> 40) & 0xff);
            output[(8 * i) + 6] = (byte)((hash[i] >>> 48) & 0xff);
            output[(8 * i) + 7] = (byte)((hash[i] >>> 56) & 0xff);
        }

        return hashBytes;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void processBlock() {
        processBlock(false);
    }
}
