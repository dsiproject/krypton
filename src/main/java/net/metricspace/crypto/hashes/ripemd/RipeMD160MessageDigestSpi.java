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
import java.security.MessageDigestSpi;

import net.metricspace.crypto.hashes.BlockMessageDigestSpi;

public final class RipeMD160MessageDigestSpi extends BlockMessageDigestSpi {
    private static final int HASH_BITS = 160;
    private static final int HASH_BYTES = HASH_BITS / 8;
    private static final int HASH_WORDS = HASH_BYTES / 4;
    private static final int BLOCK_BYTES = 64;
    private static final int BLOCK_WORDS = BLOCK_BYTES / 4;

    private final int[] state = new int[5];
    private final int[] wordsblock = new int[BLOCK_WORDS];

    public static final String NAME = "RipeMD-160";

    public RipeMD160MessageDigestSpi() {
        super(BLOCK_BYTES);

        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineReset() {
        super.engineReset();

        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected int engineGetDigestLength() {
        return HASH_BYTES;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final int engineDigest(final byte[] output,
                                     final int outputOffset,
                                     final int outputLen)
        throws DigestException {
        if (outputLen < HASH_BYTES) {
            throw new DigestException("Insufficient space for digest");
        }

        block[blockOffset] = (byte)0x80;
        blockOffset++;

        if (BLOCK_BYTES - blockOffset < 8) {
            Arrays.fill(block, blockOffset, BLOCK_BYTES, (byte)0);
            processBlock();
            blockOffset = 0;
        }

        final long inputBits = inputBytes << 3;

        Arrays.fill(block, blockOffset, BLOCK_BYTES - 8, (byte)0);
        block[BLOCK_BYTES - 8] = (byte)(inputBits & 0xff);
        block[BLOCK_BYTES - 7] = (byte)((inputBits >>> 8) & 0xff);
        block[BLOCK_BYTES - 6] = (byte)((inputBits >>> 16) & 0xff);
        block[BLOCK_BYTES - 5] = (byte)((inputBits >>> 24) & 0xff);
        block[BLOCK_BYTES - 4] = (byte)((inputBits >>> 32) & 0xff);
        block[BLOCK_BYTES - 3] = (byte)((inputBits >>> 40) & 0xff);
        block[BLOCK_BYTES - 2] = (byte)((inputBits >>> 48) & 0xff);
        block[BLOCK_BYTES - 1] = (byte)((inputBits >>> 56) & 0xff);

        processBlock();

        for(int i = 0; i < HASH_WORDS; i++) {
            output[4 * i] = (byte)(state[i] & 0xff);
            output[(4 * i) + 1] = (byte)((state[i] >>> 8) & 0xff);
            output[(4 * i) + 2] = (byte)((state[i] >>> 16) & 0xff);
            output[(4 * i) + 3] = (byte)((state[i] >>> 24) & 0xff);
        }

        return HASH_BYTES;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineUpdate(final byte[] input,
                                final int inputOffset,
                                final int inputLen) {
        super.engineUpdate(input, inputOffset, inputLen);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void processBlock() {
        int a = state[0];
        int b = state[1];
        int c = state[2];
        int d = state[3];
        int e = state[4];
        int aprime = state[0];
        int bprime = state[1];
        int cprime = state[2];
        int dprime = state[3];
        int eprime = state[4];
        int t;

        for(int i = 0; i < BLOCK_WORDS; i++) {
            wordsblock[i] = (block[4 * i] & 0xff) |
                            ((block[(4 * i) + 1] & 0xff) << 8) |
                            ((block[(4 * i) + 2] & 0xff) << 16) |
                            ((block[(4 * i) + 3] & 0xff) << 24);
        }

        /* round 1 */
        // FF(aa, bb, cc, dd, ee, X[ 0], 11);
        a += (b ^ c ^ d) + wordsblock[0];
        a = ((a << 11) | (a >>> 21)) + e;
        c = ((c << 10) | (c >>> 22));

        // FF(ee, aa, bb, cc, dd, X[ 1], 14);
        e += (a ^ b ^ c) + wordsblock[1];
        e = ((e << 14) | (e >>> 18)) + d;
        b = ((b << 10) | (b >>> 22));

        // FF(dd, ee, aa, bb, cc, X[ 2], 15);
        d += (e ^ a ^ b) + wordsblock[2];
        d = ((d << 15) | (d >>> 17)) + c;
        a = ((a << 10) | (a >>> 22));

        // FF(cc, dd, ee, aa, bb, X[ 3], 12);
        c += (d ^ e ^ a) + wordsblock[3];
        c = ((c << 12) | (c >>> 20)) + b;
        e = ((e << 10) | (e >>> 22));

        // FF(bb, cc, dd, ee, aa, X[ 4],  5);
        b += (c ^ d ^ e) + wordsblock[4];
        b = ((b << 5) | (b >>> 27)) + a;
        d = ((d << 10) | (d >>> 22));

        // FF(aa, bb, cc, dd, ee, X[ 5],  8);
        a += (b ^ c ^ d) + wordsblock[5];
        a = ((a << 8) | (a >>> 24)) + e;
        c = ((c << 10) | (c >>> 22));

        // FF(ee, aa, bb, cc, dd, X[ 6],  7);
        e += (a ^ b ^ c) + wordsblock[6];
        e = ((e << 7) | (e >>> 25)) + d;
        b = ((b << 10) | (b >>> 22));

        // FF(dd, ee, aa, bb, cc, X[ 7],  9);
        d += (e ^ a ^ b) + wordsblock[7];
        d = ((d << 9) | (d >>> 23)) + c;
        a = ((a << 10) | (a >>> 22));

        // FF(cc, dd, ee, aa, bb, X[ 8], 11);
        c += (d ^ e ^ a) + wordsblock[8];
        c = ((c << 11) | (c >>> 21)) + b;
        e = ((e << 10) | (e >>> 22));

        // FF(bb, cc, dd, ee, aa, X[ 9], 13);
        b += (c ^ d ^ e) + wordsblock[9];
        b = ((b << 13) | (b >>> 19)) + a;
        d = ((d << 10) | (d >>> 22));

        // FF(aa, bb, cc, dd, ee, X[10], 14);
        a += (b ^ c ^ d) + wordsblock[10];
        a = ((a << 14) | (a >>> 18)) + e;
        c = ((c << 10) | (c >>> 22));

        // FF(ee, aa, bb, cc, dd, X[11], 15);
        e += (a ^ b ^ c) + wordsblock[11];
        e = ((e << 15) | (e >>> 17)) + d;
        b = ((b << 10) | (b >>> 22));

        // FF(dd, ee, aa, bb, cc, X[12],  6);
        d += (e ^ a ^ b) + wordsblock[12];
        d = ((d << 6) | (d >>> 26)) + c;
        a = ((a << 10) | (a >>> 22));

        // FF(cc, dd, ee, aa, bb, X[13],  7);
        c += (d ^ e ^ a) + wordsblock[13];
        c = ((c << 7) | (c >>> 25)) + b;
        e = ((e << 10) | (e >>> 22));

        // FF(bb, cc, dd, ee, aa, X[14],  9);
        b += (c ^ d ^ e) + wordsblock[14];
        b = ((b << 9) | (b >>> 23)) + a;
        d = ((d << 10) | (d >>> 22));

        // FF(aa, bb, cc, dd, ee, X[15],  8);
        a += (b ^ c ^ d) + wordsblock[15];
        a = ((a << 8) | (a >>> 24)) + e;
        c = ((c << 10) | (c >>> 22));

        /* round 2 */
        // GG(ee, aa, bb, cc, dd, X[ 7],  7);
        e += ((a & b) | (~a & c)) + wordsblock[7] + 0x5a827999;
        e = ((e << 7) | (e >>> 25)) + d;
        b = ((b << 10) | (b >>> 22));

        // GG(dd, ee, aa, bb, cc, X[ 4],  6);
        d += ((e & a) | (~e & b)) + wordsblock[4] + 0x5a827999;
        d = ((d << 6) | (d >>> 26)) + c;
        a = ((a << 10) | (a >>> 22));

        // GG(cc, dd, ee, aa, bb, X[13],  8);
        c += ((d & e) | (~d & a)) + wordsblock[13] + 0x5a827999;
        c = ((c << 8) | (c >>> 24)) + b;
        e = ((e << 10) | (e >>> 22));

        // GG(bb, cc, dd, ee, aa, X[ 1], 13);
        b += ((c & d) | (~c & e)) + wordsblock[1] + 0x5a827999;
        b = ((b << 13) | (b >>> 19)) + a;
        d = ((d << 10) | (d >>> 22));

        // GG(aa, bb, cc, dd, ee, X[10], 11);
        a += ((b & c) | (~b & d)) + wordsblock[10] + 0x5a827999;
        a = ((a << 11) | (a >>> 21)) + e;
        c = ((c << 10) | (c >>> 22));

        // GG(ee, aa, bb, cc, dd, X[ 6],  9);
        e += ((a & b) | (~a & c)) + wordsblock[6] + 0x5a827999;
        e = ((e << 9) | (e >>> 23)) + d;
        b = ((b << 10) | (b >>> 22));

        // GG(dd, ee, aa, bb, cc, X[15],  7);
        d += ((e & a) | (~e & b)) + wordsblock[15] + 0x5a827999;
        d = ((d << 7) | (d >>> 25)) + c;
        a = ((a << 10) | (a >>> 22));

        // GG(cc, dd, ee, aa, bb, X[ 3], 15);
        c += ((d & e) | (~d & a)) + wordsblock[3] + 0x5a827999;
        c = ((c << 15) | (c >>> 17)) + b;
        e = ((e << 10) | (e >>> 22));

        // GG(bb, cc, dd, ee, aa, X[12],  7);
        b += ((c & d) | (~c & e)) + wordsblock[12] + 0x5a827999;
        b = ((b << 7) | (b >>> 25)) + a;
        d = ((d << 10) | (d >>> 22));

        // GG(aa, bb, cc, dd, ee, X[ 0], 12);
        a += ((b & c) | (~b & d)) + wordsblock[0] + 0x5a827999;
        a = ((a << 12) | (a >>> 20)) + e;
        c = ((c << 10) | (c >>> 22));

        // GG(ee, aa, bb, cc, dd, X[ 9], 15);
        e += ((a & b) | (~a & c)) + wordsblock[9] + 0x5a827999;
        e = ((e << 15) | (e >>> 17)) + d;
        b = ((b << 10) | (b >>> 22));

        // GG(dd, ee, aa, bb, cc, X[ 5],  9);
        d += ((e & a) | (~e & b)) + wordsblock[5] + 0x5a827999;
        d = ((d << 9) | (d >>> 23)) + c;
        a = ((a << 10) | (a >>> 22));

        // GG(cc, dd, ee, aa, bb, X[ 2], 11);
        c += ((d & e) | (~d & a)) + wordsblock[2] + 0x5a827999;
        c = ((c << 11) | (c >>> 21)) + b;
        e = ((e << 10) | (e >>> 22));

        // GG(bb, cc, dd, ee, aa, X[14],  7);
        b += ((c & d) | (~c & e)) + wordsblock[14] + 0x5a827999;
        b = ((b << 7) | (b >>> 25)) + a;
        d = ((d << 10) | (d >>> 22));

        // GG(aa, bb, cc, dd, ee, X[11], 13);
        a += ((b & c) | (~b & d)) + wordsblock[11] + 0x5a827999;
        a = ((a << 13) | (a >>> 19)) + e;
        c = ((c << 10) | (c >>> 22));

        // GG(ee, aa, bb, cc, dd, X[ 8], 12);
        e += ((a & b) | (~a & c)) + wordsblock[8] + 0x5a827999;
        e = ((e << 12) | (e >>> 20)) + d;
        b = ((b << 10) | (b >>> 22));

        /* round 3 */

        // HH(dd, ee, aa, bb, cc, X[ 3], 11);
        d += ((e | ~a) ^ b) + wordsblock[3] + 0x6ed9eba1;
        d = ((d << 11) | (d >>> 21)) + c;
        a = ((a << 10) | (a >>> 22));

        // HH(cc, dd, ee, aa, bb, X[10], 13);
        c += ((d | ~e) ^ a) + wordsblock[10] + 0x6ed9eba1;
        c = ((c << 13) | (c >>> 19)) + b;
        e = ((e << 10) | (e >>> 22));

        // HH(bb, cc, dd, ee, aa, X[14],  6);
        b += ((c | ~d) ^ e) + wordsblock[14] + 0x6ed9eba1;
        b = ((b << 6) | (b >>> 26)) + a;
        d = ((d << 10) | (d >>> 22));

        // HH(aa, bb, cc, dd, ee, X[ 4],  7);
        a += ((b | ~c) ^ d) + wordsblock[4] + 0x6ed9eba1;
        a = ((a << 7) | (a >>> 25)) + e;
        c = ((c << 10) | (c >>> 22));

        // HH(ee, aa, bb, cc, dd, X[ 9], 14);
        e += ((a | ~b) ^ c) + wordsblock[9] + 0x6ed9eba1;
        e = ((e << 14) | (e >>> 18)) + d;
        b = ((b << 10) | (b >>> 22));

        // HH(dd, ee, aa, bb, cc, X[15],  9);
        d += ((e | ~a) ^ b) + wordsblock[15] + 0x6ed9eba1;
        d = ((d << 9) | (d >>> 23)) + c;
        a = ((a << 10) | (a >>> 22));

        // HH(cc, dd, ee, aa, bb, X[ 8], 13);
        c += ((d | ~e) ^ a) + wordsblock[8] + 0x6ed9eba1;
        c = ((c << 13) | (c >>> 19)) + b;
        e = ((e << 10) | (e >>> 22));

        // HH(bb, cc, dd, ee, aa, X[ 1], 15);
        b += ((c | ~d) ^ e) + wordsblock[1] + 0x6ed9eba1;
        b = ((b << 15) | (b >>> 17)) + a;
        d = ((d << 10) | (d >>> 22));

        // HH(aa, bb, cc, dd, ee, X[ 2], 14);
        a += ((b | ~c) ^ d) + wordsblock[2] + 0x6ed9eba1;
        a = ((a << 14) | (a >>> 18)) + e;
        c = ((c << 10) | (c >>> 22));

        // HH(ee, aa, bb, cc, dd, X[ 7],  8);
        e += ((a | ~b) ^ c) + wordsblock[7] + 0x6ed9eba1;
        e = ((e << 8) | (e >>> 24)) + d;
        b = ((b << 10) | (b >>> 22));

        // HH(dd, ee, aa, bb, cc, X[ 0], 13);
        d += ((e | ~a) ^ b) + wordsblock[0] + 0x6ed9eba1;
        d = ((d << 13) | (d >>> 19)) + c;
        a = ((a << 10) | (a >>> 22));

        // HH(cc, dd, ee, aa, bb, X[ 6],  6);
        c += ((d | ~e) ^ a) + wordsblock[6] + 0x6ed9eba1;
        c = ((c << 6) | (c >>> 26)) + b;
        e = ((e << 10) | (e >>> 22));

        // HH(bb, cc, dd, ee, aa, X[13],  5);
        b += ((c | ~d) ^ e) + wordsblock[13] + 0x6ed9eba1;
        b = ((b << 5) | (b >>> 27)) + a;
        d = ((d << 10) | (d >>> 22));

        // HH(aa, bb, cc, dd, ee, X[11], 12);
        a += ((b | ~c) ^ d) + wordsblock[11] + 0x6ed9eba1;
        a = ((a << 12) | (a >>> 20)) + e;
        c = ((c << 10) | (c >>> 22));

        // HH(ee, aa, bb, cc, dd, X[ 5],  7);
        e += ((a | ~b) ^ c) + wordsblock[5] + 0x6ed9eba1;
        e = ((e << 7) | (e >>> 25)) + d;
        b = ((b << 10) | (b >>> 22));

        // HH(dd, ee, aa, bb, cc, X[12],  5);
        d += ((e | ~a) ^ b) + wordsblock[12] + 0x6ed9eba1;
        d = ((d << 5) | (d >>> 27)) + c;
        a = ((a << 10) | (a >>> 22));

        /* round 4 */

        // II(cc, dd, ee, aa, bb, X[ 1], 11);
        c += ((d & a) | (e & ~a)) + wordsblock[1] + 0x8f1bbcdc;
        c = ((c << 11) | (c >>> 21)) + b;
        e = ((e << 10) | (e >>> 22));

        // II(bb, cc, dd, ee, aa, X[ 9], 12);
        b += ((c & e) | (d & ~e)) + wordsblock[9] + 0x8f1bbcdc;
        b = ((b << 12) | (b >>> 20)) + a;
        d = ((d << 10) | (d >>> 22));

        // II(aa, bb, cc, dd, ee, X[11], 14);
        a += ((b & d) | (c & ~d)) + wordsblock[11] + 0x8f1bbcdc;
        a = ((a << 14) | (a >>> 18)) + e;
        c = ((c << 10) | (c >>> 22));

        // II(ee, aa, bb, cc, dd, X[10], 15);
        e += ((a & c) | (b & ~c)) + wordsblock[10] + 0x8f1bbcdc;
        e = ((e << 15) | (e >>> 17)) + d;
        b = ((b << 10) | (b >>> 22));

        // II(dd, ee, aa, bb, cc, X[ 0], 14);
        d += ((e & b) | (a & ~b)) + wordsblock[0] + 0x8f1bbcdc;
        d = ((d << 14) | (d >>> 18)) + c;
        a = ((a << 10) | (a >>> 22));

        // II(cc, dd, ee, aa, bb, X[ 8], 15);
        c += ((d & a) | (e & ~a)) + wordsblock[8] + 0x8f1bbcdc;
        c = ((c << 15) | (c >>> 17)) + b;
        e = ((e << 10) | (e >>> 22));

        // II(bb, cc, dd, ee, aa, X[12],  9);
        b += ((c & e) | (d & ~e)) + wordsblock[12] + 0x8f1bbcdc;
        b = ((b << 9) | (b >>> 23)) + a;
        d = ((d << 10) | (d >>> 22));

        // II(aa, bb, cc, dd, ee, X[ 4],  8);
        a += ((b & d) | (c & ~d)) + wordsblock[4] + 0x8f1bbcdc;
        a = ((a << 8) | (a >>> 24)) + e;
        c = ((c << 10) | (c >>> 22));

        // II(ee, aa, bb, cc, dd, X[13],  9);
        e += ((a & c) | (b & ~c)) + wordsblock[13] + 0x8f1bbcdc;
        e = ((e << 9) | (e >>> 23)) + d;
        b = ((b << 10) | (b >>> 22));

        // II(dd, ee, aa, bb, cc, X[ 3], 14);
        d += ((e & b) | (a & ~b)) + wordsblock[3] + 0x8f1bbcdc;
        d = ((d << 14) | (d >>> 18)) + c;
        a = ((a << 10) | (a >>> 22));

        // II(cc, dd, ee, aa, bb, X[ 7],  5);
        c += ((d & a) | (e & ~a)) + wordsblock[7] + 0x8f1bbcdc;
        c = ((c << 5) | (c >>> 27)) + b;
        e = ((e << 10) | (e >>> 22));

        // II(bb, cc, dd, ee, aa, X[15],  6);
        b += ((c & e) | (d & ~e)) + wordsblock[15] + 0x8f1bbcdc;
        b = ((b << 6) | (b >>> 26)) + a;
        d = ((d << 10) | (d >>> 22));

        // II(aa, bb, cc, dd, ee, X[14],  8);
        a += ((b & d) | (c & ~d)) + wordsblock[14] + 0x8f1bbcdc;
        a = ((a << 8) | (a >>> 24)) + e;
        c = ((c << 10) | (c >>> 22));

        // II(ee, aa, bb, cc, dd, X[ 5],  6);
        e += ((a & c) | (b & ~c)) + wordsblock[5] + 0x8f1bbcdc;
        e = ((e << 6) | (e >>> 26)) + d;
        b = ((b << 10) | (b >>> 22));

        // II(dd, ee, aa, bb, cc, X[ 6],  5);
        d += ((e & b) | (a & ~b)) + wordsblock[6] + 0x8f1bbcdc;
        d = ((d << 5) | (d >>> 27)) + c;
        a = ((a << 10) | (a >>> 22));

        // II(cc, dd, ee, aa, bb, X[ 2], 12);
        c += ((d & a) | (e & ~a)) + wordsblock[2] + 0x8f1bbcdc;
        c = ((c << 12) | (c >>> 20)) + b;
        e = ((e << 10) | (e >>> 22));

        /* round 5 */

        // JJ(bb, cc, dd, ee, aa, X[ 4],  9);
        b += (c ^ (d | ~e)) + wordsblock[4] + 0xa953fd4e;
        b = ((b << 9) | (b >>> 23)) + a;
        d = ((d << 10) | (d >>> 22));

        // JJ(aa, bb, cc, dd, ee, X[ 0], 15);
        a += (b ^ (c | ~d)) + wordsblock[0] + 0xa953fd4e;
        a = ((a << 15) | (a >>> 17)) + e;
        c = ((c << 10) | (c >>> 22));

        // JJ(ee, aa, bb, cc, dd, X[ 5],  5);
        e += (a ^ (b | ~c)) + wordsblock[5] + 0xa953fd4e;
        e = ((e << 5) | (e >>> 27)) + d;
        b = ((b << 10) | (b >>> 22));

        // JJ(dd, ee, aa, bb, cc, X[ 9], 11);
        d += (e ^ (a | ~b)) + wordsblock[9] + 0xa953fd4e;
        d = ((d << 11) | (d >>> 21)) + c;
        a = ((a << 10) | (a >>> 22));

        // JJ(cc, dd, ee, aa, bb, X[ 7],  6);
        c += (d ^ (e | ~a)) + wordsblock[7] + 0xa953fd4e;
        c = ((c << 6) | (c >>> 26)) + b;
        e = ((e << 10) | (e >>> 22));

        // JJ(bb, cc, dd, ee, aa, X[12],  8);
        b += (c ^ (d | ~e)) + wordsblock[12] + 0xa953fd4e;
        b = ((b << 8) | (b >>> 24)) + a;
        d = ((d << 10) | (d >>> 22));

        // JJ(aa, bb, cc, dd, ee, X[ 2], 13);
        a += (b ^ (c | ~d)) + wordsblock[2] + 0xa953fd4e;
        a = ((a << 13) | (a >>> 19)) + e;
        c = ((c << 10) | (c >>> 22));

        // JJ(ee, aa, bb, cc, dd, X[10], 12);
        e += (a ^ (b | ~c)) + wordsblock[10] + 0xa953fd4e;
        e = ((e << 12) | (e >>> 20)) + d;
        b = ((b << 10) | (b >>> 22));

        // JJ(dd, ee, aa, bb, cc, X[14],  5);
        d += (e ^ (a | ~b)) + wordsblock[14] + 0xa953fd4e;
        d = ((d << 5) | (d >>> 27)) + c;
        a = ((a << 10) | (a >>> 22));

        // JJ(cc, dd, ee, aa, bb, X[ 1], 12);
        c += (d ^ (e | ~a)) + wordsblock[1] + 0xa953fd4e;
        c = ((c << 12) | (c >>> 20)) + b;
        e = ((e << 10) | (e >>> 22));

        // JJ(bb, cc, dd, ee, aa, X[ 3], 13);
        b += (c ^ (d | ~e)) + wordsblock[3] + 0xa953fd4e;
        b = ((b << 13) | (b >>> 19)) + a;
        d = ((d << 10) | (d >>> 22));

        // JJ(aa, bb, cc, dd, ee, X[ 8], 14);
        a += (b ^ (c | ~d)) + wordsblock[8] + 0xa953fd4e;
        a = ((a << 14) | (a >>> 18)) + e;
        c = ((c << 10) | (c >>> 22));

        // JJ(ee, aa, bb, cc, dd, X[11], 11);
        e += (a ^ (b | ~c)) + wordsblock[11] + 0xa953fd4e;
        e = ((e << 11) | (e >>> 21)) + d;
        b = ((b << 10) | (b >>> 22));

        // JJ(dd, ee, aa, bb, cc, X[ 6],  8);
        d += (e ^ (a | ~b)) + wordsblock[6] + 0xa953fd4e;
        d = ((d << 8) | (d >>> 24)) + c;
        a = ((a << 10) | (a >>> 22));

        // JJ(cc, dd, ee, aa, bb, X[15],  5);
        c += (d ^ (e | ~a)) + wordsblock[15] + 0xa953fd4e;
        c = ((c << 5) | (c >>> 27)) + b;
        e = ((e << 10) | (e >>> 22));

        // JJ(bb, cc, dd, ee, aa, X[13],  6);
        b += (c ^ (d | ~e)) + wordsblock[13] + 0xa953fd4e;
        b = ((b << 6) | (b >>> 26)) + a;
        d = ((d << 10) | (d >>> 22));

        /* parallel round 1 */

        // JJJ(aaa, bbb, ccc, ddd, eee, X[ 5],  8);
        aprime += (bprime ^ (cprime | ~dprime)) + wordsblock[5] + 0x50a28be6;
        aprime = ((aprime << 8) | (aprime >>> 24)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // JJJ(eee, aaa, bbb, ccc, ddd, X[14],  9);
        eprime += (aprime ^ (bprime | ~cprime)) + wordsblock[14] + 0x50a28be6;
        eprime = ((eprime << 9) | (eprime >>> 23)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // JJJ(ddd, eee, aaa, bbb, ccc, X[ 7],  9);
        dprime += (eprime ^ (aprime | ~bprime)) + wordsblock[7] + 0x50a28be6;
        dprime = ((dprime << 9) | (dprime >>> 23)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // JJJ(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
        cprime += (dprime ^ (eprime | ~aprime)) + wordsblock[0] + 0x50a28be6;
        cprime = ((cprime << 11) | (cprime >>> 21)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // JJJ(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
        bprime += (cprime ^ (dprime | ~eprime)) + wordsblock[9] + 0x50a28be6;
        bprime = ((bprime << 13) | (bprime >>> 19)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // JJJ(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
        aprime += (bprime ^ (cprime | ~dprime)) + wordsblock[2] + 0x50a28be6;
        aprime = ((aprime << 15) | (aprime >>> 17)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15);
        eprime += (aprime ^ (bprime | ~cprime)) + wordsblock[11] + 0x50a28be6;
        eprime = ((eprime << 15) | (eprime >>> 17)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // JJJ(ddd, eee, aaa, bbb, ccc, X[ 4],  5);
        dprime += (eprime ^ (aprime | ~bprime)) + wordsblock[4] + 0x50a28be6;
        dprime = ((dprime << 5) | (dprime >>> 27)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // JJJ(ccc, ddd, eee, aaa, bbb, X[13],  7);
        cprime += (dprime ^ (eprime | ~aprime)) + wordsblock[13] + 0x50a28be6;
        cprime = ((cprime << 7) | (cprime >>> 25)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // JJJ(bbb, ccc, ddd, eee, aaa, X[ 6],  7);
        bprime += (cprime ^ (dprime | ~eprime)) + wordsblock[6] + 0x50a28be6;
        bprime = ((bprime << 7) | (bprime >>> 25)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // JJJ(aaa, bbb, ccc, ddd, eee, X[15],  8);
        aprime += (bprime ^ (cprime | ~dprime)) + wordsblock[15] + 0x50a28be6;
        aprime = ((aprime << 8) | (aprime >>> 24)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // JJJ(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
        eprime += (aprime ^ (bprime | ~cprime)) + wordsblock[8] + 0x50a28be6;
        eprime = ((eprime << 11) | (eprime >>> 21)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // JJJ(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
        dprime += (eprime ^ (aprime | ~bprime)) + wordsblock[1] + 0x50a28be6;
        dprime = ((dprime << 14) | (dprime >>> 18)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14);
        cprime += (dprime ^ (eprime | ~aprime)) + wordsblock[10] + 0x50a28be6;
        cprime = ((cprime << 14) | (cprime >>> 18)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // JJJ(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
        bprime += (cprime ^ (dprime | ~eprime)) + wordsblock[3] + 0x50a28be6;
        bprime = ((bprime << 12) | (bprime >>> 20)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // JJJ(aaa, bbb, ccc, ddd, eee, X[12],  6);
        aprime += (bprime ^ (cprime | ~dprime)) + wordsblock[12] + 0x50a28be6;
        aprime = ((aprime << 6) | (aprime >>> 26)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        /* parallel round 2 */

        // III(eee, aaa, bbb, ccc, ddd, X[ 6],  9);
        eprime += ((aprime & cprime) | (bprime & ~cprime)) +
            wordsblock[6] + 0x5c4dd124;
        eprime = ((eprime << 9) | (eprime >>> 23)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // III(ddd, eee, aaa, bbb, ccc, X[11], 13);
        dprime += ((eprime & bprime) | (aprime & ~bprime)) +
            wordsblock[11] + 0x5c4dd124;
        dprime = ((dprime << 13) | (dprime >>> 19)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // III(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
        cprime += ((dprime & aprime) | (eprime & ~aprime)) +
            wordsblock[3] + 0x5c4dd124;
        cprime = ((cprime << 15) | (cprime >>> 17)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // III(bbb, ccc, ddd, eee, aaa, X[ 7],  7);
        bprime += ((cprime & eprime) | (dprime & ~eprime)) +
            wordsblock[7] + 0x5c4dd124;
        bprime = ((bprime << 7) | (bprime >>> 25)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // III(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
        aprime += ((bprime & dprime) | (cprime & ~dprime)) +
            wordsblock[0] + 0x5c4dd124;
        aprime = ((aprime << 12) | (aprime >>> 20)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // III(eee, aaa, bbb, ccc, ddd, X[13],  8);
        eprime += ((aprime & cprime) | (bprime & ~cprime)) +
            wordsblock[13] + 0x5c4dd124;
        eprime = ((eprime << 8) | (eprime >>> 24)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // III(ddd, eee, aaa, bbb, ccc, X[ 5],  9);
        dprime += ((eprime & bprime) | (aprime & ~bprime)) +
            wordsblock[5] + 0x5c4dd124;
        dprime = ((dprime << 9) | (dprime >>> 23)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // III(ccc, ddd, eee, aaa, bbb, X[10], 11);
        cprime += ((dprime & aprime) | (eprime & ~aprime)) +
            wordsblock[10] + 0x5c4dd124;
        cprime = ((cprime << 11) | (cprime >>> 21)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // III(bbb, ccc, ddd, eee, aaa, X[14],  7);
        bprime += ((cprime & eprime) | (dprime & ~eprime)) +
            wordsblock[14] + 0x5c4dd124;
        bprime = ((bprime << 7) | (bprime >>> 25)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // III(aaa, bbb, ccc, ddd, eee, X[15],  7);
        aprime += ((bprime & dprime) | (cprime & ~dprime)) +
            wordsblock[15] + 0x5c4dd124;
        aprime = ((aprime << 7) | (aprime >>> 25)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // III(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
        eprime += ((aprime & cprime) | (bprime & ~cprime)) +
            wordsblock[8] + 0x5c4dd124;
        eprime = ((eprime << 12) | (eprime >>> 20)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // III(ddd, eee, aaa, bbb, ccc, X[12],  7);
        dprime += ((eprime & bprime) | (aprime & ~bprime)) +
            wordsblock[12] + 0x5c4dd124;
        dprime = ((dprime << 7) | (dprime >>> 25)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // III(ccc, ddd, eee, aaa, bbb, X[ 4],  6);
        cprime += ((dprime & aprime) | (eprime & ~aprime)) +
            wordsblock[4] + 0x5c4dd124;
        cprime = ((cprime << 6) | (cprime >>> 26)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // III(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
        bprime += ((cprime & eprime) | (dprime & ~eprime)) +
            wordsblock[9] + 0x5c4dd124;
        bprime = ((bprime << 15) | (bprime >>> 17)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // III(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
        aprime += ((bprime & dprime) | (cprime & ~dprime)) +
            wordsblock[1] + 0x5c4dd124;
        aprime = ((aprime << 13) | (aprime >>> 19)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // III(eee, aaa, bbb, ccc, ddd, X[ 2], 11);
        eprime += ((aprime & cprime) | (bprime & ~cprime)) +
            wordsblock[2] + 0x5c4dd124;
        eprime = ((eprime << 11) | (eprime >>> 21)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        /* parallel round 3 */

        // HHH(ddd, eee, aaa, bbb, ccc, X[15],  9);
        dprime += ((eprime | ~aprime) ^ bprime) + wordsblock[15] + 0x6d703ef3;
        dprime = ((dprime << 9) | (dprime >>> 23)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // HHH(ccc, ddd, eee, aaa, bbb, X[ 5],  7);
        cprime += ((dprime | ~eprime) ^ aprime) + wordsblock[5] + 0x6d703ef3;
        cprime = ((cprime << 7) | (cprime >>> 25)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // HHH(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
        bprime += ((cprime | ~dprime) ^ eprime) + wordsblock[1] + 0x6d703ef3;
        bprime = ((bprime << 15) | (bprime >>> 17)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // HHH(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
        aprime += ((bprime | ~cprime) ^ dprime) + wordsblock[3] + 0x6d703ef3;
        aprime = ((aprime << 11) | (aprime >>> 21)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // HHH(eee, aaa, bbb, ccc, ddd, X[ 7],  8);
        eprime += ((aprime | ~bprime) ^ cprime) + wordsblock[7] + 0x6d703ef3;
        eprime = ((eprime << 8) | (eprime >>> 24)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // HHH(ddd, eee, aaa, bbb, ccc, X[14],  6);
        dprime += ((eprime | ~aprime) ^ bprime) + wordsblock[14] + 0x6d703ef3;
        dprime = ((dprime << 6) | (dprime >>> 26)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // HHH(ccc, ddd, eee, aaa, bbb, X[ 6],  6);
        cprime += ((dprime | ~eprime) ^ aprime) + wordsblock[6] + 0x6d703ef3;
        cprime = ((cprime << 6) | (cprime >>> 26)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // HHH(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
        bprime += ((cprime | ~dprime) ^ eprime) + wordsblock[9] + 0x6d703ef3;
        bprime = ((bprime << 14) | (bprime >>> 18)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // HHH(aaa, bbb, ccc, ddd, eee, X[11], 12);
        aprime += ((bprime | ~cprime) ^ dprime) + wordsblock[11] + 0x6d703ef3;
        aprime = ((aprime << 12) | (aprime >>> 20)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // HHH(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
        eprime += ((aprime | ~bprime) ^ cprime) + wordsblock[8] + 0x6d703ef3;
        eprime = ((eprime << 13) | (eprime >>> 19)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // HHH(ddd, eee, aaa, bbb, ccc, X[12],  5);
        dprime += ((eprime | ~aprime) ^ bprime) + wordsblock[12] + 0x6d703ef3;
        dprime = ((dprime << 5) | (dprime >>> 27)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // HHH(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
        cprime += ((dprime | ~eprime) ^ aprime) + wordsblock[2] + 0x6d703ef3;
        cprime = ((cprime << 14) | (cprime >>> 18)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // HHH(bbb, ccc, ddd, eee, aaa, X[10], 13);
        bprime += ((cprime | ~dprime) ^ eprime) + wordsblock[10] + 0x6d703ef3;
        bprime = ((bprime << 13) | (bprime >>> 19)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // HHH(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
        aprime += ((bprime | ~cprime) ^ dprime) + wordsblock[0] + 0x6d703ef3;
        aprime = ((aprime << 13) | (aprime >>> 19)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // HHH(eee, aaa, bbb, ccc, ddd, X[ 4],  7);
        eprime += ((aprime | ~bprime) ^ cprime) + wordsblock[4] + 0x6d703ef3;
        eprime = ((eprime << 7) | (eprime >>> 25)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // HHH(ddd, eee, aaa, bbb, ccc, X[13],  5);
        dprime += ((eprime | ~aprime) ^ bprime) + wordsblock[13] + 0x6d703ef3;
        dprime = ((dprime << 5) | (dprime >>> 27)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        /* parallel round 4 */

        // GGG(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
        cprime += ((dprime & eprime) | (~dprime & aprime)) +
            wordsblock[8] + 0x7a6d76e9;
        cprime = ((cprime << 15) | (cprime >>> 17)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // GGG(bbb, ccc, ddd, eee, aaa, X[ 6],  5);
        bprime += ((cprime & dprime) | (~cprime & eprime)) +
            wordsblock[6] + 0x7a6d76e9;
        bprime = ((bprime << 5) | (bprime >>> 27)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // GGG(aaa, bbb, ccc, ddd, eee, X[ 4],  8);
        aprime += ((bprime & cprime) | (~bprime & dprime)) +
            wordsblock[4] + 0x7a6d76e9;
        aprime = ((aprime << 8) | (aprime >>> 24)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // GGG(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
        eprime += ((aprime & bprime) | (~aprime & cprime)) +
            wordsblock[1] + 0x7a6d76e9;
        eprime = ((eprime << 11) | (eprime >>> 21)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));


        // GGG(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
        dprime += ((eprime & aprime) | (~eprime & bprime)) +
            wordsblock[3] + 0x7a6d76e9;
        dprime = ((dprime << 14) | (dprime >>> 18)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
        cprime += ((dprime & eprime) | (~dprime & aprime)) +
            wordsblock[11] + 0x7a6d76e9;
        cprime = ((cprime << 14) | (cprime >>> 18)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // GGG(bbb, ccc, ddd, eee, aaa, X[15],  6);
        bprime += ((cprime & dprime) | (~cprime & eprime)) +
            wordsblock[15] + 0x7a6d76e9;
        bprime = ((bprime << 6) | (bprime >>> 26)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // GGG(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
        aprime += ((bprime & cprime) | (~bprime & dprime)) +
            wordsblock[0] + 0x7a6d76e9;
        aprime = ((aprime << 14) | (aprime >>> 18)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // GGG(eee, aaa, bbb, ccc, ddd, X[ 5],  6);
        eprime += ((aprime & bprime) | (~aprime & cprime)) +
            wordsblock[5] + 0x7a6d76e9;
        eprime = ((eprime << 6) | (eprime >>> 26)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // GGG(ddd, eee, aaa, bbb, ccc, X[12],  9);
        dprime += ((eprime & aprime) | (~eprime & bprime)) +
            wordsblock[12] + 0x7a6d76e9;
        dprime = ((dprime << 9) | (dprime >>> 23)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // GGG(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
        cprime += ((dprime & eprime) | (~dprime & aprime)) +
            wordsblock[2] + 0x7a6d76e9;
        cprime = ((cprime << 12) | (cprime >>> 20)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // GGG(bbb, ccc, ddd, eee, aaa, X[13],  9);
        bprime += ((cprime & dprime) | (~cprime & eprime)) +
            wordsblock[13] + 0x7a6d76e9;
        bprime = ((bprime << 9) | (bprime >>> 23)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // GGG(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
        aprime += ((bprime & cprime) | (~bprime & dprime)) +
            wordsblock[9] + 0x7a6d76e9;
        aprime = ((aprime << 12) | (aprime >>> 20)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // GGG(eee, aaa, bbb, ccc, ddd, X[ 7],  5);
        eprime += ((aprime & bprime) | (~aprime & cprime)) +
            wordsblock[7] + 0x7a6d76e9;
        eprime = ((eprime << 5) | (eprime >>> 27)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // GGG(ddd, eee, aaa, bbb, ccc, X[10], 15);
        dprime += ((eprime & aprime) | (~eprime & bprime)) +
            wordsblock[10] + 0x7a6d76e9;
        dprime = ((dprime << 15) | (dprime >>> 17)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // GGG(ccc, ddd, eee, aaa, bbb, X[14],  8);
        cprime += ((dprime & eprime) | (~dprime & aprime)) +
            wordsblock[14] + 0x7a6d76e9;
        cprime = ((cprime << 8) | (cprime >>> 24)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        /* parallel round 5 */

        // FFF(bbb, ccc, ddd, eee, aaa, X[12] ,  8);
        bprime += (cprime ^ dprime ^ eprime) + wordsblock[12];
        bprime = ((bprime << 8) | (bprime >>> 24)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // FFF(aaa, bbb, ccc, ddd, eee, X[15] ,  5);
        aprime += (bprime ^ cprime ^ dprime) + wordsblock[15];
        aprime = ((aprime << 5) | (aprime >>> 27)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // FFF(eee, aaa, bbb, ccc, ddd, X[10] , 12);
        eprime += (aprime ^ bprime ^ cprime) + wordsblock[10];
        eprime = ((eprime << 12) | (eprime >>> 20)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // FFF(ddd, eee, aaa, bbb, ccc, X[ 4] ,  9);
        dprime += (eprime ^ aprime ^ bprime) + wordsblock[4];
        dprime = ((dprime << 9) | (dprime >>> 23)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // FFF(ccc, ddd, eee, aaa, bbb, X[ 1] , 12);
        cprime += (dprime ^ eprime ^ aprime) + wordsblock[1];
        cprime = ((cprime << 12) | (cprime >>> 20)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // FFF(bbb, ccc, ddd, eee, aaa, X[ 5] ,  5);
        bprime += (cprime ^ dprime ^ eprime) + wordsblock[5];
        bprime = ((bprime << 5) | (bprime >>> 27)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // FFF(aaa, bbb, ccc, ddd, eee, X[ 8] , 14);
        aprime += (bprime ^ cprime ^ dprime) + wordsblock[8];
        aprime = ((aprime << 14) | (aprime >>> 18)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // FFF(eee, aaa, bbb, ccc, ddd, X[ 7] ,  6);
        eprime += (aprime ^ bprime ^ cprime) + wordsblock[7];
        eprime = ((eprime << 6) | (eprime >>> 26)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // FFF(ddd, eee, aaa, bbb, ccc, X[ 6] ,  8);
        dprime += (eprime ^ aprime ^ bprime) + wordsblock[6];
        dprime = ((dprime << 8) | (dprime >>> 24)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // FFF(ccc, ddd, eee, aaa, bbb, X[ 2] , 13);
        cprime += (dprime ^ eprime ^ aprime) + wordsblock[2];
        cprime = ((cprime << 13) | (cprime >>> 19)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // FFF(bbb, ccc, ddd, eee, aaa, X[13] ,  6);
        bprime += (cprime ^ dprime ^ eprime) + wordsblock[13];
        bprime = ((bprime << 6) | (bprime >>> 26)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        // FFF(aaa, bbb, ccc, ddd, eee, X[14] ,  5);
        aprime += (bprime ^ cprime ^ dprime) + wordsblock[14];
        aprime = ((aprime << 5) | (aprime >>> 27)) + eprime;
        cprime = ((cprime << 10) | (cprime >>> 22));

        // FFF(eee, aaa, bbb, ccc, ddd, X[ 0] , 15);
        eprime += (aprime ^ bprime ^ cprime) + wordsblock[0];
        eprime = ((eprime << 15) | (eprime >>> 17)) + dprime;
        bprime = ((bprime << 10) | (bprime >>> 22));

        // FFF(ddd, eee, aaa, bbb, ccc, X[ 3] , 13);
        dprime += (eprime ^ aprime ^ bprime) + wordsblock[3];
        dprime = ((dprime << 13) | (dprime >>> 19)) + cprime;
        aprime = ((aprime << 10) | (aprime >>> 22));

        // FFF(ccc, ddd, eee, aaa, bbb, X[ 9] , 11);
        cprime += (dprime ^ eprime ^ aprime) + wordsblock[9];
        cprime = ((cprime << 11) | (cprime >>> 21)) + bprime;
        eprime = ((eprime << 10) | (eprime >>> 22));

        // FFF(bbb, ccc, ddd, eee, aaa, X[11] , 11);
        bprime += (cprime ^ dprime ^ eprime) + wordsblock[11];
        bprime = ((bprime << 11) | (bprime >>> 21)) + aprime;
        dprime = ((dprime << 10) | (dprime >>> 22));

        dprime += c + state[1];
        state[1] = state[2] + d + eprime;
        state[2] = state[3] + e + aprime;
        state[3] = state[4] + a + bprime;
        state[4] = state[0] + b + cprime;
        state[0] = dprime;
    }
}
