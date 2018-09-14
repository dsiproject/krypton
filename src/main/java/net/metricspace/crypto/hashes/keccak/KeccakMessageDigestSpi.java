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
package net.metricspace.crypto.hashes.keccak;

import java.security.DigestException;
import java.security.MessageDigestSpi;

import java.util.Arrays;

import net.metricspace.crypto.hashes.BlockMessageDigestSpi;

/**
 */
abstract class KeccakMessageDigestSpi extends BlockMessageDigestSpi {
    private static final long[] RC = new long[] {
        0x0000000000000001L,
        0x0000000000008082L,
        0x800000000000808aL,
        0x8000000080008000L,
        0x000000000000808bL,
        0x0000000080000001L,
        0x8000000080008081L,
        0x8000000000008009L,
        0x000000000000008aL,
        0x0000000000000088L,
        0x0000000080008009L,
        0x000000008000000aL,
        0x000000008000808bL,
        0x800000000000008bL,
        0x8000000000008089L,
        0x8000000000008003L,
        0x8000000000008002L,
        0x8000000000000080L,
        0x000000000000800aL,
        0x800000008000000aL,
        0x8000000080008081L,
        0x8000000000008080L,
        0x0000000080000001L,
        0x8000000080008008L
    };

    private final long[][] lanes = new long[5][5];
    private final long[][] tempb = new long[5][5];
    private final long[] tempc = new long[5];
    private final long[] tempd = new long[5];
    private final int hashBytes;
    private final int capacity;
    private final int rate;
    private final int nrounds;

    /**
     * Initialize a {@code KeccakMessageDigestSpi} with a hash size.
     *
     * @param hashBytes The number of bytes in a hash value.
     */
    protected KeccakMessageDigestSpi(final int hashBytes,
                                     final int capacity,
                                     final int rate) {
        super(rate / 8);

        this.hashBytes = hashBytes;
        this.capacity = capacity;
        this.rate = rate;

        switch(capacity + rate) {
        default:
            throw new IllegalArgumentException("");
        case 25:
            this.nrounds = 12;
            break;
        case 50:
            this.nrounds = 14;
            break;
        case 100:
            this.nrounds = 16;
            break;
        case 200:
            this.nrounds = 18;
            break;
        case 400:
            this.nrounds = 20;
            break;
        case 800:
            this.nrounds = 22;
            break;
        case 1600:
            this.nrounds = 24;
            break;
        }

        engineReset();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineReset() {
        super.engineReset();

        Arrays.fill(lanes[0], 0, 5, (long)0);
        Arrays.fill(lanes[1], 0, 5, (long)0);
        Arrays.fill(lanes[2], 0, 5, (long)0);
        Arrays.fill(lanes[3], 0, 5, (long)0);
        Arrays.fill(lanes[4], 0, 5, (long)0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected int engineGetDigestLength() {
        return hashBytes;
    }

    private void round(final long rc) {
        // Theta step

        tempc[0] = lanes[0][0] ^ lanes[0][1] ^ lanes[0][2] ^
            lanes[0][3] ^ lanes[0][4];
        tempc[1] = lanes[1][0] ^ lanes[1][1] ^ lanes[1][2] ^
            lanes[1][3] ^ lanes[1][4];
        tempc[2] = lanes[2][0] ^ lanes[2][1] ^ lanes[2][2] ^
            lanes[2][3] ^ lanes[2][4];
        tempc[3] = lanes[3][0] ^ lanes[3][1] ^ lanes[3][2] ^
            lanes[3][3] ^ lanes[3][4];
        tempc[4] = lanes[4][0] ^ lanes[4][1] ^ lanes[4][2] ^
            lanes[4][3] ^ lanes[4][4];

        tempd[0] = tempc[4] ^ ((tempc[1] << 1) | (tempc[1] >>> 63));
        tempd[1] = tempc[0] ^ ((tempc[2] << 1) | (tempc[2] >>> 63));
        tempd[2] = tempc[1] ^ ((tempc[3] << 1) | (tempc[3] >>> 63));
        tempd[3] = tempc[2] ^ ((tempc[4] << 1) | (tempc[4] >>> 63));
        tempd[4] = tempc[3] ^ ((tempc[0] << 1) | (tempc[0] >>> 63));

        lanes[0][0] ^= tempd[0];
        lanes[0][1] ^= tempd[0];
        lanes[0][2] ^= tempd[0];
        lanes[0][3] ^= tempd[0];
        lanes[0][4] ^= tempd[0];
        lanes[1][0] ^= tempd[1];
        lanes[1][1] ^= tempd[1];
        lanes[1][2] ^= tempd[1];
        lanes[1][3] ^= tempd[1];
        lanes[1][4] ^= tempd[1];
        lanes[2][0] ^= tempd[2];
        lanes[2][1] ^= tempd[2];
        lanes[2][2] ^= tempd[2];
        lanes[2][3] ^= tempd[2];
        lanes[2][4] ^= tempd[2];
        lanes[3][0] ^= tempd[3];
        lanes[3][1] ^= tempd[3];
        lanes[3][2] ^= tempd[3];
        lanes[3][3] ^= tempd[3];
        lanes[3][4] ^= tempd[3];
        lanes[4][0] ^= tempd[4];
        lanes[4][1] ^= tempd[4];
        lanes[4][2] ^= tempd[4];
        lanes[4][3] ^= tempd[4];
        lanes[4][4] ^= tempd[4];

        // Rho and Pi steps

        tempb[0][0] = lanes[0][0];
        tempb[1][3] = ((lanes[0][1] >>> 28) | (lanes[0][1] << 36));
        tempb[2][1] = ((lanes[0][2] >>> 61) | (lanes[0][2] << 3));
        tempb[3][4] = ((lanes[0][3] >>> 23) | (lanes[0][3] << 41));
        tempb[4][2] = ((lanes[0][4] >>> 46) | (lanes[0][4] << 18));

        tempb[0][2] = ((lanes[1][0] >>> 63) | (lanes[1][0] << 1));
        tempb[1][0] = ((lanes[1][1] >>> 20) | (lanes[1][1] << 44));
        tempb[2][3] = ((lanes[1][2] >>> 54) | (lanes[1][2] << 10));
        tempb[3][1] = ((lanes[1][3] >>> 19) | (lanes[1][3] << 45));
        tempb[4][4] = ((lanes[1][4] >>> 62) | (lanes[1][4] << 2));

        tempb[0][4] = ((lanes[2][0] >>> 2) | (lanes[2][0] << 62));
        tempb[1][2] = ((lanes[2][1] >>> 58) | (lanes[2][1] << 6));
        tempb[2][0] = ((lanes[2][2] >>> 21) | (lanes[2][2] << 43));
        tempb[3][3] = ((lanes[2][3] >>> 49) | (lanes[2][3] << 15));
        tempb[4][1] = ((lanes[2][4] >>> 3) | (lanes[2][4] << 61));

        tempb[0][1] = ((lanes[3][0] >>> 36) | (lanes[3][0] << 28));
        tempb[1][4] = ((lanes[3][1] >>> 9) | (lanes[3][1] << 55));
        tempb[2][2] = ((lanes[3][2] >>> 39) | (lanes[3][2] << 25));
        tempb[3][0] = ((lanes[3][3] >>> 43) | (lanes[3][3] << 21));
        tempb[4][3] = ((lanes[3][4] >>> 8) | (lanes[3][4] << 56));

        tempb[0][3] = ((lanes[4][0] >>> 37) | (lanes[4][0] << 27));
        tempb[1][1] = ((lanes[4][1] >>> 44) | (lanes[4][1] << 20));
        tempb[2][4] = ((lanes[4][2] >>> 25) | (lanes[4][2] << 39));
        tempb[3][2] = ((lanes[4][3] >>> 56) | (lanes[4][3] << 8));
        tempb[4][0] = ((lanes[4][4] >>> 50) | (lanes[4][4] << 14));

        // Chi step

        lanes[0][0] = tempb[0][0] ^ ((~tempb[1][0]) & tempb[2][0]);
        lanes[0][1] = tempb[0][1] ^ ((~tempb[1][1]) & tempb[2][1]);
        lanes[0][2] = tempb[0][2] ^ ((~tempb[1][2]) & tempb[2][2]);
        lanes[0][3] = tempb[0][3] ^ ((~tempb[1][3]) & tempb[2][3]);
        lanes[0][4] = tempb[0][4] ^ ((~tempb[1][4]) & tempb[2][4]);
        lanes[1][0] = tempb[1][0] ^ ((~tempb[2][0]) & tempb[3][0]);
        lanes[1][1] = tempb[1][1] ^ ((~tempb[2][1]) & tempb[3][1]);
        lanes[1][2] = tempb[1][2] ^ ((~tempb[2][2]) & tempb[3][2]);
        lanes[1][3] = tempb[1][3] ^ ((~tempb[2][3]) & tempb[3][3]);
        lanes[1][4] = tempb[1][4] ^ ((~tempb[2][4]) & tempb[3][4]);
        lanes[2][0] = tempb[2][0] ^ ((~tempb[3][0]) & tempb[4][0]);
        lanes[2][1] = tempb[2][1] ^ ((~tempb[3][1]) & tempb[4][1]);
        lanes[2][2] = tempb[2][2] ^ ((~tempb[3][2]) & tempb[4][2]);
        lanes[2][3] = tempb[2][3] ^ ((~tempb[3][3]) & tempb[4][3]);
        lanes[2][4] = tempb[2][4] ^ ((~tempb[3][4]) & tempb[4][4]);
        lanes[3][0] = tempb[3][0] ^ ((~tempb[4][0]) & tempb[0][0]);
        lanes[3][1] = tempb[3][1] ^ ((~tempb[4][1]) & tempb[0][1]);
        lanes[3][2] = tempb[3][2] ^ ((~tempb[4][2]) & tempb[0][2]);
        lanes[3][3] = tempb[3][3] ^ ((~tempb[4][3]) & tempb[0][3]);
        lanes[3][4] = tempb[3][4] ^ ((~tempb[4][4]) & tempb[0][4]);
        lanes[4][0] = tempb[4][0] ^ ((~tempb[0][0]) & tempb[1][0]);
        lanes[4][1] = tempb[4][1] ^ ((~tempb[0][1]) & tempb[1][1]);
        lanes[4][2] = tempb[4][2] ^ ((~tempb[0][2]) & tempb[1][2]);
        lanes[4][3] = tempb[4][3] ^ ((~tempb[0][3]) & tempb[1][3]);
        lanes[4][4] = tempb[4][4] ^ ((~tempb[0][4]) & tempb[1][4]);

        // Iota step

        lanes[0][0] = lanes[0][0] ^ rc;
    }

    private void keccakF() {
        for(int i = 0; i < nrounds; i++) {
            round(RC[i]);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void processBlock() {
        for(int i = 0; i < 5; i++) {
            for(int j = 0; j < 5 && (5 * j) + i < rate / 64; j++) {
                final int idx = 8 * ((5 * j) + i);
                final long word = ((long)block[idx]) & 0xff |
                    (((long)block[idx + 1]) & 0xff) << 8 |
                    (((long)block[idx + 2]) & 0xff) << 16 |
                    (((long)block[idx + 3]) & 0xff) << 24 |
                    (((long)block[idx + 4]) & 0xff) << 32 |
                    (((long)block[idx + 5]) & 0xff) << 40 |
                    (((long)block[idx + 6]) & 0xff) << 48 |
                    (((long)block[idx + 7]) & 0xff) << 56;

                lanes[i][j] ^= word;
            }
        }

        keccakF();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final int engineDigest(final byte[] output,
                                     final int outputOffset,
                                     final int outputLen)
        throws DigestException {
        final int rateBytes = rate >> 3;

        if (outputLen > hashBytes) {
            throw new DigestException("Insufficient space for digest");
        }

        if (blockOffset >= rateBytes) {
            processBlock();
            blockOffset = 0;
        }


        block[blockOffset] = (byte)0x06;
        blockOffset++;
        Arrays.fill(block, blockOffset, rateBytes, (byte)0);
        block[rateBytes - 1] ^= (byte)0x80;
        processBlock();

        // Squeezing phase
        exit:
        for(int i = 0;;) {
            for(int j = 0; j < 5; j++) {
                for(int k = 0; k < 5 && (5 * j) + k < rate / 64; k++) {
                    final long word = lanes[k][j];

                    output[i++] = (byte)(word & 0xff);
                    output[i++] = (byte)((word >>> 8) & 0xff);
                    output[i++] = (byte)((word >>> 16) & 0xff);
                    output[i++] = (byte)((word >>> 24) & 0xff);
                    output[i++] = (byte)((word >>> 32) & 0xff);
                    output[i++] = (byte)((word >>> 40) & 0xff);
                    output[i++] = (byte)((word >>> 48) & 0xff);
                    output[i++] = (byte)((word >>> 56) & 0xff);

                    if (i >= hashBytes) {
                        break exit;
                    }
                }
            }

            keccakF();
        }
        System.err.println();

        return hashBytes;
    }
}
