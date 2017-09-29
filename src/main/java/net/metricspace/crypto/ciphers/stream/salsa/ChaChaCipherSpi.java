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

/**
 * A {@link javax.crypto.CipherSpi} base class for ChaCha{@code n}
 * variants.
 */
public abstract class ChaChaCipherSpi<K extends
                                            SalsaFamilyCipherSpi.SalsaFamilyKey>
    extends SalsaFamilyCipherSpi<K> {
    /**
     * Compute one quarter-round.
     */
    public static void quarterRound(final int a,
                                    final int b,
                                    final int c,
                                    final int d,
                                    final int[] block) {
        block[a] ^= block[b];
        block[d] += block[a];
        block[d] = (block[d] << 16) | (block[d] >>> 48);

        block[c] ^= block[d];
        block[b] += block[c];
        block[b] = (block[b] << 12) | (block[b] >>> 52);

        block[a] ^= block[b];
        block[d] += block[a];
        block[d] = (block[d] << 8) | (block[d] >>> 56);

        block[c] ^= block[d];
        block[b] += block[c];
        block[b] = (block[b] << 7) | (block[b] >>> 57);
    }

    /**
     * Compute one double round (a row round followed by a column round).
     */
    protected final void doubleRound() {
        quarterRound(0, 4, 8, 12, block);
        quarterRound(1, 5, 9, 13, block);
        quarterRound(2, 6, 10, 14, block);
        quarterRound(3, 7, 11, 15, block);
        quarterRound(0, 5, 10, 15, block);
        quarterRound(1, 6, 11, 12, block);
        quarterRound(2, 7, 8, 13, block);
        quarterRound(3, 4, 9, 14, block);
    }
}
