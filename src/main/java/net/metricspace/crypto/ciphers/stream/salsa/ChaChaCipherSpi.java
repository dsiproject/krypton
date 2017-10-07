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
 * A {@link javax.crypto.CipherSpi} base class for ChaCha{@code N}
 * variants.  ChaCha is a sub-family of the Salsa family, introduced
 * by Daniel J. Bernstein in 2008.  ChaCha shares the basic structure
 * of Salsa, but aims to improve on both diffusion and performance.
 * The ChaCha20 variant is used frequently in the modern open-source
 * community.
 * <h2>Usage</h2>
 *
 * This class should not be used directly.  It provides the underlying
 * implementation for the Java Cryptography Architecture (JCA).  See
 * the {@link javax.crypto.Cipher} class documentation for information
 * on how to use this cipher.
 * <h2>Misuses</h2>
 *
 * The following are possible misuses of the ChaCha family ciphers.
 * <ul>
 * <li> <b>Encrypting multiple plaintexts with the same cipher
 * stream</b>: As with other stream ciphers, the ChaCha family's cipher
 * stream is generated solely from the key, IV, and starting position,
 * and is XORed with the plaintext to produce the cipher stream.
 * Thus, if multiple plaintexts are encrypted with the same cipher
 * stream, attackers can recover information about the plaintexts as
 * well as the cipher stream.
 * <li> <b>Re-using initialization vecctors</b>: Reuse of
 * initialization vectors leads to encryption of multiple plaintexts
 * with the same IV.
 * <li> <b>Ciphertext Manipulation</b>: Since encryption/decryption
 * consists of XORing the plaintext/ciphertext by the cipher stream,
 * an attacker can flip bits in the plaintext by flipping them in the
 * ciphertext, unless the message is also protected by a message
 * authentication code (MAC).
 * </ul>
 *
 * @see net.metricspace.crypto.providers.KryptonProvider
 * @see javax.crypto.Cipher
 */
public abstract class
    ChaChaCipherSpi<K extends SalsaFamilyCipherSpi.SalsaFamilyKey>
    extends SalsaFamilyCipherSpi<K> {

    public static void quarterRound(final int a,
                                    final int b,
                                    final int c,
                                    final int d,
                                    final int[] block) {
        block[a] += block[b];
        block[d] ^= block[a];
        block[d] = (block[d] << 16) | (block[d] >>> 48);

        block[c] += block[d];
        block[b] ^= block[c];
        block[b] = (block[b] << 12) | (block[b] >>> 52);

        block[a] += block[b];
        block[d] ^= block[a];
        block[d] = (block[d] << 8) | (block[d] >>> 56);

        block[c] += block[d];
        block[b] ^= block[c];
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

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void addBlock() {
        block[0] += 0x61707865;
        block[1] += 0x3320646e;
        block[2] += 0x79622d32;
        block[3] += 0x6b206574;
        block[4] += key.data[0];
        block[5] += key.data[1];
        block[6] += key.data[2];
        block[7] += key.data[3];
        block[8] += key.data[4];
        block[9] += key.data[5];
        block[10] += key.data[6];
        block[11] += key.data[7];
        block[12] += (int)(blockIdx & 0xffffffffL);
        block[13] += (int)((blockIdx >> 32) & 0xffffffffL);
        block[14] += iv[0] | iv[1] << 8 | iv[2] << 16 | iv[3] << 24;
        block[15] += iv[4] | iv[5] << 8 | iv[6] << 16 | iv[7] << 24;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void initBlock() {
        block[0] = 0x61707865;
        block[1] = 0x3320646e;
        block[2] = 0x79622d32;
        block[3] = 0x6b206574;
        block[4] = key.data[0];
        block[5] = key.data[1];
        block[6] = key.data[2];
        block[7] = key.data[3];
        block[8] = key.data[4];
        block[9] = key.data[5];
        block[10] = key.data[6];
        block[11] = key.data[7];
        block[12] = (int)(blockIdx & 0xffffffffL);
        block[13] = (int)((blockIdx >> 32) & 0xffffffffL);
        block[14] = iv[0] | iv[1] << 8 | iv[2] << 16 | iv[3] << 24;
        block[15] = iv[4] | iv[5] << 8 | iv[6] << 16 | iv[7] << 24;
    }
}
