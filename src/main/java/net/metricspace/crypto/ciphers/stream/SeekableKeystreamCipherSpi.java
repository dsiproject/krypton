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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Common superclass of ciphers that generate a stream of blocks that
 * get XORed with plaintext/ciphertext.  This class of ciphers
 * includes almost all stream ciphers as well as block ciphers
 * operating in CTR or OFB mode.
 */
public abstract class
    SeekableKeystreamCipherSpi<K extends SecretKey & Key,
                               S extends IvParameterSpec &
                                         PositionParameterSpec>
    extends KeystreamCipherSpi<K, S> {
    /**
     * Initialize the engine with a block buffer.  This takes
     * possession of the {@code block} array.
     *
     * @param paramSpecClass The {@link Class} of parameter specs.
     * @param block The array that will become the block buffer.
     * @param iv The array that will become the IV buffer.
     */
    protected SeekableKeystreamCipherSpi(final Class<S> paramSpecClass,
                                         final int[] block,
                                         final byte[] iv) {
        super(paramSpecClass, block, iv);
    }

    /**
     * Initialize the engine with a key, a position, and a random
     * initialization vector.  This also recomputes the stream block.
     *
     * @param key The key.
     * @param pos The position.
     * @param random The {@link SecureRandom} to use to generate the
     *               initialization vector.
     * @throws InvalidKeyException If {@code key} is not of type {@code K}.
     */
    protected void engineInit(final K key,
                              final long pos,
                              final SecureRandom random) {
        setPosition(pos);
        super.engineInit(key, random);
    }

    /**
     * Set the key, position, and IV.  This also recomputes the stream
     * block.
     *
     * @param key The key.
     * @param pos The position.
     * @param iv The IV.
     */
    protected void engineInit(final K key,
                              final long pos,
                              final byte[] iv) {
        setPosition(pos);
        super.engineInit(key, iv);
    }

    /**
     * Set the key, position, and IV.  This also recomputes the stream
     * block.
     *
     * @param key The key
     * @param pos The position.
     * @param spec An {@link IvParameterSpec} containing the IV.
     */
    protected void engineInit(final K key,
                              final long pos,
                              final IvParameterSpec spec) {
        engineInit(key, pos, spec.getIV());
    }

    /**
     * Initialize the engine with a key, a position of {@code 0}, and
     * a random initialization vector.  This also recomputes the
     * stream block.
     *
     * @param key The key.
     * @param random The {@link SecureRandom} to use to generate the
     *               initialization vector.
     * @throws InvalidKeyException If {@code key} is not of type {@code K}.
     */
    @Override
    protected void engineInit(final K key,
                              final SecureRandom random) {
        engineInit(key, 0, random);
    }

    /**
     * Set the key and IV, and the position to {@code 0}.  This also
     * recomputes the stream block.
     *
     * @param key The key
     * @param iv The IV.
     */
    @Override
    protected void engineInit(final K key,
                              final byte[] iv) {
        engineInit(key, 0, iv);
    }

    /**
     * Set the key and IV, and the position to {@code 0}.  This also
     * recomputes the stream block.
     *
     * @param key The key
     * @param spec An {@link IvParameterSpec} containing the IV.
     */
    protected void engineInit(final K key,
                              final S spec) {
        setPosition(spec.getPosition());
        super.engineInit(key, spec);
    }

    /**
     * Set the position.
     *
     * @param pos The position.
     */
    protected final void setPosition(final long pos) {
        // Figure out the block index and offsets
        this.blockIdx = pos / blockBytes;
        this.blockOffset = (int)(pos % blockBytes);
    }
}
