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
package net.metricspace.crypto.hashes;

import java.nio.ByteBuffer;

import java.security.DigestException;
import java.security.MessageDigestSpi;

public abstract class BlockMessageDigestSpi extends MessageDigestSpi {
    protected final int blockBytes;
    protected final byte[] block;
    protected int blockOffset = 0;
    protected long inputBytes = 0;

    /**
     * Initialize a {@code BlockMessageDigestSpi} with its basic
     * components.
     *
     * @param blockBytes The block size in bytes.
     * @param block The block array.
     */
    protected BlockMessageDigestSpi(final int blockBytes,
                                    final byte[] block) {
        this.blockBytes = blockBytes;
        this.block = block;
    }

    /**
     * Initialize a {@code BlockMessageDigestSpi} with its block size.
     *
     * @param blockBytes The block size in bytes.
     */
    protected BlockMessageDigestSpi(final int blockBytes) {
        this(blockBytes, new byte[blockBytes]);
    }

    /**
     * Process a full block of input.
     */
    protected abstract void processBlock();

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineReset() {
        blockOffset = 0;
        inputBytes = 0;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineUpdate(final byte input) {
        block[blockOffset] = input;
        blockOffset++;
        inputBytes++;

        if (blockOffset >= blockBytes) {
            processBlock();
            blockOffset = 0;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineUpdate(final ByteBuffer buf) {
        for(int i = 0; buf.hasRemaining();) {
            final int inputRemaining = buf.remaining() - i;
            final int blockRemaining = blockBytes - blockOffset;
            final int groupLen;

            if (inputRemaining < blockRemaining) {
                groupLen = inputRemaining;
                buf.get(block, blockOffset, groupLen);
                blockOffset += groupLen;
                i += groupLen;
            } else {
                groupLen = blockRemaining;
                buf.get(block, blockOffset, groupLen);
                processBlock();
                blockOffset = 0;
                i += groupLen;
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void engineUpdate(final byte[] input,
                                final int inputOffset,
                                final int inputLen) {
        for(int i = 0; i < inputLen;) {
            final int inputRemaining = inputLen - i;
            final int blockRemaining = blockBytes - blockOffset;
            final int groupLen;

            if (inputRemaining < blockRemaining) {
                groupLen = inputRemaining;
                System.arraycopy(input, inputOffset + i, block,
                                 blockOffset, groupLen);
                blockOffset += groupLen;
                i += groupLen;
            } else {
                groupLen = blockRemaining;
                System.arraycopy(input, inputOffset + i, block,
                                 blockOffset, groupLen);
                processBlock();
                blockOffset = 0;
                i += groupLen;
            }
        }
        inputBytes += inputLen;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final byte[] engineDigest() {
        final int len = engineGetDigestLength();
        final byte[] out = new byte[len];

        try {
            engineDigest(out, 0, len);
        } catch(final DigestException ex) {
            throw new IllegalStateException("Impossible DigestException",
                                            ex);
        }

        return out;
    }
}
