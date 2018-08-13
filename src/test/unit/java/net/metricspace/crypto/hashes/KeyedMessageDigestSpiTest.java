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

import java.util.Arrays;

import java.security.DigestException;
import java.security.MessageDigestSpi;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.hashes.BlockMessageDigestSpi;
import net.metricspace.crypto.providers.KryptonProvider;

@Test(groups = "unit")
public abstract class KeyedMessageDigestSpiTest {
    private final byte[] expectedEmptyHash;
    protected final int hashBytes;

    protected KeyedMessageDigestSpiTest(final int hashBytes,
                                        final byte[] expectedEmptyHash) {
        this.hashBytes = hashBytes;
        this.expectedEmptyHash = expectedEmptyHash;
    }

    protected abstract BlockMessageDigestSpi getMessageDigest();

    protected abstract BlockMessageDigestSpi
        getKeyedMessageDigest(final byte[] key);

    @Test(description = "Test an empty hash")
    public void emptyHashTest()
        throws DigestException {
        final BlockMessageDigestSpi spi = getMessageDigest();
        final byte[] actual = new byte[hashBytes];

        spi.engineDigest(actual, 0, hashBytes);
        Assert.assertEquals(actual, expectedEmptyHash);
    }

    @DataProvider(name = "hash")
    protected abstract Object[][] hashProvider();

    @DataProvider(name = "hashWithKey")
    protected abstract Object[][] hashWithKeyProvider();


    @Test(dataProvider = "hashWithKey",
          description = "Test hash")
    public void hashWithKeyTest(final byte[] input,
                                final byte[] key,
                                final byte[] expected)
        throws DigestException {
        final BlockMessageDigestSpi spi = getKeyedMessageDigest(key);
        final byte[] actual = new byte[hashBytes];

        spi.engineUpdate(input, 0, input.length);
        spi.engineDigest(actual, 0, hashBytes);
        Assert.assertEquals(actual, expected);
    }

    @Test(dataProvider = "hash",
          description = "Test hash")
    public void hashTest(final byte[] input,
                         final byte[] expected)
        throws DigestException {
        final BlockMessageDigestSpi spi = getMessageDigest();
        final byte[] actual = new byte[hashBytes];

        spi.engineUpdate(input, 0, input.length);
        spi.engineDigest(actual, 0, hashBytes);
        Assert.assertEquals(actual, expected);
    }
}
