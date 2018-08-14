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
package net.metricspace.crypto.hashes;

import java.util.Arrays;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.hashes.ripemd.RipeMD160MessageDigestSpi;
import net.metricspace.crypto.providers.KryptonProvider;

@Test(groups = "unit")
public abstract class MessageDigestJCATest {
    private final String hashname;
    private final byte[] expected;
    private final byte[] message;

    protected MessageDigestJCATest(final String hashname,
                                   final byte[] message,
                                   final byte[] expected) {
        this.hashname = hashname;
        this.message = message;
        this.expected = expected;
    };

    @Test(description = "Test hashing byte-by-byte")
    public void testHashOneByte()
        throws NoSuchAlgorithmException {
        final MessageDigest hash = MessageDigest.getInstance(hashname);

        for(int i = 0; i < message.length; i++) {
            hash.update(message[i]);
        }

        final byte[] actual = hash.digest();

        Assert.assertEquals(actual, expected);
    }


    @Test(description = "Test hashing whole message")
    private void testHashWhole()
        throws NoSuchAlgorithmException {
        final MessageDigest hash = MessageDigest.getInstance(hashname);

        hash.update(message, 0, message.length);

        final byte[] actual = hash.digest();

        Assert.assertEquals(actual, expected);
    }

    @Test(description = "Test hashing chunks")
    protected void testHash()
        throws NoSuchAlgorithmException {
        for(int i = 0; i < message.length; i++) {
            doTestHash(i);
        }
    }

    private void doTestHash(final int split)
        throws NoSuchAlgorithmException {
        final MessageDigest hash = MessageDigest.getInstance(hashname);

        hash.update(message, 0, split);
        hash.update(message, split, message.length - split);

        final byte[] actual = hash.digest();

        Assert.assertEquals(actual, expected);
    }
}
