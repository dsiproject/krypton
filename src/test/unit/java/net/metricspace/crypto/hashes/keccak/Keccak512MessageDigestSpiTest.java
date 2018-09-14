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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import java.security.DigestException;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.hashes.MessageDigestSpiTest;
import net.metricspace.crypto.hashes.keccak.Keccak512MessageDigestSpi;
import net.metricspace.crypto.providers.KryptonProvider;

public class Keccak512MessageDigestSpiTest extends MessageDigestSpiTest {
    private static final byte[] EXPECTED_EMPTY_HASH = new byte[] {
        (byte)0xa6, (byte)0x9f, (byte)0x73, (byte)0xcc,
        (byte)0xa2, (byte)0x3a, (byte)0x9a, (byte)0xc5,
        (byte)0xc8, (byte)0xb5, (byte)0x67, (byte)0xdc,
        (byte)0x18, (byte)0x5a, (byte)0x75, (byte)0x6e,
        (byte)0x97, (byte)0xc9, (byte)0x82, (byte)0x16,
        (byte)0x4f, (byte)0xe2, (byte)0x58, (byte)0x59,
        (byte)0xe0, (byte)0xd1, (byte)0xdc, (byte)0xc1,
        (byte)0x47, (byte)0x5c, (byte)0x80, (byte)0xa6,
        (byte)0x15, (byte)0xb2, (byte)0x12, (byte)0x3a,
        (byte)0xf1, (byte)0xf5, (byte)0xf9, (byte)0x4c,
        (byte)0x11, (byte)0xe3, (byte)0xe9, (byte)0x40,
        (byte)0x2c, (byte)0x3a, (byte)0xc5, (byte)0x58,
        (byte)0xf5, (byte)0x00, (byte)0x19, (byte)0x9d,
        (byte)0x95, (byte)0xb6, (byte)0xd3, (byte)0xe3,
        (byte)0x01, (byte)0x75, (byte)0x85, (byte)0x86,
        (byte)0x28, (byte)0x1d, (byte)0xcd, (byte)0x26
    };

    private static final Object[][] HASH_CASES = new Object[][] {
        new Object[] {
            new byte[] {},
            EXPECTED_EMPTY_HASH
        },
    };

    public Keccak512MessageDigestSpiTest() {
        super(64, EXPECTED_EMPTY_HASH);
    }

    @BeforeClass
    public static void init() {
        KryptonProvider.register();
    }

    @AfterClass
    public static void fini() {
        KryptonProvider.unregister();
    }

    @Override
    @DataProvider(name = "hash")
    protected Object[][] hashProvider() {
        return HASH_CASES;
    }

    @Override
    protected Keccak512MessageDigestSpi getMessageDigest() {
        return new Keccak512MessageDigestSpi();
    }
}
