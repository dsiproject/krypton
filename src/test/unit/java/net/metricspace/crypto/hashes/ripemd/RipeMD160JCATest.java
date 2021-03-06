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
package net.metricspace.crypto.hashes.ripemd;

import java.util.Arrays;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import net.metricspace.crypto.hashes.MessageDigestJCATest;
import net.metricspace.crypto.hashes.ripemd.RipeMD160MessageDigestSpi;
import net.metricspace.crypto.providers.KryptonProvider;

@Test(groups = "unit")
public class RipeMD160JCATest extends MessageDigestJCATest {
    private static final byte[] EXPECTED =
        new byte[] {
            (byte)0x7c, (byte)0x4d, (byte)0x36, (byte)0x07,
            (byte)0x0c, (byte)0x1e, (byte)0x11, (byte)0x76,
            (byte)0xb2, (byte)0x96, (byte)0x0a, (byte)0x1b,
            (byte)0x0d, (byte)0xd2, (byte)0x31, (byte)0x9d,
            (byte)0x54, (byte)0x7c, (byte)0xf8, (byte)0xeb
        };
    private static final byte[] ASCENDING =
        new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
            (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
            (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x28, (byte)0x29, (byte)0x2a, (byte)0x2b,
            (byte)0x2c, (byte)0x2d, (byte)0x2e, (byte)0x2f,
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x3a, (byte)0x3b,
            (byte)0x3c, (byte)0x3d, (byte)0x3e, (byte)0x3f,
            (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43,
            (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
            (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b,
            (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f,
            (byte)0x50, (byte)0x51, (byte)0x52, (byte)0x53,
            (byte)0x54, (byte)0x55, (byte)0x56, (byte)0x57,
            (byte)0x58, (byte)0x59, (byte)0x5a, (byte)0x5b,
            (byte)0x5c, (byte)0x5d, (byte)0x5e, (byte)0x5f,
            (byte)0x60, (byte)0x61, (byte)0x62, (byte)0x63,
            (byte)0x64, (byte)0x65, (byte)0x66, (byte)0x67,
            (byte)0x68, (byte)0x69, (byte)0x6a, (byte)0x6b,
            (byte)0x6c, (byte)0x6d, (byte)0x6e, (byte)0x6f,
            (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
            (byte)0x74, (byte)0x75, (byte)0x76, (byte)0x77,
            (byte)0x78, (byte)0x79, (byte)0x7a, (byte)0x7b,
            (byte)0x7c, (byte)0x7d, (byte)0x7e, (byte)0x7f
        };

    public RipeMD160JCATest() {
        super(RipeMD160MessageDigestSpi.NAME, ASCENDING, EXPECTED);

    };

    @BeforeClass
    public static void init() {
        KryptonProvider.register();
    }

    @AfterClass
    public static void fini() {
        KryptonProvider.unregister();
    }
}
