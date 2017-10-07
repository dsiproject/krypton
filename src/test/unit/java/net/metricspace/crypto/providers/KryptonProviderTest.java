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
package net.metricspace.crypto.providers;

import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class KryptonProviderTest {
    @BeforeClass
    public static void init() {
        KryptonProvider.register();
    }

    @AfterClass
    public static void fini() {
        KryptonProvider.unregister();
    }

    @Test
    public static void testChaCha20KeyGenerator()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {
        final KeyGenerator g = KeyGenerator.getInstance("ChaCha20", "Krypton");

        Assert.assertNotEquals(g, null);
        Assert.assertEquals(g.getProvider().getName(), "Krypton");
        Assert.assertEquals(g.getAlgorithm(), "ChaCha20");
    }

    @Test
    public static void testSalsa20KeyGenerator()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {
        final KeyGenerator g = KeyGenerator.getInstance("Salsa20", "Krypton");

        Assert.assertNotEquals(g, null);
        Assert.assertEquals(g.getProvider().getName(), "Krypton");
        Assert.assertEquals(g.getAlgorithm(), "Salsa20");
    }

    @Test
    public static void testChaCha20Parameters()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {
        final AlgorithmParameters g =
            AlgorithmParameters.getInstance("ChaCha20", "Krypton");

        Assert.assertNotEquals(g, null);
        Assert.assertEquals(g.getProvider().getName(), "Krypton");
        Assert.assertEquals(g.getAlgorithm(), "ChaCha20");
    }

    @Test
    public static void testSalsa20Parameters()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {
        final AlgorithmParameters g =
            AlgorithmParameters.getInstance("Salsa20", "Krypton");

        Assert.assertNotEquals(g, null);
        Assert.assertEquals(g.getProvider().getName(), "Krypton");
        Assert.assertEquals(g.getAlgorithm(), "Salsa20");
    }

    @Test
    public static void testChaCha20ParameterGenerator()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {
        final AlgorithmParameterGenerator g =
            AlgorithmParameterGenerator.getInstance("ChaCha20", "Krypton");

        Assert.assertNotEquals(g, null);
        Assert.assertEquals(g.getProvider().getName(), "Krypton");
        Assert.assertEquals(g.getAlgorithm(), "ChaCha20");
    }

    @Test
    public static void testSalsa20ParameterGenerator()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {
        final AlgorithmParameterGenerator g =
            AlgorithmParameterGenerator.getInstance("Salsa20", "Krypton");

        Assert.assertNotEquals(g, null);
        Assert.assertEquals(g.getProvider().getName(), "Krypton");
        Assert.assertEquals(g.getAlgorithm(), "Salsa20");
    }

    @Test
    public static void testChaCha20Cipher()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {
        final Cipher c = Cipher.getInstance("ChaCha20", "Krypton");

        Assert.assertNotEquals(c, null);
        Assert.assertEquals(c.getProvider().getName(), "Krypton");
        Assert.assertEquals(c.getAlgorithm(), "ChaCha20");
    }

    @Test
    public static void testSalsa20Cipher()
        throws NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException {
        final Cipher c = Cipher.getInstance("Salsa20", "Krypton");

        Assert.assertNotEquals(c, null);
        Assert.assertEquals(c.getProvider().getName(), "Krypton");
        Assert.assertEquals(c.getAlgorithm(), "Salsa20");
    }

}
