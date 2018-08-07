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
package net.metricspace.crypto.ciphers;

import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import org.testng.Assert;
import org.testng.annotations.Test;

import net.metricspace.crypto.providers.KryptonProvider;

@Test(groups = "unit")
public abstract class JCACipherTest {
    protected final String providername;
    protected final String ciphername;
    protected final int keysize;
    protected final int ivsize;

    protected JCACipherTest(final String providername,
                            final String ciphername,
                            final int keysize,
                            final int ivsize) {
        this.providername = providername;
        this.ciphername = ciphername;
        this.keysize = keysize;
        this.ivsize = ivsize;
    }

    protected static final byte[] MSG_DATA  = new byte[16];

    static {
        for(int i = 0; i < MSG_DATA.length; i++) {
            MSG_DATA[i] = (byte)i;
        }
    };

    @Test
    protected abstract void jcaCipherSmokeTest()
        throws ShortBufferException, InvalidKeyException,
               NoSuchAlgorithmException, NoSuchProviderException,
               InvalidAlgorithmParameterException, IllegalBlockSizeException,
               NoSuchPaddingException, BadPaddingException;

    protected void testMessageDecrypt(final Cipher cipher,
                                      final byte[] ctextfrag1,
                                      final byte[] ctextfrag2,
                                      final byte[] expected)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {
        final int ctextlen1 = ctextfrag1.length;
        final int ctextlen2 = ctextfrag2.length;
        final int expectedlen = expected.length;
        final int ptextlen1 = cipher.getOutputSize(ctextlen1);
        final byte[] ptextfrag1 = new byte[ptextlen1];

        cipher.update(ctextfrag1, 0, ctextlen1, ptextfrag1, 0);

        final int ptextlen2 = cipher.getOutputSize(ctextlen2);
        final byte[] ptextfrag2 = new byte[ptextlen2];

        cipher.doFinal(ctextfrag2, 0, ctextlen2, ptextfrag2, 0);

        Assert.assertTrue(expectedlen <= ptextlen1 + ptextlen2);

        final byte[] actual = Arrays.copyOf(ptextfrag1, expectedlen);

        for(int i = 0; i < expectedlen - ptextlen1; i++) {
            actual[ptextlen1 + i] = ptextfrag2[i];
        }

        Assert.assertEquals(actual, expected);
    }
}
