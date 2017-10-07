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

import net.metricspace.crypto.ciphers.JCACipherTest;
import net.metricspace.crypto.providers.KryptonProvider;

public abstract class StreamCipherJCACipherTest extends JCACipherTest {
    protected StreamCipherJCACipherTest(final String providername,
                                        final String ciphername,
                                        final int keysize,
                                        final int ivsize) {
        super(providername, ciphername, keysize, ivsize);
    }

    @Override
    protected void doJCACipherSmokeTest(final byte[] expected1,
                                        final int break1,
                                        final byte[] expected2,
                                        final int break2)
        throws ShortBufferException, InvalidKeyException,
               NoSuchAlgorithmException, NoSuchProviderException,
               InvalidAlgorithmParameterException, IllegalBlockSizeException,
               NoSuchPaddingException, BadPaddingException {
        final int length1 = expected1.length;
        final int length2 = expected2.length;
        final Cipher cipher =
            Cipher.getInstance(ciphername, providername);
        final KeyGenerator keygen =
            KeyGenerator.getInstance(ciphername, providername);
        final AlgorithmParameterGenerator paramgen =
            AlgorithmParameterGenerator.getInstance(ciphername, providername);
        keygen.init(keysize);
        final SecretKey key = keygen.generateKey();
        paramgen.init(ivsize);
        final AlgorithmParameters initparams = paramgen.generateParameters();

        cipher.init(Cipher.ENCRYPT_MODE, key, initparams);

        final AlgorithmParameters params1 = cipher.getParameters();
        final int ctextlen1 = cipher.getOutputSize(break1);
        final byte[] ctext1 = new byte[ctextlen1];

        cipher.update(expected1, 0, break1, ctext1, 0);

        final int ctextlen2 = cipher.getOutputSize(length1 - break1);
        final byte[] ctext2 = new byte[ctextlen2];

        cipher.doFinal(expected1, break1, length1 - break1, ctext2, 0);

        final AlgorithmParameters params2 = cipher.getParameters();
        final int ctextlen3 = cipher.getOutputSize(break2);
        final byte[] ctext3 = new byte[ctextlen3];

        cipher.update(expected2, 0, break2, ctext3, 0);

        final int ctextlen4 = cipher.getOutputSize(length2 - break2);
        final byte[] ctext4 = new byte[ctextlen4];

        cipher.doFinal(expected2, break2, length2 - break2, ctext4, 0);

        cipher.init(Cipher.DECRYPT_MODE, key, params1);
        testMessageDecrypt(cipher, ctext1, ctext2, expected1);
        testMessageDecrypt(cipher, ctext3, ctext4, expected2);

        cipher.init(Cipher.DECRYPT_MODE, key, params2);
        testMessageDecrypt(cipher, ctext3, ctext4, expected2);
    }
}
