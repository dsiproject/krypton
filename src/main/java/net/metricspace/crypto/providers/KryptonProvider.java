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

import java.security.Security;
import java.security.Provider;

import net.metricspace.crypto.ciphers.stream.hc.HC256CipherSpi;
import net.metricspace.crypto.ciphers.stream.hc.HC256KeyGeneratorSpi;
import net.metricspace.crypto.ciphers.stream.hc.HC256ParameterGeneratorSpi;
import net.metricspace.crypto.ciphers.stream.hc.HC256ParametersSpi;
import net.metricspace.crypto.ciphers.stream.salsa.ChaCha20CipherSpi;
import net.metricspace.crypto.ciphers.stream.salsa.ChaCha20KeyGeneratorSpi;
import net.metricspace.crypto.ciphers.stream.salsa.ChaCha20ParameterGeneratorSpi;
import net.metricspace.crypto.ciphers.stream.salsa.Salsa20CipherSpi;
import net.metricspace.crypto.ciphers.stream.salsa.Salsa20KeyGeneratorSpi;
import net.metricspace.crypto.ciphers.stream.salsa.Salsa20ParameterGeneratorSpi;
import net.metricspace.crypto.ciphers.stream.salsa.SalsaFamilyParametersSpi;
import net.metricspace.crypto.hashes.blake.Blake2b256MessageDigestSpi;
import net.metricspace.crypto.hashes.blake.Blake2b384MessageDigestSpi;
import net.metricspace.crypto.hashes.blake.Blake2b512MessageDigestSpi;
import net.metricspace.crypto.hashes.keccak.Keccak224MessageDigestSpi;
import net.metricspace.crypto.hashes.keccak.Keccak256MessageDigestSpi;
import net.metricspace.crypto.hashes.keccak.Keccak384MessageDigestSpi;
import net.metricspace.crypto.hashes.keccak.Keccak512MessageDigestSpi;
import net.metricspace.crypto.hashes.ripemd.RipeMD160MessageDigestSpi;

/**
 * The {@link Provider} for curated cryptographic algorithms.
 * Algorithms provided in the curated set are currently considered
 * trustworthy, and there is no reason to suspect that they will be
 * compromised in the near future.
 * <p>
 * If the security of an algorithm in the curated set is considered
 * likely to be compromised, it will be demoted to the deprecated set
 * and dropped from the curated set.
 * <p>
 * The curated set consists of the following algorithms:
 * <p>
 * <b>Stream Ciphers</b>
 * <ul>
 * <li> Salsa20
 *      ({@link net.metricspace.crypto.ciphers.stream.salsa.Salsa20CipherSpi})
 * <li> ChaCha20
 *      ({@link net.metricspace.crypto.ciphers.stream.salsa.ChaCha20CipherSpi})
 * <li> HC-256
 *      ({@link net.metricspace.crypto.ciphers.stream.hc.HC256CipherSpi})
 * </ul>
 * <p>
 * <b>Hashes</b>
 * <ul>
 * <li> RipeMD-160
 *      ({@link net.metricspace.crypto.hashes.ripemd.RipeMD160MessageDigestSpi})
 * <li> SHA3-224
 *      ({@link net.metricspace.crypto.hashes.keccak.Keccak224MessageDigestSpi})
 * <li> SHA3-256
 *      ({@link net.metricspace.crypto.hashes.keccak.Keccak256MessageDigestSpi})
 * <li> SHA3-384
 *      ({@link net.metricspace.crypto.hashes.keccak.Keccak384MessageDigestSpi})
 * <li> SHA3-512
 *      ({@link net.metricspace.crypto.hashes.keccak.Keccak512MessageDigestSpi})
 * <li> Blake2b-256
 *      ({@link net.metricspace.crypto.hashes.blake.Blake2b256MessageDigestSpi})
 * <li> Blake2b-384
 *      ({@link net.metricspace.crypto.hashes.blake.Blake2b384MessageDigestSpi})
 * <li> Blake2b-512
 *      ({@link net.metricspace.crypto.hashes.blake.Blake2b512MessageDigestSpi})
 * </ul>
 * <p>
 * See the corresponding Spi class documentation for each cipher for
 * additional information.
 * <p>
 * For each stream cipher, there are {@code Cipher}.<i>algName</i>,
 * {@code AlgorithmParameters}.<i>algName</i>,
 * {@code AlgorithmParameterGenerator}.<i>algName</i>, and
 * {@code KeyGenerator}.<i>algName</i> instances.
 *
 * @see net.metricspace.crypto.providers.KryptonProviderDeprecated
 * @see net.metricspace.crypto.providers.KryptonProviderExperimental
 */
public final class KryptonProvider extends Provider {
    /**
     * The name under which this provider is registered.
     */
    public static final String NAME = "Krypton";

    /**
     * The version of this provider.
     */
    public static final double VERSION = 1.0;

    /**
     * The singleton instance.
     */
    private static final KryptonProvider instance = new KryptonProvider();

    /**
     * Initialize this {@code KryptonProvider}.
     */
    private KryptonProvider() {
        super(NAME, VERSION, "Krypton curated cipher suite");

        // Cipher key generators
        put("KeyGenerator.ChaCha20", ChaCha20KeyGeneratorSpi.class.getName());
        put("KeyGenerator.Salsa20", Salsa20KeyGeneratorSpi.class.getName());
        put("KeyGenerator.HC-256", HC256KeyGeneratorSpi.class.getName());

        // Cipher parameters
        put("AlgorithmParameters.ChaCha20",
            SalsaFamilyParametersSpi.class.getName());
        put("AlgorithmParameters.Salsa20",
            SalsaFamilyParametersSpi.class.getName());
        put("AlgorithmParameters.HC-256",
            HC256ParametersSpi.class.getName());

        // Cipher parameter generators
        put("AlgorithmParameterGenerator.ChaCha20",
            ChaCha20ParameterGeneratorSpi.class.getName());
        put("AlgorithmParameterGenerator.Salsa20",
            Salsa20ParameterGeneratorSpi.class.getName());
        put("AlgorithmParameterGenerator.HC-256",
            HC256ParameterGeneratorSpi.class.getName());

        // Stream ciphers
        put("Cipher.ChaCha20", ChaCha20CipherSpi.class.getName());
        put("Cipher.Salsa20", Salsa20CipherSpi.class.getName());
        put("Cipher.HC-256", HC256CipherSpi.class.getName());

        // Hashes
        put("MessageDigest.RipeMD-160",
            RipeMD160MessageDigestSpi.class.getName());
        put("MessageDigest.Blake2b-512",
            Blake2b512MessageDigestSpi.class.getName());
        put("MessageDigest.Blake2b-384",
            Blake2b384MessageDigestSpi.class.getName());
        put("MessageDigest.Blake2b-256",
            Blake2b256MessageDigestSpi.class.getName());
        put("MessageDigest.SHA3-512",
            Keccak512MessageDigestSpi.class.getName());
        put("MessageDigest.SHA3-384",
            Keccak384MessageDigestSpi.class.getName());
        put("MessageDigest.SHA3-256",
            Keccak256MessageDigestSpi.class.getName());
        put("MessageDigest.SHA3-224",
            Keccak224MessageDigestSpi.class.getName());
    }

    /**
     * Get the singleton instance.
     *
     * @return The singleton instance.
     * @see #instance
     */
    public static KryptonProvider getInstance() {
        return instance;
    }

    /**
     * Register this provider.
     */
    public static void register() {
        Security.addProvider(getInstance());
    }

    /**
     * Register this provider at a specific position.
     *
     * @param position The position at which to register this provider.
     */
    public static void register(final int position) {
        Security.insertProviderAt(getInstance(), position);
    }

    /**
     * Unregister this provider.
     */
    public static void unregister() {
        Security.removeProvider(NAME);
    }
}
