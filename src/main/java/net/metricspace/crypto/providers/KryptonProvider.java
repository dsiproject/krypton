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

/**
 * The {@link Provider} for curated cryptographic algorithms.
 * Algorithms provided in the curated set are currently considered
 * trustworthy, and there is no reason to suspect that they will be
 * compromised in the near future.
 * <p>
 * If the security of an algorithm in the curated set is considered
 * likely to be compromised, it will be demoted to the deprecated set
 * and dropped from the curated set.
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
