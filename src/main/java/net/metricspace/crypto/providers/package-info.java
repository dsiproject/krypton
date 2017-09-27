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

/**
 * Java Cryptography Architecture Provider implementations for the
 * Krypton library.
 * <p>
 * This package contains the {@link java.security.Provider}
 * implementations for the Krypton cryptography library.  The Krypton
 * library segregates its cryptographic functionality into a number of
 * <i>collections</i>, based on the security of the algorithms at the
 * time of each release.  The collections are as follows:
 * <ul>
 * <li> <b>Curated</b>: This is the main collection, consisting of
 *      cryptographic algorithms that are well-established enough to
 *      be trustworthy, and which show no warning signs of being
 *      compromised.  Most applications should use this set. The
 *      {@link net.metricspace.crypto.providers.KryptonProvider} class
 *      implements the {@link java.security.Provider} for this set.
 *
 * <li> <b>Deprecated</b>: This collection exists to hold any
 *      algorithms which have previously been in the curated set, but
 *      which are now considered compromised or weak, or there is
 *      reason to believe that they may be compromised in the near
 *      future.  As an example, the SHA-1 hash would have been moved
 *      to this set following the publication of a collision-finding
 *      algorithm in 2005. The {@link
 *      net.metricspace.crypto.providers.KryptonProviderDeprecated}
 *      class implements the {@link java.security.Provider} for this
 *      set.
 *
 * <li> <b>Experimental</b>: This collection consists of cryptographic
 *      algorithms which are considered too new to be trustworthy, but
 *      which have no known attacks and show no signs of critical
 *      weakness.  As an example, Supersingular Isogeny Diffie-Hellman
 *      (SIDH) is a candidate for this set in 2017. The {@link
 *      net.metricspace.crypto.providers.KryptonProviderExperimental}
 *      class implements the {@link java.security.Provider} for this
 *      set.
 * </ul>
 */
package net.metricspace.crypto.providers;
