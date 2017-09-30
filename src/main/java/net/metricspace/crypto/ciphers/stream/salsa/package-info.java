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
 * Implementation of the Salsa family of stream ciphers.  The salsa
 * family is a group of ARX (add-rotate-xor) ciphers, consisting of
 * the original Salsa cipher scheme as well as the ChaCha variant.  A
 * number of variants of each category exist, which vary in the number
 * of rounds they execute.  The most popular are the Salsa20 and
 * ChaCha20 variants, each of which execute 20 rounds of the
 * corresponding category.
 * <p>
 * Both Salsa and ChaCha ciphers generate a cipher stream from a
 * 256-bit key, an 8-byte initialization vector, and an 8-bit stream
 * position.
 * <h2>Usage</h2>
 *
 * Classes in this package should not be used directly.  They provide
 * the underlying implementations for the Java Cryptography
 * Architecture (JCA).  See the JCA engine class documentation for
 * details.
 * <h2>Misuses</h2>
 *
 * The following are possible misuses of the salsa family ciphers.
 * <ul>
 * <li> <b>Encrypting multiple plaintexts with the same cipher
 * stream</b>: As with other stream ciphers, the Salsa family's cipher
 * stream is generated solely from the key, IV, and starting position,
 * and is XORed with the plaintext to produce the cipher stream.
 * Thus, if multiple plaintexts are encrypted with the same cipher
 * stream, attackers can recover information about the plaintexts as
 * well as the cipher stream.
 * <li> <b>Re-using initialization vecctors</b>: Reuse of
 * initialization vectors leads to encryption of multiple plaintexts
 * with the same IV.
 * <li> <b>Ciphertext Manipulation</b>: Since encryption/decryption
 * consists of XORing the plaintext/ciphertext by the cipher stream,
 * an attacker can flip bits in the plaintext by flipping them in the
 * ciphertext, unless the message is also protected by a message
 * authentication code (MAC).
 * </ul>
 *
 * @see net.metricspace.crypto.providers.KryptonProvider
 * @see javax.crypto.Cipher
 * @see java.security.Security
 */
package net.metricspace.crypto.ciphers.stream.salsa;
