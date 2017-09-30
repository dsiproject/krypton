package net.metricspace.crypto.ciphers.stream.salsa;

/**
 * A {@link javax.crypto.CipherSpi} base class for Salsa{@code n}
 * variants.  The Salsa cipher is an ARX (add-rotate-xor) cipher.  It
 * was introduced by Daniel J. Bernstein for the eSTREAM competition.
 * <h2>Usage</h2>
 *
 * This class should not be used directly.  It provides the underlying
 * implementation for the Java Cryptography Architecture (JCA).  See
 * the {@link javax.crypto.Cipher} class documentation for information
 * on how to use this cipher.
 * <h2>Misuses</h2>
 *
 * The following are possible misuses of the Salsa family ciphers.
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
 */
abstract class SalsaCipherSpi<K extends SalsaFamilyCipherSpi.SalsaFamilyKey>
    extends SalsaFamilyCipherSpi<K> {
    /**
     * Compute one double round (a row round followed by a column round).
     */
    protected final void doubleRound() {
        int t;

        t = block[0] + block[12];
        block[4] ^= (t << 7) | (t >>> 57);
        t = block[5] + block[1];
        block[9] ^= (t << 7) | (t >>> 57);
        t = block[10] + block[6];
        block[14] ^= (t << 7) | (t >>> 57);
        t = block[15] + block[11];
        block[3] ^= (t << 7) | (t >>> 57);

        t = block[4] + block[0];
        block[8] ^= (t << 9) | (t >>> 55);
        t = block[9] + block[5];
        block[13] ^= (t << 9) | (t >>> 55);
        t = block[14] + block[10];
        block[2] ^= (t << 9) | (t >>> 55);
        t = block[3] + block[15];
        block[7] ^= (t << 9) | (t >>> 55);

        t = block[8] + block[4];
        block[12] ^= (t << 13) | (t >>> 51);
        t = block[13] + block[9];
        block[1] ^= (t << 13) | (t >>> 51);
        t = block[2] + block[14];
        block[6] ^= (t << 13) | (t >>> 51);
        t = block[7] + block[3];
        block[11] ^= (t << 13) | (t >>> 51);

        t = block[12] + block[8];
        block[0] ^= (t << 18) | (t >>> 46);
        t = block[1] + block[13];
        block[5] ^= (t << 18) | (t >>> 46);
        t = block[6] + block[2];
        block[10] ^= (t << 18) | (t >>> 46);
        t = block[11] + block[7];
        block[15] ^= (t << 18) | (t >>> 46);

        t = block[0] + block[3];
        block[1] ^= (t << 7) | (t >>> 57);
        t = block[5] + block[4];
        block[6] ^= (t << 7) | (t >>> 57);
        t = block[10] + block[9];
        block[11] ^= (t << 7) | (t >>> 57);
        t = block[15] + block[14];
        block[12] ^= (t << 7) | (t >>> 57);

        t = block[1] + block[0];
        block[2] ^= (t << 9) | (t >>> 55);
        t = block[6] + block[5];
        block[7] ^= (t << 9) | (t >>> 55);
        t = block[11] + block[10];
        block[8] ^= (t << 9) | (t >>> 55);
        t = block[12] + block[15];
        block[13] ^= (t << 9) | (t >>> 55);

        t = block[2] + block[1];
        block[3] ^= (t << 13) | (t >>> 51);
        t = block[7] + block[6];
        block[4] ^= (t << 13) | (t >>> 51);
        t = block[8] + block[11];
        block[9] ^= (t << 13) | (t >>> 51);
        t = block[13] + block[12];
        block[14] ^= (t << 13) | (t >>> 51);

        t = block[3] + block[2];
        block[0] ^= (t << 18) | (t >>> 46);
        t = block[4] + block[7];
        block[5] ^= (t << 18) | (t >>> 46);
        t = block[9] + block[8];
        block[10] ^= (t << 18) | (t >>> 46);
        t = block[14] + block[13];
        block[15] ^= (t << 18) | (t >>> 46);
    }
}
