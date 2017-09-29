package net.metricspace.crypto.ciphers.stream.salsa;

/**
 * A {@link javax.crypto.CipherSpi} base class for Salsa{@code n}
 * variants.
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
