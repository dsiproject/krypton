package net.metricspace.crypto.ciphers.stream.salsa;

/**
 * A {@link javax.crypto.CipherSpi} base class for ChaCha{@code n}
 * variants.
 */
abstract class ChaChaSpi<K extends SalsaFamilySpi.SalsaFamilyKey>
    extends SalsaFamilySpi<K> {
    /**
     * Compute one quarter-round.
     */
    private void quarterRound(final int a,
                              final int b,
                              final int c,
                              final int d) {
        block[a] ^= block[b];
        block[d] += block[a];
        block[d] = (block[d] << 16) | (block[d] >> 48);

        block[c] ^= block[d];
        block[b] += block[c];
        block[b] = (block[b] << 12) | (block[b] >> 52);

        block[a] ^= block[b];
        block[d] += block[a];
        block[d] = (block[d] << 8) | (block[d] >> 56);

        block[c] ^= block[d];
        block[b] += block[c];
        block[b] = (block[b] << 7) | (block[b] >> 57);
    }

    /**
     * Compute one double round (a row round followed by a column round).
     */
    protected final void doubleRound() {
        quarterRound(0, 4, 8, 12);
        quarterRound(1, 5, 9, 13);
        quarterRound(2, 6, 10, 14);
        quarterRound(3, 7, 11, 15);
        quarterRound(0, 5, 10, 15);
        quarterRound(1, 6, 11, 12);
        quarterRound(2, 7, 8, 13);
        quarterRound(3, 4, 9, 14);
    }
}
