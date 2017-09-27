package net.metricspace.crypto.ciphers.stream.salsa;

/**
 * A {@link javax.crypto.CipherSpi} implementation for the ChaCha20 cipher.
 */
public final class ChaCha20Spi extends ChaChaSpi<ChaCha20Spi.Key> {
    /**
     * The name of this cipher.
     */
    public static final String NAME = "ChaCha20";

    /**
     * Keys for the ChaCha20 cipher.
     */
    static final class Key extends SalsaFamilySpi.SalsaFamilyKey {
        /**
         * Initialize this key with the given array.  The key takes
         * possession of the {@code data} array.
         *
         * @param data The key material.
         */
        Key(final int[] data) {
            super(data);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public final String getAlgorithm() {
            return NAME;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void rounds() {
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
        doubleRound();
    }
}
