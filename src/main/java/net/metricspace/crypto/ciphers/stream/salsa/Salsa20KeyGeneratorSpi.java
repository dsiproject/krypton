package net.metricspace.crypto.ciphers.stream.salsa;

import javax.crypto.SecretKey;

/**
 * A key generate for the Salsa20 cipher.
 */
public final class Salsa20KeyGeneratorSpi extends SalsaFamilyKeyGeneratorSpi {
    /**
     * {@inheritDoc}
     */
    @Override
    protected final SecretKey engineGenerateKey(final int[] data) {
        return new Salsa20Spi.Key(data);
    }
}
