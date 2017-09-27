package net.metricspace.crypto.ciphers.stream.salsa;

import javax.crypto.SecretKey;

/**
 * A key generator for the ChaCha20 cipher.
 */
public final class ChaCha20KeyGeneratorSpi extends SalsaFamilyKeyGeneratorSpi {
    /**
     * {@inheritDoc}
     */
    @Override
    protected final SecretKey engineGenerateKey(final int[] data) {
        return new ChaCha20CipherSpi.Key(data);
    }
}
