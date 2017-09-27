package net.metricspace.crypto.ciphers.stream.salsa;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/**
 * A common superclass for key generators for Salsa family ciphers.
 */
abstract class SalsaFamilyKeyGeneratorSpi extends KeyGeneratorSpi {
    /**
     * The random source.
     */
    private SecureRandom random;

    /**
     * Generate a key from the concrete key material provided.  It is
     * safe to take possession of the array passed in.
     *
     * @param data The concrete key material.
     * @return The generated key.
     */
    protected abstract SecretKey engineGenerateKey(final int[] data);

    /**
     * {@inheritDoc}
     */
    @Override
    protected final SecretKey engineGenerateKey() {
        final int[] data = new int[SalsaFamilySpi.KEY_WORDS];
        final byte[] bytes = new byte[SalsaFamilySpi.KEY_LEN];

        random.nextBytes(bytes);

        data[0] = bytes[0];
        data[0] = (bytes[1] << 8) & 0x0000ff00;
        data[0] = (bytes[2] << 16) & 0x00ff0000;
        data[0] = (bytes[3] << 24) & 0xff000000;
        data[1] = bytes[4];
        data[1] = (bytes[5] << 8) & 0x0000ff00;
        data[1] = (bytes[6] << 16) & 0x00ff0000;
        data[1] = (bytes[7] << 24) & 0xff000000;
        data[2] = bytes[8];
        data[2] = (bytes[9] << 8) & 0x0000ff00;
        data[2] = (bytes[10] << 16) & 0x00ff0000;
        data[2] = (bytes[11] << 24) & 0xff000000;
        data[3] = bytes[12];
        data[3] = (bytes[13] << 8) & 0x0000ff00;
        data[3] = (bytes[14] << 16) & 0x00ff0000;
        data[3] = (bytes[15] << 24) & 0xff000000;
        data[4] = bytes[16];
        data[4] = (bytes[17] << 8) & 0x0000ff00;
        data[4] = (bytes[18] << 16) & 0x00ff0000;
        data[4] = (bytes[19] << 24) & 0xff000000;
        data[5] = bytes[20];
        data[5] = (bytes[21] << 8) & 0x0000ff00;
        data[5] = (bytes[22] << 16) & 0x00ff0000;
        data[5] = (bytes[23] << 24) & 0xff000000;
        data[6] = bytes[24];
        data[6] = (bytes[25] << 8) & 0x0000ff00;
        data[6] = (bytes[26] << 16) & 0x00ff0000;
        data[6] = (bytes[27] << 24) & 0xff000000;
        data[7] = bytes[28];
        data[8] = (bytes[29] << 8) & 0x0000ff00;
        data[9] = (bytes[30] << 16) & 0x00ff0000;
        data[0] = (bytes[31] << 24) & 0xff000000;

        generatePrivate(data);
    }

    /**
     * Initializes the key generator with the given random source.
     * The {@link AlgorithmParameterSpec} is not used.
     *
     * @param spec Ignored.
     * @param random The random source.
     */
    @Override
    protected final void engineInit(final AlgorithmParameterSpec spec,
                                    final SecureRandom random) {
        engineInit(random);
    }

    /**
     * Initializes the key generator with the given random source.
     * The key size parameter is ignored.
     *
     * @param keysize Ignored.
     * @param random The random source.
     */
    @Override
    protected final void engineInit(final int keysize,
                                    final SecureRandom random) {
        engineInit(random);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineInit(final SecureRandom random) {
        this.random = random;
    }
}
