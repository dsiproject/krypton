package net.metricspace.crypto.ciphers.stream.salsa;

import javax.crypto.spec.IvParameterSpec;

import net.metricspace.crypto.ciphers.stream.PositionParameterSpec;

public class SalsaFamilyParameterSpec
    extends IvParameterSpec
    implements PositionParameterSpec {
    private final long pos;

    SalsaFamilyParameterSpec(final byte[] iv,
                             final long pos) {
        super(iv, 0, SalsaFamilySpi.IV_LEN);
        this.pos = pos;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getPosition() {
        return pos;
    }
}
