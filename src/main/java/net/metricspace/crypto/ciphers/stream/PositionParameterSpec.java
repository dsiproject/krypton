package net.metricspace.crypto.ciphers.stream;

import java.security.spec.AlgorithmParameterSpec;

/**
 * An {@link java.security.spec.AlgorithmParameterSpec} subinterface
 * for stream position parameters.
 */
public interface PositionParameterSpec extends AlgorithmParameterSpec {
    /**
     * Get the stream position parameter.
     *
     * @return The stream position parameter.
     */
    public long getPosition();
}
