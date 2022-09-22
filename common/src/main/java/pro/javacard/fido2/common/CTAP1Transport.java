package pro.javacard.fido2.common;

import java.io.IOException;

public interface CTAP1Transport {
    byte[] transmitCTAP1(byte[] cmd) throws IOException;

    default void wink() throws IOException, UnsupportedOperationException {
        throw new UnsupportedOperationException("Wink operation not supported");
    }

    TransportMetadata getMetadata();
}
