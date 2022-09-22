package pro.javacard.fido2.common;

import java.io.Closeable;
import java.io.IOException;

public interface CTAP2Transport extends Closeable, CTAP1Transport {

    byte[] transmitCBOR(byte[] cmd) throws IOException;
}
