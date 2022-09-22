package pro.javacard.fido2.transports;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.fido2.common.*;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.ctap2;
import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.ctap2command;

public abstract class ISO7816Transport implements CTAP2Transport {

    private static final Logger logger = LoggerFactory.getLogger(ISO7816Transport.class);

    protected TransportMetadata metadata;


    public abstract byte[] transmit(byte[] bytes) throws IOException;

    public abstract String getDeviceName();

    @Override
    public byte[] transmitCBOR(byte[] cmd) throws IOException {
        // NOTE: we force the command APDU to be with extended semantics by requiring the response to always be 65536 (0x0000 on wire)
        ResponseAPDU responseAPDU = new ResponseAPDU(transmit(new CommandAPDU(0x80, 0x10, 0x00, 0x00, cmd, 65536).getBytes()));
        if (responseAPDU.getSW() != 0x9000)
            throw new IOException(String.format("Failed to communicate CBOR over %s: 0x%04X", this.getClass().getSimpleName(), responseAPDU.getSW()));
        return responseAPDU.getData();
    }

    @Override
    public byte[] transmitCTAP1(byte[] cmd) throws IOException {
        return transmit(cmd);
    }

    protected TransportMetadata probe() {
        try {
            // Issue initial SELECT
            byte[] selectResponse = transmit(CTAP2Commands.select());
            ResponseAPDU response = new ResponseAPDU(selectResponse);
            if (response.getSW() != 0x9000) {
                logger.error(String.format("SELECT returned %04X%n", response.getSW()));
                return null;
            }
            String select_response = new String(response.getData(), StandardCharsets.UTF_8);
            EnumSet<CTAPVersion> versions = EnumSet.noneOf(CTAPVersion.class);

            if (select_response.equals("U2F_V2")) {
                versions.add(CTAPVersion.U2F_V2);
            } else if (select_response.equals("FIDO_2_0")) {
                versions.add(CTAPVersion.FIDO_2_0);
            } else {
                return null;
            }

            // Check for FIDO2
            byte[] cmd = ctap2command(CTAP2Enums.Command.authenticatorGetInfo, new byte[0]);
            ObjectNode deviceInfo = ctap2(cmd, this);
            deviceInfo.get("versions").forEach(v -> versions.add(CTAPVersion.valueOf(v.asText())));
            logger.info("Found device with support for {}", versions);
            return new DefaultTransportMetadata("1.0.0", getDeviceName(), versions);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    final public TransportMetadata getMetadata() {
        return metadata;
    }
}
