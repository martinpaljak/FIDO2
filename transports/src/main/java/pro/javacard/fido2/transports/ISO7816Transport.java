package pro.javacard.fido2.transports;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.fido2.common.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.ctap2;
import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.ctap2command;

public abstract class ISO7816Transport implements CTAP2Transport {

    private static final Logger logger = LoggerFactory.getLogger(ISO7816Transport.class);

    protected TransportMetadata metadata;

    public abstract byte[] transmit(byte[] bytes) throws IOException;

    public abstract String getDeviceName();

    protected boolean extendedMode = true;


    public void setExtendedMode(boolean value) {
        this.extendedMode = value;
    }

    public byte[] select() throws IOException {
        return check(new ResponseAPDU(transmit(CTAP2Commands.select())), 0x9000).getData();
    }

    @Override
    public byte[] transmitCBOR(byte[] cmd) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        ResponseAPDU response = null;
        if (!extendedMode) {
            // split the command into 255 byte chunks
            List<byte[]> chunks = split(cmd, 255);
            for (int i = 0; i < chunks.size(); i++) {
                CommandAPDU chunkCommand = new CommandAPDU(i == chunks.size() - 1 ? 0x80 : 0x90, 0x10, 0x00, 0x00, chunks.get(0), 256);
                response = new ResponseAPDU(transmit(chunkCommand.getBytes()));
                if (i != chunks.size() - 1)
                    check(response, 0x9000);
            }
        } else {
            // NOTE: we force the command APDU to be with extended semantics by requiring the response to always be 65536 (0x0000 on wire)
            response = new ResponseAPDU(transmit(new CommandAPDU(0x80, 0x10, 0x00, 0x00, cmd, 65536).getBytes()));
        }

        if (extendedMode && response.getSW1() == 0x61) {
            logger.warn("Chunked response in extended APDU mode");
        }

        if (!extendedMode && response.getData().length > 256) {
            logger.warn("Using short APDU mode and got extended APDU response!");
        }

        // Avoid endless loop from bad/broken/buggy card by limited for
        for (int i = 0; i < 20; i++) {
            result.write(response.getData());
            if (response.getSW1() == 0x61)
                response = new ResponseAPDU(transmit(new CommandAPDU(0x80, 0xC0, 0x00, 0x00, response.getSW2() == 0 ? 256 : response.getSW2()).getBytes()));
            else break;
        }
        // Last response
        check(response, 0x9000);
        return result.toByteArray();
    }

    public ResponseAPDU check(ResponseAPDU apdu, int expected) throws IOException {
        if (apdu.getSW() != expected)
            throw new IOException(String.format("Failed to communicate CBOR over %s: 0x%04X", this.getClass().getSimpleName(), apdu.getSW()));
        return apdu;
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

    public static List<byte[]> split(byte[] array, int blockSize) {
        List<byte[]> result = new ArrayList<>();

        int len = array.length;
        int offset = 0;
        int left = len - offset;
        while (left > 0) {
            int currentLen = Math.min(left, blockSize);
            byte[] block = new byte[currentLen];
            System.arraycopy(array, offset, block, 0, currentLen);
            result.add(block);
            left -= currentLen;
            offset += currentLen;
        }
        return result;
    }

    @Override
    final public TransportMetadata getMetadata() {
        return metadata;
    }
}
