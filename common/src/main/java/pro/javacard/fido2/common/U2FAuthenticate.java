package pro.javacard.fido2.common;

import apdu4j.core.CommandAPDU;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class U2FAuthenticate {
    private static final Logger logger = LoggerFactory.getLogger(U2FAuthenticate.class);

    static void verifyU2FAuthentication(GetAssertionCommand command) throws IllegalArgumentException {
        if (command.options.getOrDefault("uv", false))
            throw new IllegalArgumentException("uv is not supported");
        if (command.extensions.size() > 0)
            throw new IllegalArgumentException("extensions are not supported");
        if (command.allowList.size() != 1)
            throw new IllegalArgumentException("Allow list must have exactly one entry");
    }


    public static byte[] toAuthenticateCommand(GetAssertionCommand command) throws IOException {
        verifyU2FAuthentication(command);


        byte[] appid = PINProtocols.sha256(command.origin.getBytes(StandardCharsets.UTF_8));
        logger.debug("AppID: {}", Hex.toHexString(appid));

        // Create payload
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        bos.write(command.clientDataHash);
        bos.write(appid);
        bos.write(command.allowList.get(0).length);
        bos.write(command.allowList.get(0));

        // FIXME: usb vs nfc differ. NFC is always 0x03, USB 0x07 -> 0x03
        int p1 = command.options.getOrDefault("up", true) ? 0x03 : 0x08;

        // Do mapping
        byte[] payload = bos.toByteArray();

        // Needs to be extended length, thus 65536
        byte[] u2fcmd = new CommandAPDU(0x00, 0x02, p1, 0x00, payload, 65536).getBytes();
        return u2fcmd;
    }

    @SuppressWarnings("deprecation")
    public static byte[] toCBOR(GetAssertionCommand command, byte[] response) throws IOException {

        byte[] appId = PINProtocols.sha256(command.origin.getBytes(StandardCharsets.UTF_8));

        //int offset = 0;
        //if (response[offset++] != 0x01)
        //   throw new IllegalArgumentException("response[0] is not 0x05");

        // counter
        byte[] counter = Arrays.copyOfRange(response, 1, 1 + 4);
        //offset += 4;
        logger.debug("counter: {}", Hex.toHexString(counter));

        byte[] signature = Arrays.copyOfRange(response, 5, response.length);

        ByteArrayOutputStream authenticatorData = new ByteArrayOutputStream();
        authenticatorData.write(appId);
        authenticatorData.write(response[0]); // flags
        authenticatorData.write(counter);

        logger.debug("Authenticator data: " + Hex.toHexString(authenticatorData.toByteArray()));

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        CBORGenerator generator = new CBORFactory().createGenerator(result);
        generator.writeStartObject(3);

        generator.writeFieldId(1);
        generator.writeStartObject(2);
        generator.writeFieldName("type");
        generator.writeString("public-key");
        generator.writeFieldName("id");
        generator.writeBinary(command.allowList.get(0));
        generator.writeEndObject();

        generator.writeFieldId(2);
        generator.writeBinary(authenticatorData.toByteArray());

        generator.writeFieldId(3);
        generator.writeBinary(signature);

        generator.writeEndObject();
        generator.close();

        return result.toByteArray();
    }
}
