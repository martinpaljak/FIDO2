package pro.javacard.fido2.common;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GetAssertionCommand {
    String origin;
    byte[] clientDataHash;
    List<byte[]> allowList = new ArrayList<>();

    Map<String, Boolean> options = new HashMap<>();
    List<CTAP2Extension> extensions = new ArrayList<>();

    byte[] pinAuth;
    int pinProtocol = -1;

    public GetAssertionCommand withDomain(String domain) {
        this.origin = domain;
        return this;
    }

    public GetAssertionCommand withClientDataHash(byte[] hash) {
        this.clientDataHash = hash.clone();
        return this;
    }

    public GetAssertionCommand withAllowed(byte[] credential) {
        this.allowList.add(credential);
        return this;
    }

    public GetAssertionCommand withOption(String option) {
        this.options.put(option, true);
        return this;
    }

    public GetAssertionCommand withOption(String option, boolean value) {
        this.options.put(option, value);
        return this;
    }

    public GetAssertionCommand withExtension(CTAP2Extension extension) {
        extensions.add(extension);
        return this;
    }

    public GetAssertionCommand withV1PinAuth(byte[] pinAuth) {
        this.pinAuth = pinAuth.clone();
        this.pinProtocol = 1;
        return this;
    }

    public GetAssertionCommand withPinAuth(byte[] pinAuth) {
        this.pinAuth = pinAuth.clone();
        return this;
    }

    public GetAssertionCommand withPinProtocol(int protocol) {
        this.pinProtocol = protocol;
        return this;
    }

    @SuppressWarnings("deprecation")
    public byte[] build() {

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try {
            CBORGenerator generator = new CBORFactory().createGenerator(result);
            generator.setCodec(CTAP2ProtocolHelpers.cborMapper);

            int numElements = 2; // ipId, cdh
            if (allowList.size() > 0) numElements++;
            if (pinAuth != null) numElements++;
            if (pinProtocol != -1) numElements++;
            if (extensions.size() > 0) numElements++;
            if (options.size() > 0) numElements++;
            generator.writeStartObject(numElements);

            generator.writeFieldId(CTAP2Enums.GetAssertionCommandParameter.rpId.value());
            generator.writeString(origin);

            generator.writeFieldId(CTAP2Enums.GetAssertionCommandParameter.clientDataHash.value());
            generator.writeBinary(clientDataHash);

            if (allowList.size() > 0) {
                generator.writeFieldId(CTAP2Enums.GetAssertionCommandParameter.allowList.value());
                generator.writeStartArray(allowList.size());
                for (byte[] credential : allowList) {
                    generator.writeStartObject(2);
                    generator.writeFieldName("type");
                    generator.writeString("public-key");
                    generator.writeFieldName("id");
                    generator.writeBinary(credential);
                    generator.writeEndObject();
                }
                generator.writeEndArray();
            }

            if (extensions.size() > 0) {
                generator.writeFieldId(CTAP2Enums.GetAssertionCommandParameter.extensions.value());
                generator.writeStartObject(extensions.size());
                for (CTAP2Extension entry : extensions) {
                    entry.serializeGetAssertionCBOR(generator);
                }
                generator.writeEndObject();
            }

            if (options.size() > 0) {
                generator.writeFieldId(CTAP2Enums.GetAssertionCommandParameter.options.value());
                generator.writeStartObject(options.size());
                for (Map.Entry<String, Boolean> entry : options.entrySet()) {
                    generator.writeFieldName(entry.getKey());
                    generator.writeBoolean(entry.getValue());
                }
                generator.writeEndObject();
            }

            if (pinAuth != null) {
                generator.writeFieldId(CTAP2Enums.GetAssertionCommandParameter.pinAuth.value());
                generator.writeBinary(pinAuth);
            }

            if (pinProtocol != -1) {
                generator.writeFieldId(CTAP2Enums.GetAssertionCommandParameter.pinProtocol.value());
                generator.writeNumber(pinProtocol);
            }

            generator.writeEndObject();

            generator.close();
            return CTAP2ProtocolHelpers.ctap2command(CTAP2Enums.Command.authenticatorGetAssertion, result.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
