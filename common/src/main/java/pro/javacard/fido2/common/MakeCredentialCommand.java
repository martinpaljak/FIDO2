package pro.javacard.fido2.common;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static pro.javacard.fido2.common.CTAP2Enums.MakeCredentialCommandParameter;

public class MakeCredentialCommand {
    byte[] clientDataHash;
    String origin;

    String userName;
    byte[] userId;

    Map<String, Boolean> options = new HashMap<>();

    List<CTAP2Extension> extensions = new ArrayList<>();

    List<Integer> algorithms = new ArrayList<>();

    List<byte[]> excludeList = new ArrayList<>();

    byte[] pinAuth;
    int pinProtocol = -1;

    int enterpriseAttestation = -1;

    public MakeCredentialCommand withClientDataHash(byte[] hash) {
        clientDataHash = hash.clone();
        return this;
    }

    public MakeCredentialCommand withDomainName(String domain) {
        origin = domain;
        return this;
    }

    public MakeCredentialCommand withExclude(byte[] credentialID) {
        excludeList.add(credentialID);
        return this;
    }

    public MakeCredentialCommand withAlgorithm(int algo) {
        algorithms.add(algo);
        return this;
    }

    public MakeCredentialCommand withExtension(CTAP2Extension extension) {
        extensions.add(extension);
        return this;
    }

    public MakeCredentialCommand withUserID(byte[] uid) {
        this.userId = uid.clone();
        return this;
    }

    public MakeCredentialCommand withUserName(String user) {
        this.userName = user;
        return this;
    }

    public MakeCredentialCommand withV1PinAuth(byte[] auth) {
        pinAuth = auth.clone();
        pinProtocol = 1;
        return this;
    }

    public MakeCredentialCommand withPinAuth(byte[] auth) {
        pinAuth = auth.clone();
        return this;
    }

    public MakeCredentialCommand withOption(String option) {
        options.put(option, true);
        return this;
    }

    public MakeCredentialCommand withOption(String option, boolean value) {
        options.put(option, value);
        return this;
    }

    public MakeCredentialCommand withEnterpriseAttestation(int variant) {
        if (!(variant == 1 || variant == 2))
            throw new IllegalArgumentException("enterpriseAttestation must be 1 or 2");
        enterpriseAttestation = variant;
        return this;
    }

    // Build the CBOR structure
    public byte[] build() {
        if (clientDataHash == null || origin == null || userId == null || algorithms.size() == 0)
            throw new IllegalStateException("Mandatory parameter missing");

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try {
            CBORGenerator generator = new CBORFactory().createGenerator(result);

            int numElements = 4;
            if (options.size() > 0)
                numElements++;
            if (extensions.size() > 0)
                numElements++;
            if (pinAuth != null)
                numElements++;
            if (pinProtocol != -1)
                numElements++;
            if (excludeList.size() > 0)
                numElements++;
            if (enterpriseAttestation != -1)
                numElements++;

            generator.writeStartObject(numElements);

            generator.writeFieldId(MakeCredentialCommandParameter.clientDataHash.value());
            generator.writeBinary(clientDataHash);

            generator.writeFieldId(MakeCredentialCommandParameter.rp.value());
            generator.writeStartObject(2);
            generator.writeFieldName("id");
            generator.writeString(origin);
            generator.writeFieldName("name");
            generator.writeString(origin);
            generator.writeEndObject();

            generator.writeFieldId(MakeCredentialCommandParameter.user.value());
            generator.writeStartObject(userName == null ? 1 : 2);
            generator.writeFieldName("id");
            generator.writeBinary(userId);
            if (userName != null) {
                generator.writeFieldName("name");
                generator.writeString(userName);
            }
            generator.writeEndObject();

            generator.writeFieldId(MakeCredentialCommandParameter.pubKeyCredParams.value());
            generator.writeStartArray(null, algorithms.size());
            for (int alg : algorithms) {
                generator.writeStartObject(2);
                generator.writeFieldName("alg");
                generator.writeNumber(alg);
                generator.writeFieldName("type");
                generator.writeString("public-key");
                generator.writeEndObject();
            }
            generator.writeEndArray();

            if (excludeList.size() > 0) {
                generator.writeFieldId(MakeCredentialCommandParameter.excludeList.value());
                generator.writeStartArray(null, excludeList.size());
                for (byte[] credential : excludeList) {
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
                generator.writeFieldId(MakeCredentialCommandParameter.extensions.value());
                generator.writeStartObject(extensions.size());
                for (CTAP2Extension extension : extensions) {
                    extension.serializeMakeCredentialCBOR(generator);
                }
                generator.writeEndObject();
            }

            if (options.size() > 0) {
                generator.writeFieldId(MakeCredentialCommandParameter.options.value());
                generator.writeStartObject(options.size());
                for (Map.Entry<String, Boolean> entry : options.entrySet()) {
                    generator.writeFieldName(entry.getKey());
                    generator.writeBoolean(entry.getValue());
                }
                generator.writeEndObject();
            }

            if (pinAuth != null) {
                generator.writeFieldId(MakeCredentialCommandParameter.pinAuth.value());
                generator.writeBinary(pinAuth);
            }
            if (pinProtocol != -1) {
                generator.writeFieldId(MakeCredentialCommandParameter.pinProtocol.value());
                generator.writeNumber(pinProtocol);
            }
            if (enterpriseAttestation != -1) {
                generator.writeFieldId(MakeCredentialCommandParameter.enterpriseAttestation.value());
                generator.writeNumber(enterpriseAttestation);
            }
            generator.writeEndObject();

            generator.close();
            return CTAP2ProtocolHelpers.ctap2command(CTAP2Enums.Command.authenticatorMakeCredential, result.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
