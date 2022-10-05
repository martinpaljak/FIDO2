package pro.javacard.fido2.common;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.interfaces.ECPublicKey;

public class ClientPINCommand {
    byte protocol = -1;
    byte subCommand = -1;
    byte[] pinAuth;
    byte[] newPinEnc;
    byte[] pinHashEnc;
    ECPublicKey keyAgreementKey;

    public ClientPINCommand withProtocol(int protocol) {
        this.protocol = (byte) (protocol & 0xFF);
        return this;
    }

    public ClientPINCommand withSubCommand(int subCommand) {
        this.subCommand = (byte) (subCommand & 0xFF);
        return this;
    }

    public ClientPINCommand withHostKey(ECPublicKey key) {
        this.keyAgreementKey = key;
        return this;
    }

    public ClientPINCommand withPinAuth(byte[] pinAuth) {
        this.pinAuth = pinAuth.clone();
        return this;
    }

    public ClientPINCommand withPinHashEnc(byte[] pinHashEnc) {
        this.pinHashEnc = pinHashEnc.clone();
        return this;
    }

    public ClientPINCommand withNewPinEnc(byte[] newPinEnc) {
        this.newPinEnc = newPinEnc.clone();
        return this;
    }

    public static ClientPINCommand getRetriesV1() {
        return new ClientPINCommand().withProtocol(1).withSubCommand(CTAP2Enums.ClientPINCommandSubCommand.getReries.value());
    }

    public static ClientPINCommand getKeyAgreementV1() {
        return new ClientPINCommand().withProtocol(1).withSubCommand(CTAP2Enums.ClientPINCommandSubCommand.getKeyAgreement.value());
    }

    public byte[] build() {
        if (protocol == -1 || subCommand == -1)
            throw new IllegalArgumentException("protocol and subcommand not set!");

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try (CBORGenerator cborGenerator = new CBORFactory().createGenerator(byteArrayOutputStream)) {
                int numItems = 2;
                if (keyAgreementKey != null)
                    numItems++;
                if (pinAuth != null)
                    numItems++;
                if (newPinEnc != null)
                    numItems++;
                if (pinHashEnc != null)
                    numItems++;

                cborGenerator.writeStartObject(numItems);
                cborGenerator.writeFieldId(CTAP2Enums.ClientPINCommandParameter.pinProtocol.value());
                cborGenerator.writeNumber(1);
                cborGenerator.writeFieldId(CTAP2Enums.ClientPINCommandParameter.subCommand.value());
                cborGenerator.writeNumber(subCommand);
                if (keyAgreementKey != null) {
                    cborGenerator.writeFieldId(CTAP2Enums.ClientPINCommandParameter.keyAgreement.value());
                    P256.pubkey2cbor(keyAgreementKey, cborGenerator, COSEPublicKey.ECDH_ES_HKDF_256);
                }
                if (pinAuth != null) {
                    cborGenerator.writeFieldId(CTAP2Enums.ClientPINCommandParameter.pinAuth.value());
                    cborGenerator.writeBinary(pinAuth);
                }
                if (newPinEnc != null) {
                    cborGenerator.writeFieldId(CTAP2Enums.ClientPINCommandParameter.newPinEnc.value());
                    cborGenerator.writeBinary(newPinEnc);
                }
                if (pinHashEnc != null) {
                    cborGenerator.writeFieldId(CTAP2Enums.ClientPINCommandParameter.pinHashEnc.value());
                    cborGenerator.writeBinary(pinHashEnc);
                }
            }
            return CTAP2ProtocolHelpers.ctap2command(CTAP2Enums.Command.authenticatorClientPIN, byteArrayOutputStream.toByteArray());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
