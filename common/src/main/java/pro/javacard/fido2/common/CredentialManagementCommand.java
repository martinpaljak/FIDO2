package pro.javacard.fido2.common;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;

import static pro.javacard.fido2.common.PINProtocols.hmac_sha256;
import static pro.javacard.fido2.common.PINProtocols.left16;

// FIDO_2_1_PRE stuff from https://fidoalliance.org/specs/fido2/vendor/CredentialManagementPrototype.pdf
public class CredentialManagementCommand {
    // Subcommands:

    // getCredsMetadata
    // enumerateRPsBegin
    // enumerateRPsGetNextRP
    // enumerateCredentialsBegin
    // enumerateCredentialsGetNextCredential
    // deleteCredential


    byte subCommand = -1;
    byte[] pinAuth;
    byte pinProtocol = -1;
    byte[] rpidHash;
    byte[] credentialId;
    byte[] pinToken;

    public CredentialManagementCommand withSubCommand(int command) {
        subCommand = (byte) (command & 0X7F);
        return this;
    }

    public CredentialManagementCommand withPinProtocol(int protocol) {
        this.pinProtocol = (byte) (protocol & 0xFF);
        return this;
    }

    public CredentialManagementCommand withPinAuth(byte[] pinAuth) {
        this.pinAuth = pinAuth.clone();
        return this;
    }

    public CredentialManagementCommand withPinToken(byte[] pinToken) {
        this.pinToken = pinToken.clone();
        return this;
    }

    public CredentialManagementCommand withParamRpIdHash(byte[] hash) {
        this.rpidHash = hash.clone();
        return this;
    }

    public CredentialManagementCommand withParamCredentialId(byte[] id) {
        this.credentialId = id.clone();
        return this;
    }

    public static CredentialManagementCommand getCredsMetadata() {
        return new CredentialManagementCommand().withSubCommand(0x01).withPinProtocol(1);
    }

    public static CredentialManagementCommand getRPs() {
        return new CredentialManagementCommand().withSubCommand(0x02).withPinProtocol(1);
    }

    public static CredentialManagementCommand getNextRP() {
        return new CredentialManagementCommand().withSubCommand(0x03);
    }

    public static CredentialManagementCommand getCredentials(byte[] rpIdHash) {
        return new CredentialManagementCommand().withSubCommand(0x04).withParamRpIdHash(rpIdHash).withPinProtocol(1);
    }

    public static CredentialManagementCommand getNextCredential() {
        return new CredentialManagementCommand().withSubCommand(0x05);
    }

    public static CredentialManagementCommand deleteCredential(byte[] credentialId) {
        return new CredentialManagementCommand().withSubCommand(0x06).withParamCredentialId(credentialId).withPinProtocol(1);
    }

    public byte[] build() {
        if (subCommand == -1)
            throw new IllegalArgumentException("subcommand not set!");

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try (CBORGenerator cborGenerator = new CBORFactory().createGenerator(byteArrayOutputStream)) {
                int numItems = 1; // subcommand
                if (pinProtocol != -1 || pinToken != null)
                    numItems++;
                if (pinAuth != null || pinToken != null)
                    numItems++;
                if (rpidHash != null || credentialId != null)
                    numItems++;

                cborGenerator.writeStartObject(numItems);

                cborGenerator.writeFieldId(0x01); // subcomm
                cborGenerator.writeNumber(subCommand);

                if (rpidHash != null || credentialId != null) {
                    cborGenerator.writeFieldId(0x02); // params
                    cborGenerator.writeStartObject(1);
                    if (rpidHash != null) {
                        cborGenerator.writeFieldId(0x01); // params
                        cborGenerator.writeBinary(rpidHash);
                    } else if (credentialId != null) {
                        cborGenerator.writeFieldId(0x02); // params
                        cborGenerator.writeStartObject(2);
                        cborGenerator.writeFieldName("type");
                        cborGenerator.writeString("public-key");
                        cborGenerator.writeFieldName("id");
                        cborGenerator.writeBinary(credentialId);
                        cborGenerator.writeEndObject();
                    }
                    cborGenerator.writeEndObject();
                }
                if (pinProtocol != -1) {
                    cborGenerator.writeFieldId(0x03); // pin protocol
                    cborGenerator.writeNumber(1);
                }
                if (pinToken != null && pinAuth == null) {
                    pinProtocol = 1; // FIXME - this is not really right
                    switch (subCommand) {
                        case 0x01:
                            pinAuth = left16(hmac_sha256(pinToken, new byte[]{0x01}));
                            break;
                        case 0x02:
                            pinAuth = left16(hmac_sha256(pinToken, new byte[]{0x02}));
                            break;
                        case 0x04:
                            pinAuth = left16(hmac_sha256(pinToken, CryptoUtils.concatenate(new byte[]{0x04}, getAuthParameter())));
                            break;
                        case 0x06:
                            pinAuth = left16(hmac_sha256(pinToken, CryptoUtils.concatenate(new byte[]{0x06}, getAuthParameter())));
                            break;
                        default:
                            throw new IllegalArgumentException("Invalid subCommand for pinAuth: " + subCommand);
                    }
                }
                if (pinAuth != null) {
                    cborGenerator.writeFieldId(0x04);
                    cborGenerator.writeBinary(pinAuth);
                }
            }
            return CTAP2ProtocolHelpers.ctap2command(CTAP2Enums.Command.authenticatorCredentialManagementPre, byteArrayOutputStream.toByteArray());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] getAuthParameter() {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (CBORGenerator cborGenerator = new CBORFactory().createGenerator(byteArrayOutputStream)) {
            cborGenerator.writeStartObject(1);
            switch (subCommand) {
                case 0x04:
                    cborGenerator.writeFieldId(0x01); // params
                    cborGenerator.writeBinary(rpidHash);
                    break;
                case 0x06:
                    cborGenerator.writeFieldId(0x02); // params
                    cborGenerator.writeStartObject(2);
                    cborGenerator.writeFieldName("type");
                    cborGenerator.writeString("public-key");
                    cborGenerator.writeFieldName("id");
                    cborGenerator.writeBinary(credentialId);
                    cborGenerator.writeEndObject();
                    break;
                default:
                    throw new IllegalStateException("auth parameter is only for subcommands 0x04 and 0x06");
            }
            cborGenerator.writeEndObject();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return byteArrayOutputStream.toByteArray();
    }
}
