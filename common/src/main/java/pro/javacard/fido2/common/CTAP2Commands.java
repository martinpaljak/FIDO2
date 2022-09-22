package pro.javacard.fido2.common;

import apdu4j.core.CommandAPDU;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

import static pro.javacard.fido2.common.CryptoUtils.concatenate;
import static pro.javacard.fido2.common.PINProtocols.*;

// Construction of CTAP2 commands via functions.
public final class CTAP2Commands {

    public static byte[] select() {
        return new CommandAPDU(0x00, 0xA4, 0x04, 0x00, CTAP2ProtocolHelpers.FIDO_AID, 256).getBytes();
    }

    public static byte[] make_setPIN(String pin, ECPublicKey cardKey, KeyPair hostEphemeral) {
        // Get shared secret
        byte[] sharedSecret = shared_secret(cardKey, hostEphemeral);

        // Pad with 0x00 to 64 bytes
        byte[] pinValue = pad00(pin.getBytes(StandardCharsets.UTF_8), 64);

        // AES256-CBC(sharedSecret, IV=0, newPin)
        byte[] newPinEnc = aes256_encrypt(sharedSecret, pinValue);

        // LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16).
        byte[] pinAuth = left16(hmac_sha256(sharedSecret, newPinEnc));

        return new ClientPINCommand()
                .withProtocol(1)
                .withSubCommand(CTAP2Enums.ClientPINCommandSubCommand.setPIN.value())
                .withHostKey((ECPublicKey) hostEphemeral.getPublic())
                .withNewPinEnc(newPinEnc)
                .withPinAuth(pinAuth)
                .build();
    }


    public static byte[] make_changePIN(String curPin, String newPin, ECPublicKey cardKey, KeyPair hostEphemeral) {
        // Get shared secret
        byte[] sharedSecret = shared_secret(cardKey, hostEphemeral);

        byte[] pinHashEnc = aes256_encrypt(sharedSecret, left16(sha256(curPin.getBytes(StandardCharsets.UTF_8))));

        // Pad with 0x00 to 64 bytes
        byte[] newPinValue = pad00(newPin.getBytes(StandardCharsets.UTF_8), 64);

        // AES256-CBC(sharedSecret, IV=0, newPin)
        byte[] newPinEnc = aes256_encrypt(sharedSecret, newPinValue);

        // LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16).
        byte[] pinAuth = left16(hmac_sha256(sharedSecret, concatenate(newPinEnc, pinHashEnc)));

        return new ClientPINCommand()
                .withProtocol(1)
                .withSubCommand(CTAP2Enums.ClientPINCommandSubCommand.changePIN.value())
                .withHostKey((ECPublicKey) hostEphemeral.getPublic())
                .withNewPinEnc(newPinEnc)
                .withPinHashEnc(pinHashEnc)
                .withPinAuth(pinAuth)
                .build();
    }


    public static byte[] make_getPinToken(String pin, ECPublicKey cardKey, KeyPair hostEphemeral) {
        byte[] sharedSecret = shared_secret(cardKey, hostEphemeral);
        byte[] pinHash = left16(sha256(pin.getBytes(StandardCharsets.UTF_8)));
        byte[] pinHashEnc = aes256_encrypt(sharedSecret, pinHash);

        return new ClientPINCommand()
                .withProtocol(1)
                .withSubCommand(CTAP2Enums.ClientPINCommandSubCommand.getPINToken.value())
                .withHostKey((ECPublicKey) hostEphemeral.getPublic())
                .withPinHashEnc(pinHashEnc)
                .build();
    }
}
