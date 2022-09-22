package pro.javacard.fido2.common;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

// PIN protocol implementation helpers
public final class PINProtocols {

    public static byte[] pad00(byte[] text, int blocksize) {
        int total = (text.length / blocksize + 1) * blocksize;
        return Arrays.copyOfRange(text, 0, total);
    }

    public static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] left16(byte[] v) {
        return Arrays.copyOf(v, 16);
    }

    public static byte[] hmac_sha256(byte[] k, byte[] v) {
        try {
            Mac hmacsha256 = Mac.getInstance("HmacSHA256");
            hmacsha256.init(new SecretKeySpec(k, "HmacSHA256"));
            return hmacsha256.doFinal(v);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aes256_decrypt(byte[] key, byte[] payload) {
        try {
            Cipher aes256 = Cipher.getInstance("AES/CBC/NoPadding");
            aes256.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
            return aes256.doFinal(payload);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] aes256_encrypt(byte[] key, byte[] payload) {
        try {
            Cipher aes256 = Cipher.getInstance("AES/CBC/NoPadding");
            aes256.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
            return aes256.doFinal(payload);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] shared_secret(ECPublicKey cardKey, KeyPair hostEphemeral) {
        try {
            // Derive secret SHA-256((baG).x)
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(hostEphemeral.getPrivate());
            ka.doPhase(cardKey, true);
            byte[] shared_secret = ka.generateSecret();
            // Do SHA256 of the point
            return sha256(shared_secret);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
