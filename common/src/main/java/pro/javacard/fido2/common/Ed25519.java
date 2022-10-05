package pro.javacard.fido2.common;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;

public class Ed25519 {

    static EdECPublicKey bytes2pubkey(byte[] bytes) {
        // RCF 8032 5.1.2 and 5.1.3
        try {
            KeyFactory kf = KeyFactory.getInstance("EdDSA");
            boolean xOdd = (bytes[bytes.length - 1] & 0x80) == 0x80;
            BigInteger y = new BigInteger(1, CryptoUtils.reverse(bytes));
            NamedParameterSpec paramSpec = new NamedParameterSpec("Ed25519");
            EdECPublicKeySpec pubSpec = new EdECPublicKeySpec(paramSpec, new EdECPoint(xOdd, y));
            return (EdECPublicKey) kf.generatePublic(pubSpec);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Can not handle ed25519");
        }
    }

    public static byte[] pubkey2bytes(EdECPublicKey pubkey) {
        byte[] y = CryptoUtils.reverse(pubkey.getPoint().getY().toByteArray());
        if (pubkey.getPoint().isXOdd()) {
            y[y.length - 1] |= (byte) 0x80;
        }
        return y;
    }
}
