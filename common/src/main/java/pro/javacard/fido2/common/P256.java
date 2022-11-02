package pro.javacard.fido2.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

public class P256 {

    static java.security.spec.ECParameterSpec secp256r1;

    static ECParameterSpec SPEC = ECNamedCurveTable.getParameterSpec("secp256r1");


    static {
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters curve = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1");
        secp256r1 = new ECNamedCurveSpec("secp256r1", curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
    }

    byte[] private2public(byte[] key) {
        ECNamedCurveParameterSpec crv = ECNamedCurveTable.getParameterSpec("secp256r1");
        return crv.getG().multiply(new BigInteger(1, key)).getEncoded(false);
    }

    public static KeyPair ephemeral() {
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC");
            keyGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            return keyGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECPublicKey xy2pub(byte[] x, byte[] y) {
        try {
            ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            ECPublicKeySpec ec = new ECPublicKeySpec(w, secp256r1);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            ECPublicKey cardKey = (ECPublicKey) keyFactory.generatePublic(ec);
            return cardKey;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECPrivateKey private2privkey(byte[] p) {
        try {
            ECPrivateKeySpec ec = new ECPrivateKeySpec(new BigInteger(p), secp256r1);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPrivateKey) keyFactory.generatePrivate(ec);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] pubkey2uncompressed(ECPublicKey pubkey) {
        byte[] x = CryptoUtils.positive(pubkey.getW().getAffineX().toByteArray());
        byte[] y = CryptoUtils.positive(pubkey.getW().getAffineY().toByteArray());
        return CryptoUtils.concatenate(new byte[]{0x04}, CryptoUtils.leftpad(x, 32), CryptoUtils.leftpad(y, 32));
    }

    public static ECPublicKey uncompressed2pubkey(byte[] pubkey) {
        try {
            // get public key
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubkey, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(pubkey, 33, pubkey.length));
            ECPoint w = new ECPoint(x, y);
            ECPublicKeySpec ec = new ECPublicKeySpec(w, secp256r1);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(ec);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECPublicKey node2pubkey(JsonNode node) throws IOException {
        // This here is hacky and depends on jackson (we ask for string keys)
        byte[] x = node.get("-2").binaryValue();
        byte[] y = node.get("-3").binaryValue();
        return xy2pub(x, y);
    }

    static void pubkey2cbor(ECPublicKey pub, CBORGenerator container, int type) {
        try {
            container.writeStartObject(5);

            container.writeFieldId(1);
            container.writeNumber(2);

            container.writeFieldId(3);
            container.writeNumber(type);

            container.writeFieldId(-1);
            container.writeNumber(1); // FIXME P256

            container.writeFieldId(-2);
            container.writeBinary(CryptoUtils.leftpad(CryptoUtils.positive(pub.getW().getAffineX().toByteArray()), 32));

            container.writeFieldId(-3);
            container.writeBinary(CryptoUtils.leftpad(CryptoUtils.positive(pub.getW().getAffineY().toByteArray()), 32));

            container.writeEndObject();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] pubkey2cbor(ECPublicKey pub) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (CBORGenerator container = CryptoUtils.cbor.createGenerator(bos)) {
            pubkey2cbor(pub, container, (byte) -7); // FIXME type implicit
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return bos.toByteArray();
    }
}
