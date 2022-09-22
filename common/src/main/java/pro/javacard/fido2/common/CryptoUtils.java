package pro.javacard.fido2.common;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

// Various secp256r1 and crypto blob handling primitives
public class CryptoUtils {

    static final CBORFactory cbor = new CBORFactory();

    static ECParameterSpec SPEC = ECNamedCurveTable.getParameterSpec("secp256r1");
    static java.security.spec.ECParameterSpec secp256r1;

    static {
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters curve = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1");
        secp256r1 = new ECNamedCurveSpec("secp256r1", curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
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


    public static byte[] random(int bytes) {
        try {
            byte[] r = new byte[bytes];
            SecureRandom.getInstanceStrong().nextBytes(r);
            return r;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }


    public static byte[] concatenate(byte[]... args) {
        int length = 0, pos = 0;
        for (byte[] arg : args) {
            length += arg.length;
        }
        byte[] result = new byte[length];
        for (byte[] arg : args) {
            System.arraycopy(arg, 0, result, pos, arg.length);
            pos += arg.length;
        }
        return result;
    }

    // Remove leading 0x00 byte from a positive bignum
    // Assumes the bignum length must be even number of bytes
    public static byte[] positive(byte[] bytes) {
        if (bytes[0] == 0 && bytes.length % 2 == 1) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    public static ECPublicKey xy2pub(byte[] x, byte[] y) {
        try {
            java.security.spec.ECPoint w = new java.security.spec.ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            ECPublicKeySpec ec = new ECPublicKeySpec(w, CryptoUtils.secp256r1);
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

    public static UUID bytes2uuid(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        long high = bb.getLong();
        long low = bb.getLong();
        UUID uuid = new UUID(high, low);
        return uuid;
    }

    public static byte[] pubkey2uncompressed(ECPublicKey pubkey) {
        byte[] x = positive(pubkey.getW().getAffineX().toByteArray());
        byte[] y = positive(pubkey.getW().getAffineY().toByteArray());
        return concatenate(new byte[]{0x04}, leftpad(x, 32), leftpad(y, 32));
    }

    public static ECPublicKey uncompressed2pubkey(byte[] pubkey) {
        try {
            // get public key
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubkey, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(pubkey, 33, pubkey.length));
            java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
            ECPublicKeySpec ec = new ECPublicKeySpec(w, secp256r1);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(ec);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    // Right-align byte array to the specified size, padding with 0 from left
    public static byte[] leftpad(byte[] bytes, int len) {
        if (bytes.length < len) {
            byte[] nv = new byte[len];
            System.arraycopy(bytes, 0, nv, len - bytes.length, bytes.length);
            return nv;
        }
        return bytes;
    }

    public static List<byte[]> splitArray(byte[] array, int blockSize) {
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

    // Convert the R||S representation to DER (as used by Java)
    public static byte[] rs2der(byte[] rs) throws SignatureException {
        if (rs.length % 2 != 0) {
            throw new IllegalArgumentException("R||S representation must be even bytes: " + rs.length);
        }
        try {
            byte[] r = Arrays.copyOfRange(rs, 0, rs.length / 2);
            byte[] s = Arrays.copyOfRange(rs, rs.length / 2, rs.length);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            ASN1OutputStream ders = ASN1OutputStream.create(bo, ASN1Encoding.DER);
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(new BigInteger(1, r)));
            v.add(new ASN1Integer(new BigInteger(1, s)));
            ders.writeObject(new DERSequence(v));
            return bo.toByteArray();
        } catch (IOException e) {
            throw new SignatureException("Can not convert R||S to DER: " + e.getMessage());
        }
    }

}
