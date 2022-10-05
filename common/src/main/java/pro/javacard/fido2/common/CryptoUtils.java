package pro.javacard.fido2.common;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

// Various secp256r1 and crypto blob handling primitives
public class CryptoUtils {

    static final CBORFactory cbor = new CBORFactory();


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


    public static UUID bytes2uuid(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        long high = bb.getLong();
        long low = bb.getLong();
        UUID uuid = new UUID(high, low);
        return uuid;
    }


    public static PublicKey bytes2pubkey(byte[] bytes) {
        if (bytes.length == 32) {
            return Ed25519.bytes2pubkey(bytes);
        } else if (bytes.length == 65) {
            return P256.uncompressed2pubkey(bytes);
        } else {
            throw new IllegalArgumentException("Unknown key: " + Hex.toHexString(bytes));
        }
    }

    // Right-align byte array to the specified size, padding with 0 from left if needed,
    // taking only rightmost bytes if more than len present
    public static byte[] leftpad(byte[] bytes, int len) {
        byte[] nv = new byte[len];
        if (bytes.length < len) {
            System.arraycopy(bytes, 0, nv, len - bytes.length, bytes.length);
        } else {
            System.arraycopy(bytes, bytes.length - len, nv, 0, len);
        }
        return nv;
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

    public static byte[] reverse(byte[] d) {
        byte[] r = new byte[d.length];
        for (int i = 0; i < d.length; i++) {
            r[i] = d[d.length - 1 - i];
        }
        return r;
    }
}
