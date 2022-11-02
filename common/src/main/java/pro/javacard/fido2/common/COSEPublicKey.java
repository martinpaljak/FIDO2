package pro.javacard.fido2.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;

// COSE pubkey handling
public class COSEPublicKey {
    public static final int P256 = -7;
    public static final int Ed25519 = -8;

    public static final int ECDH_ES_HKDF_256 = -25;

    static final CBORFactory factory = new CBORFactory();

    static {
        factory.setCodec(CTAP2ProtocolHelpers.cborMapper);
    }

    static COSEPublicKey fromBytes(byte[] cbor) throws IOException {
        CBORParser parser = factory.createParser(cbor);
        ObjectNode parsed = parser.readValueAsTree();
        byte[] encoded = Arrays.copyOf(cbor, (int) parser.getCurrentLocation().getByteOffset() - 1);

        final PublicKey pubkey;
        switch (parsed.get("3").asInt()) {
            case P256:
                // This here is hacky and depends on jackson (we ask for string keys)
                byte[] x = parsed.get("-2").binaryValue();
                byte[] y = parsed.get("-3").binaryValue();
                pubkey = pro.javacard.fido2.common.P256.xy2pub(x, y);
                break;
            case Ed25519:
                pubkey = pro.javacard.fido2.common.Ed25519.bytes2pubkey(parsed.get("-2").binaryValue());
                break;
            default:
                throw new IOException("Unknown key type");
        }
        return new COSEPublicKey(encoded, pubkey);
    }

    static COSEPublicKey fromParsedNode(JsonNode parsed) throws IOException {
        final PublicKey pubkey;
        switch (parsed.get("3").asInt()) {
            case P256:
                // This here is hacky and depends on jackson (we ask for string keys)
                byte[] x = parsed.get("-2").binaryValue();
                byte[] y = parsed.get("-3").binaryValue();
                pubkey = pro.javacard.fido2.common.P256.xy2pub(x, y);
                break;
            case Ed25519:
                pubkey = pro.javacard.fido2.common.Ed25519.bytes2pubkey(parsed.get("-2").binaryValue());
                break;
            default:
                throw new IOException("Unknown key type");
        }
        return new COSEPublicKey(null, pubkey);
    }

    private COSEPublicKey(byte[] encoded, PublicKey pubkey) {
        this.encoded = encoded;
        this.publicKey = pubkey;
    }

    byte[] encoded;

    PublicKey publicKey;

    public static byte[] pubkey2bytes(PublicKey pubkey) {
        if (pubkey instanceof EdECPublicKey) {
            return pro.javacard.fido2.common.Ed25519.pubkey2bytes((EdECPublicKey) pubkey);
        } else if (pubkey instanceof ECPublicKey) {
            return pro.javacard.fido2.common.P256.pubkey2uncompressed((ECPublicKey) pubkey);
        } else {
            throw new IllegalArgumentException("Unknown pubkey type: " + pubkey);
        }
    }

    public byte[] getEncoded() {
        return encoded == null ? new byte[0] : encoded.clone();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public String toString() {
        if (publicKey instanceof EdECPublicKey) {
            return "ed25519:" + Hex.toHexString(pubkey2bytes(publicKey));
        } else if (publicKey instanceof ECPublicKey) {
            return "p256:" + Hex.toHexString(pubkey2bytes(publicKey));
        } else {
            return "UNKNOWN KEY: " + publicKey.getClass().getCanonicalName();
        }
    }
}
