package pro.javacard.fido2.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.interfaces.ECPublicKey;

// COSE pubkey handling
public class COSE {
    public static final byte P256 = -7;
    public static final byte Ed25519 = -8;

    public static ECPublicKey extractKeyAgreementKey(byte[] response) throws IOException {
        // Extract public key
        ObjectNode kak = (ObjectNode) CTAP2ProtocolHelpers.cborMapper.readTree(response);
        //System.out.println(CTAP2ProtocolHelpers.pretty.writeValueAsString(CTAP2ProtocolHelpers.hexify(kak)));

        // This here is hacky and depends on jackson (we ask for string keys)
        byte[] x = kak.get("-2").binaryValue();
        byte[] y = kak.get("-3").binaryValue();
        ECPublicKey cardKey = CryptoUtils.xy2pub(x, y);
        return cardKey;
    }

    public static ECPublicKey extractKeyAgreementKey(JsonNode keyNode) throws IOException {
        // Extract public key
        // This here is hacky and depends on jackson (we ask for string keys)
        byte[] x = keyNode.get("-2").binaryValue();
        byte[] y = keyNode.get("-3").binaryValue();
        ECPublicKey cardKey = CryptoUtils.xy2pub(x, y);
        return cardKey;
    }


    // TODO: This does by default key exhange purpose! (-25). Signature key requires explicit -7
    static void pubkey2cbor(ECPublicKey pub, CBORGenerator container) {
        pubkey2cbor(pub, container, (byte) -25);
    }

    static void pubkey2cbor(ECPublicKey pub, CBORGenerator container, byte type) {
        try {
            container.writeStartObject(5);

            container.writeFieldId(1);
            container.writeNumber(2);

            container.writeFieldId(3);
            container.writeNumber(type);

            container.writeFieldId(-1);
            container.writeNumber(1); // P256

            container.writeFieldId(-2);
            container.writeBinary(CryptoUtils.positive(pub.getW().getAffineX().toByteArray()));

            container.writeFieldId(-3);
            container.writeBinary(CryptoUtils.positive(pub.getW().getAffineY().toByteArray()));

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
