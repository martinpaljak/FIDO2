package pro.javacard.fido2.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;
import java.util.UUID;

public class AttestationData {
    private static final Logger logger = LoggerFactory.getLogger(AttestationData.class);

    byte[] aaguid;
    byte[] credentialID;
    PublicKey publicKey;

    int length;

    private AttestationData(byte[] aaguid, byte[] credentialID, PublicKey publicKey, int length) {
        this.aaguid = aaguid.clone();
        this.credentialID = credentialID.clone();
        this.publicKey = publicKey;
        this.length = length;
        logger.debug("Created attestation: " + this);
    }

    static AttestationData fromBytes(byte[] bytes) throws IOException {
        ByteBuffer b = ByteBuffer.wrap(bytes);
        byte[] aaguid = new byte[16];
        b.get(aaguid);
        short credLen = b.getShort();
        byte[] cred = new byte[credLen];
        b.get(cred);

        byte[] remaining = Arrays.copyOfRange(bytes, 16 + 2 + credLen, bytes.length);

        COSEPublicKey cosekey = COSEPublicKey.fromBytes(remaining);

        return new AttestationData(aaguid, cred, cosekey.getPublicKey(), 16 + 2 + cred.length + cosekey.getEncoded().length);
    }

    public UUID getAAGUID() {
        return CryptoUtils.bytes2uuid(aaguid);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public byte[] getCredentialID() {
        return credentialID.clone();
    }

    @Override
    public String toString() {
        return "AttestationData{" +
                "aaguid=" + CryptoUtils.bytes2uuid(aaguid) +
                ", credentialID=" + Hex.toHexString(credentialID) +
                ", publicKey=" + Hex.toHexString(COSEPublicKey.pubkey2bytes(publicKey)) +
                ", length=" + length +
                '}';
    }

    // Given the input of attestation data, return the length of it
    public int getLength() {
        return length;
    }

    // XXX: this is purely "visual"
    public JsonNode toJSON() {
        ObjectNode result = JsonNodeFactory.instance.objectNode();
        result.put("aaguid", getAAGUID().toString());
        result.put("credentialID", credentialID);
        ObjectNode pubkey = JsonNodeFactory.instance.objectNode();
        if (publicKey instanceof EdECPublicKey) {
            // "okp" type 1:1 Algo 3: -8 EdDSA, curve -1: 6 Ed25519
            EdECPublicKey ecpub = (EdECPublicKey) publicKey;
            pubkey.put("crv", "Ed25519");
            pubkey.put("kty", "OKP");
            pubkey.put("x", CryptoUtils.reverse(CryptoUtils.positive(ecpub.getPoint().getY().toByteArray())));
        } else if (publicKey instanceof ECPublicKey) {
            // 1:2 xy type,
            ECPublicKey ecpub = (ECPublicKey) publicKey;
            pubkey.put("crv", "P-256");
            pubkey.put("kty", "EC");
            pubkey.put("x", CryptoUtils.positive(ecpub.getW().getAffineX().toByteArray()));
            pubkey.put("y", CryptoUtils.positive(ecpub.getW().getAffineY().toByteArray()));
        } else {
            throw new IllegalArgumentException("Unknown public key: " + publicKey);
        }
        result.set("publicKey", pubkey);
        return CTAP2ProtocolHelpers.hexify(result);
    }
}
