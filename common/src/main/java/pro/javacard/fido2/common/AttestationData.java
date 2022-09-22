package pro.javacard.fido2.common;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

public class AttestationData {
    private static final Logger logger = LoggerFactory.getLogger(AttestationData.class);

    byte[] aaguid;
    byte[] credentialID;
    ECPublicKey publicKey;

    int length;

    private AttestationData(byte[] aaguid, byte[] credentialID, ECPublicKey publicKey) {
        this.aaguid = aaguid.clone();
        this.credentialID = credentialID.clone();
        this.publicKey = publicKey;
        this.length = 16 + 2 + credentialID.length + 77; // FIXME: fixed to secp256r1
    }

    static AttestationData fromBytes(byte[] bytes) throws IOException {
        ByteBuffer b = ByteBuffer.wrap(bytes);
        byte[] aaguid = new byte[16];
        b.get(aaguid);
        short credLen = b.getShort();
        byte[] cred = new byte[credLen];
        b.get(cred);
        byte[] coseKey = new byte[77];
        b.get(coseKey);

        ECPublicKey key = COSE.extractKeyAgreementKey(coseKey);
        return new AttestationData(aaguid, cred, key);
    }

    public UUID getAAGUID() {
        return CryptoUtils.bytes2uuid(aaguid);
    }

    public ECPublicKey getPublicKey() {
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
                ", publicKey=" + Hex.toHexString(CryptoUtils.pubkey2uncompressed(publicKey)) +
                '}';
    }

    // Given the input of attestation data, return the length of it
    public int getLength() {
        return length;
    }

    // XXX: this is purely "visual"
    public ObjectNode toJSON() {
        ObjectNode result = JsonNodeFactory.instance.objectNode();
        result.put("aaguid", getAAGUID().toString());
        result.put("credentialID", Hex.toHexString(credentialID));
        ObjectNode pubkey = JsonNodeFactory.instance.objectNode();
        pubkey.put("crv", "P-256");
        pubkey.put("kty", "EC");
        pubkey.put("x", Hex.toHexString(CryptoUtils.positive(publicKey.getW().getAffineX().toByteArray())));
        pubkey.put("y", Hex.toHexString(CryptoUtils.positive(publicKey.getW().getAffineY().toByteArray())));
        result.set("publicKey", pubkey);
        return result;
    }
}
