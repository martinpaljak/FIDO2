package pro.javacard.fido2.common;

import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

public class FIDOCredential {

    public String getUsername() {
        return username;
    }

    public String getRpId() {
        return rpId;
    }

    public byte[] getCredentialID() {
        return credentialID.clone();
    }

    public ECPublicKey getPublicKey() {
        return publicKey;
    }

    final String username;
    final byte[] userId;

    final String rpId;
    final byte[] rpIdHash;

    final Map<String, Object> options = new HashMap<>();

    final byte[] credentialID;

    final ECPublicKey publicKey;

    public FIDOCredential(String username, byte[] userId, String rpId, byte[] rpIdHash, byte[] credentialID, ECPublicKey publicKey, Map<String, Object> options) {
        this.username = username;
        this.userId = userId.clone();

        this.rpId = rpId;
        this.rpIdHash = rpIdHash.clone();

        this.credentialID = credentialID.clone();
        this.publicKey = publicKey;

        if (options != null)
            this.options.putAll(options);
    }

    static FIDOCredential empty() {
        return new FIDOCredential(null, new byte[0], null, new byte[0], new byte[0], null, null);
    }

    @Override
    public String toString() {
        if (rpIdHash == null)
            return "EMPTY";
        else {
            return username + "@" + rpId;
        }
    }
}
