package pro.javacard.fido2.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

// WebAuthn cargo cult for testing purposes.
@SuppressWarnings("rawtypes")
public class WebAuthnPlatform {

    static final ObjectMapper json = new ObjectMapper();
    final String origin;

    public WebAuthnPlatform(URI uri) {
        origin = uri.getHost().toLowerCase();
    }


    public Map create() {
        return null;
    }

    public Map get() {
        return null;
    }

    static class PublicKeyCredentialRpEntity {
        final String id; // origin

        PublicKeyCredentialRpEntity(String id) {
            this.id = id;
        }
    }

    static class PublicKeyCredentialUserEntity {
        final byte[] id;
        final String displayName;

        PublicKeyCredentialUserEntity(String displayName, byte[] id) {
            this.id = id.clone();
            this.displayName = displayName;
        }
    }

    static class PublicKeyCredentialParameters {
        final String type;
        final int alg;

        PublicKeyCredentialParameters(int algo) {
            this.type = "public-key";
            this.alg = algo;
        }

    }

    static class AuthenticatorSelectionCriteria {
        String authenticatorAttachment; // "platform" and "cross-platform"
        String residentKey; // "required" "preferred" "discouraged"
        boolean requireResidentKey = false;
        String userVerification = "preferred"; // "required" "preferred" "discouraged"

        AuthenticatorSelectionCriteria withUserVerification(String v) {
            userVerification = v;
            return this;
        }

        AuthenticatorSelectionCriteria withResidentKey(String v) {
            residentKey = v;
            if (residentKey.equals("required"))
                requireResidentKey = true;
            return this;
        }
    }

    static class PublicKeyCredentialCreationOptions {
        final PublicKeyCredentialRpEntity rp;
        final PublicKeyCredentialUserEntity user;

        final byte[] challenge;

        final List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>();

        long timeout;

        List<PublicKeyCredentialDescriptor> excludeCredentials = new ArrayList<>();
        AuthenticatorSelectionCriteria authenticatorSelection;
        String attestation = "none";
        ObjectNode extensions;

        PublicKeyCredentialCreationOptions(PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user, byte[] challenge, List<PublicKeyCredentialParameters> algos) {
            this.rp = rp;
            this.user = user;
            this.challenge = challenge.clone();
            this.pubKeyCredParams.addAll(algos);
        }

    }


    static class PublicKeyCredentialDescriptor {
        final String type;
        final byte[] id;
        final List<String> transports;

        PublicKeyCredentialDescriptor(byte[] id, String transport) {
            type = "public-key";
            this.id = id.clone();
            transports = Arrays.asList(transport);
        }
    }

    static class ClientDataJSON {
        final String type;
        final String origin;
        final byte[] challenge;


        ClientDataJSON(String type, String origin, byte[] challenge) {
            this.type = type;
            this.origin = origin;
            this.challenge = challenge.clone();
        }

        @Override
        public String toString() {
            try {
                LinkedHashMap<String, Object> ordered = new LinkedHashMap<>();
                ordered.put("type", type);
                ordered.put("challenge", Base64.getUrlEncoder().withoutPadding().encode(challenge));
                ordered.put("origin", origin);
                ordered.put("crossOrigin", false);
                return json.writeValueAsString(ordered);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        public byte[] hash() {
            return PINProtocols.sha256(toString().getBytes(StandardCharsets.UTF_8));
        }
    }
}
