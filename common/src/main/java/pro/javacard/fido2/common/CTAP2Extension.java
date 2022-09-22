package pro.javacard.fido2.common;

import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.IOException;
import java.security.interfaces.ECPublicKey;

public abstract class CTAP2Extension {

    abstract void serializeGetAssertionCBOR(CBORGenerator generator) throws IOException;

    abstract void serializeMakeCredentialCBOR(CBORGenerator generator) throws IOException;

    abstract String getExtensionName();

    public static class HMACSecret extends CTAP2Extension {
        private final ECPublicKey hostPublic;
        private final byte[] saltEnc;
        private final byte[] saltAuth;

        public HMACSecret() {
            hostPublic = null;
            saltAuth = null;
            saltEnc = null;
        }

        public HMACSecret(ECPublicKey hostPublic, byte[] saltEnc, byte[] saltAuth) {
            this.hostPublic = hostPublic;
            this.saltEnc = saltEnc.clone();
            this.saltAuth = saltAuth.clone();
        }

        @Override
        void serializeGetAssertionCBOR(CBORGenerator generator) throws IOException {
            generator.writeStartObject(3);
            generator.writeFieldId(1);
            COSE.pubkey2cbor(hostPublic, generator);
            generator.writeFieldId(2);
            generator.writeBinary(saltEnc);
            generator.writeFieldId(3);
            generator.writeBinary(saltAuth);
            generator.writeEndObject();
        }

        @Override
        void serializeMakeCredentialCBOR(CBORGenerator generator) throws IOException {
            generator.writeFieldName(getExtensionName());
            generator.writeBoolean(true);
        }

        @Override
        String getExtensionName() {
            return "hmac-secret";
        }
    }

    public static class CredProtect extends CTAP2Extension {
        public enum Protection {OPTIONAL, UNLESSKNOWN, REQUIRED}

        private final byte protection;

        public CredProtect(byte protection) {
            this.protection = protection;
        }

        @Override
        void serializeGetAssertionCBOR(CBORGenerator generator) throws IOException {
            // Nothing
        }

        @Override
        void serializeMakeCredentialCBOR(CBORGenerator generator) throws IOException {
            generator.writeFieldName(getExtensionName());
            generator.writeNumber(protection);
        }

        @Override
        String getExtensionName() {
            return "credProtect";
        }
    }
}
