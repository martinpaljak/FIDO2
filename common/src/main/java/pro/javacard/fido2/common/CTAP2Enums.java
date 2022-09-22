package pro.javacard.fido2.common;

import java.util.Arrays;
import java.util.Optional;

// Names for CTAP2 numerics
public class CTAP2Enums {

    public enum Command {
        authenticatorMakeCredential(0x01),
        authenticatorGetAssertion(0x02),
        authenticatorGetInfo(0x04),
        authenticatorClientPIN(0x06),
        authenticatorReset(0x07),
        authenticatorGetNextAssertion(0x08),
        authenticatorBioEnrollment(0x09), // 2.1
        authenticatorCredentialManagement(0x0A), // 2.1
        authenticatorSelection(0x0B), // 2.1
        authenticatorLargeBlobs(0x0C), // 2.1
        authenticatorConfig(0x0D), // 2.1
        authenticatorBioEnrollmentPre(0x40), // 2.1 pre
        authenticatorCredentialManagementPre(0x41), // 2.1 pre

        // Proprietary commands
        vendorCBOR(0x50),
        vendorXCBOR(0x51);

        public final byte cmd;

        Command(int b) {
            this.cmd = (byte) (b & 0xFF);
        }

        public static Optional<Command> valueOf(byte v) {
            return Arrays.stream(values()).filter(command -> command.cmd == v).findFirst();
        }
    }

    public enum MakeCredentialCommandParameter {
        clientDataHash(1),
        rp(2),
        user(3),
        pubKeyCredParams(4),
        excludeList(5),
        extensions(6),
        options(7),
        pinAuth(8),
        pinProtocol(9),

        enterpriseAttestation(0x0A); // 2.1
        private final byte v;

        MakeCredentialCommandParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<MakeCredentialCommandParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.value() == v).findFirst();
        }

        public byte value() {
            return v;
        }
    }


    public enum MakeCredentialResponseParameter {
        fmt(1),
        authData(2),
        attStmt(3),
        epAtt(4), // 2.1
        largeBlobKey(5); // 2.1
        private final byte v;

        MakeCredentialResponseParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<MakeCredentialResponseParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.value() == v).findFirst();
        }

        public byte value() {
            return v;
        }
    }


    public enum GetInfoResponseParameter {
        versions(1),
        extensions(2),
        aaguid(3),
        options(4),
        maxMsgSize(5),
        pinUvAuthProtocols(6),
        // CTAP2.1
        maxCredentialCountInList(7),
        maxCredentialIdLength(8),
        transports(9),
        algorithms(0xA),
        maxSerializedLargeBlobArray(0xB),
        forcePINChange(0xC),
        minPINLength(0xD),
        firmwareVersion(0xE),
        maxCredBlobLength(0xF),
        maxRPIDsForSetMinPINLength(0x10),
        preferredPlatformUvAttempts(0x11),
        uvModality(0x12),
        certifications(0x13),
        remainingDiscoverableCredentials(0x14),
        vendorPrototypeConfigCommands(0x15);
        private final byte v;

        GetInfoResponseParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<GetInfoResponseParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.value() == v).findFirst();
        }

        public byte value() {
            return v;
        }
    }


    public enum GetAssertionCommandParameter {
        rpId(1),
        clientDataHash(2),
        allowList(3),
        extensions(4),
        options(5),
        pinAuth(6),
        pinProtocol(7);
        private final byte v;

        GetAssertionCommandParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<GetAssertionCommandParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.value() == v).findFirst();
        }

        public byte value() {
            return v;
        }
    }

    public enum GetAssertionResponseParameter {
        credential(1),
        authData(2),
        signature(3),
        publicKeyCredentialUserEntity(4),
        numberOfCredentials(5);
        private final byte v;

        GetAssertionResponseParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<GetAssertionResponseParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.value() == v).findFirst();
        }

        public byte value() {
            return v;
        }
    }

    public enum ClientPINCommandParameter {
        pinProtocol(1),
        subCommand(2),
        keyAgreement(3),
        pinAuth(4),
        newPinEnc(5),
        pinHashEnc(6),
        permissions(7), // 2.1
        rpId(8); // 2.1
        private final byte v;

        ClientPINCommandParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<ClientPINCommandParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.value() == v).findFirst();
        }

        public byte value() {
            return v;
        }
    }

    public enum ClientPINCommandSubCommand {
        getReries(1),
        getKeyAgreement(2),
        setPIN(3),
        changePIN(4),
        getPINToken(5),
        getPinUvAuthTokenUsingUvWithPermissions(6), // 2.1
        getUVRetries(7), // 2.1
        getPinUvAuthTokenUsingPinWithPermissions(8); // 2.1

        private final byte v;

        ClientPINCommandSubCommand(int v) {
            this.v = (byte) v;
        }

        public byte value() {
            return v;
        }
    }


    public enum ClientPINResponseParameter {
        keyAgreement(1),
        pinToken(2),
        retries(3),
        powerCycleState(4), // 2.1
        uvRetries(5); // 2.1

        public final byte v;

        ClientPINResponseParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<ClientPINResponseParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.v == v).findFirst();
        }
    }


    public enum CredentialManagementPreCommandParameter {
        subCommand(1),
        subCommandParams(2),
        pinProtocol(3),
        pinAuth(4);
        public final byte v;

        CredentialManagementPreCommandParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<CredentialManagementPreCommandParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.v == v).findFirst();
        }
    }

    public enum CredentialManagementPreResponseParameter {
        existingResidentCredentialsCount(1),
        maxPossibleRemainingResidentCredentialsCount(2),
        rp(3),
        rpIDHash(4),
        totalRPs(5),
        user(6),
        credentialID(7),
        publicKey(8),
        totalCredentials(9),
        credProtect(0x0A),

        largeBlobKey(0x0B);

        public final byte v;

        CredentialManagementPreResponseParameter(int v) {
            this.v = (byte) v;
        }

        public static Optional<CredentialManagementPreResponseParameter> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.v == v).findFirst();
        }
    }


    public enum Error {
        CTAP1_ERR_SUCCESS((byte) 0x00),
        CTAP1_ERR_INVALID_COMMAND((byte) 0x01),
        CTAP1_ERR_INVALID_PARAMETER((byte) 0x02),
        CTAP1_ERR_INVALID_LENGTH((byte) 0x03),
        CTAP1_ERR_INVALID_SEQ((byte) 0x04),
        CTAP1_ERR_TIMEOUT((byte) 0x05),
        CTAP1_ERR_CHANNEL_BUSY((byte) 0x06),
        CTAP1_ERR_LOCK_REQUIRED((byte) 0x0A),
        CTAP1_ERR_INVALID_CHANNEL((byte) 0x0B),
        CTAP2_ERR_CBOR_UNEXPECTED_TYPE((byte) 0x11),
        CTAP2_ERR_INVALID_CBOR((byte) 0x12),
        CTAP2_ERR_MISSING_PARAMETER((byte) 0x14),
        CTAP2_ERR_LIMIT_EXCEEDED((byte) 0x15),
        CTAP2_ERR_UNSUPPORTED_EXTENSION((byte) 0x16),
        CTAP2_ERR_CREDENTIAL_EXCLUDED((byte) 0x19),
        CTAP2_ERR_PROCESSING((byte) 0x21),
        CTAP2_ERR_INVALID_CREDENTIAL((byte) 0x22),
        CTAP2_ERR_USER_ACTION_PENDING((byte) 0x23),
        CTAP2_ERR_OPERATION_PENDING((byte) 0x24),
        CTAP2_ERR_NO_OPERATIONS((byte) 0x25),
        CTAP2_ERR_UNSUPPORTED_ALGORITHM((byte) 0x26),
        CTAP2_ERR_OPERATION_DENIED((byte) 0x27),
        CTAP2_ERR_KEY_STORE_FULL((byte) 0x28),
        CTAP2_ERR_NOT_BUSY((byte) 0x29),
        CTAP2_ERR_NO_OPERATION_PENDING((byte) 0x2A),
        CTAP2_ERR_UNSUPPORTED_OPTION((byte) 0x2B),
        CTAP2_ERR_INVALID_OPTION((byte) 0x2C),
        CTAP2_ERR_KEEPALIVE_CANCEL((byte) 0x2D),
        CTAP2_ERR_NO_CREDENTIALS((byte) 0x2E),
        CTAP2_ERR_USER_ACTION_TIMEOUT((byte) 0x2F),
        CTAP2_ERR_NOT_ALLOWED((byte) 0x30),
        CTAP2_ERR_PIN_INVALID((byte) 0x31),
        CTAP2_ERR_PIN_BLOCKED((byte) 0x32),
        CTAP2_ERR_PIN_AUTH_INVALID((byte) 0x33),
        CTAP2_ERR_PIN_AUTH_BLOCKED((byte) 0x34),
        CTAP2_ERR_PIN_NOT_SET((byte) 0x35),
        CTAP2_ERR_PIN_REQUIRED((byte) 0x36),
        CTAP2_ERR_PIN_POLICY_VIOLATION((byte) 0x37),
        CTAP2_ERR_PIN_TOKEN_EXPIRED((byte) 0x38),
        CTAP2_ERR_REQUEST_TOO_LARGE((byte) 0x39),
        CTAP2_ERR_ACTION_TIMEOUT((byte) 0x3A),
        CTAP2_ERR_UP_REQUIRED((byte) 0x3B),
        CTAP1_ERR_OTHER((byte) 0x7F),
        CTAP2_ERR_SPEC_LAST((byte) 0xDF),
        CTAP2_ERR_EXTENSION_FIRST((byte) 0xE0),
        CTAP2_ERR_EXTENSION_LAST((byte) 0xEF),
        CTAP2_ERR_VENDOR_FIRST((byte) 0xF0),
        CTAP2_ERR_VENDOR_LAST((byte) 0xFF);

        public final byte v;

        Error(byte v) {
            this.v = v;
        }

        public static Optional<Error> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.v == v).findFirst();
        }
    }
}
