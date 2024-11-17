package pro.javacard.fido2.common;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.*;
import java.util.function.Function;

import static pro.javacard.fido2.common.CTAP2Enums.Error.CTAP1_ERR_SUCCESS;
import static pro.javacard.fido2.common.CTAP2Enums.Error.valueOf;
import static pro.javacard.fido2.common.CryptoUtils.concatenate;

@SuppressWarnings({"deprecation", "rawtypes"})
public class CTAP2ProtocolHelpers {
    private static final Logger logger = LoggerFactory.getLogger(CTAP2ProtocolHelpers.class);

    public static final ObjectMapper cborMapper = new CBORMapper();
    public static final ObjectMapper mapper = new ObjectMapper();

    private static PrintStream protocolDebug = null;

    public static void setProtocolDebug(OutputStream debug) {
        protocolDebug = new PrintStream(debug, true, StandardCharsets.UTF_8);
    }

    static {
        // FIXME: QUOTE_FIELD_NAMES in com.fasterxml.jackson.core.JsonGenerator.Feature has been deprecated
        mapper.configure(JsonGenerator.Feature.QUOTE_FIELD_NAMES, false); // We have numerics in visual
    }

    public static final ObjectWriter pretty = mapper.writerWithDefaultPrettyPrinter();

    public static String pretty(JsonNode node) throws IOException {
        return pretty.writeValueAsString(node);
    }

    public static final byte[] FIDO_AID = Hex.decode("A0000006472F0001");

    // Recursive and makes a copy of the node
    public static JsonNode hexify(JsonNode node) {
        return hexify_(node.deepCopy());
    }

    static JsonNode hexify_(JsonNode node) {
        if (node.isArray()) {
            ArrayNode hexified = mapper.createArrayNode();
            node.forEach(e -> hexified.add(hexify_(e)));
            return hexified;
        } else if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            obj.fieldNames().forEachRemaining(fn -> obj.set(fn, hexify_(obj.get(fn))));
            return obj;
        } else if (node.isBinary()) {
            byte[] bytes = Base64.decode(node.asText());
            return new TextNode(bytes.length + " " + Hex.toHexString(bytes));
        }
        return node;
    }

    // Response parsing helpers
    public static CTAP2Enums.Error status(byte[] response) {
        return CTAP2Enums.Error.valueOf(response[0]).orElseThrow(() -> new RuntimeException("Unknown status: " + response[0]));
    }

    public static ObjectNode payload(byte[] response) {
        CTAP2Enums.Error status = status(response);
        if (status != CTAP1_ERR_SUCCESS)
            throw new RuntimeException("Response is not success: " + status);
        try {
            return (ObjectNode) cborMapper.readTree(Arrays.copyOfRange(response, 1, response.length));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] ctap2command(CTAP2Enums.Command command, byte[] payload) {
        return concatenate(new byte[]{command.cmd}, payload);
    }

    public static byte[] ctap2command(CTAP2Enums.Command command, Map<Object, Object> payload) {
        try {
            return ctap2command(command, cborMapper.writeValueAsBytes(payload));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static <V extends Enum> ObjectNode printifyObject(Function<Byte, Optional<V>> table, ObjectNode obj) {
        return (ObjectNode) CTAP2ProtocolHelpers.hexify(translateKeys(table, obj));
    }


    public static <V extends Enum> ObjectNode translateKeys(Function<Byte, Optional<V>> table, ObjectNode obj) {
        ObjectNode fresh = JsonNodeFactory.instance.objectNode();
        obj.fieldNames().forEachRemaining(fn -> {
            fresh.set(table.apply(Byte.valueOf(fn)).map(V::name).orElse("UNKNOWN " + fn), obj.get(fn));
        });
        return fresh;
    }

    public static ObjectNode cbor2object(CTAP2Enums.Command command, byte[] cbor_response) {
        try {
            if (cbor_response.length > 1) {
                ObjectNode cborRespopnse = (ObjectNode) cborMapper.readTree(cbor_response);

                switch (command) {
                    case authenticatorGetInfo:
                        return translateKeys(CTAP2Enums.GetInfoResponseParameter::valueOf, cborRespopnse);
                    case authenticatorMakeCredential:
                        return translateKeys(CTAP2Enums.MakeCredentialResponseParameter::valueOf, cborRespopnse);
                    case authenticatorGetAssertion:
                        return translateKeys(CTAP2Enums.GetAssertionResponseParameter::valueOf, cborRespopnse);
                    case authenticatorClientPIN:
                        return translateKeys(CTAP2Enums.ClientPINResponseParameter::valueOf, cborRespopnse);
                    case authenticatorCredentialManagementPre:
                        return translateKeys(CTAP2Enums.CredentialManagementPreResponseParameter::valueOf, cborRespopnse);
                    default:
                        return cborRespopnse;
                }
            } else return JsonNodeFactory.instance.objectNode();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // Send a command and translate returned structure into string keys. Throws on all errors
    public static ObjectNode ctap2(byte[] cmd, CTAP2Transport transport) {

        CTAP2Enums.Command command = CTAP2Enums.Command.valueOf(cmd[0]).orElseThrow();

        byte[] respopnse = ctap2raw(cmd, transport);

        if (status(respopnse) != CTAP1_ERR_SUCCESS)
            throw new CTAPProtocolError("Command returned error: " + status(respopnse));

        return cbor2object(command, Arrays.copyOfRange(respopnse, 1, respopnse.length));

    }

    // Nice logger for CTAP2 commands and responses
    public static byte[] ctap2raw(byte[] cmd, CTAP2Transport transport) {
        try {
            CTAP2Enums.Command command = CTAP2Enums.Command.valueOf(cmd[0]).orElseThrow(() -> new IllegalArgumentException("Unknown command " + cmd[0]));

            if (protocolDebug != null)
                protocolDebug.println(">> " + command.name());
            if (cmd.length > 1 && protocolDebug != null) {
                // Translate integers to names
                byte[] cbor = Arrays.copyOfRange(cmd, 1, cmd.length);
                ObjectNode stringifiedCommand;
                ObjectNode parsedCommand = (ObjectNode) cborMapper.readTree(cbor);

                switch (command) {
                    case authenticatorMakeCredential:
                        stringifiedCommand = printifyObject(CTAP2Enums.MakeCredentialCommandParameter::valueOf, parsedCommand);
                        break;
                    case authenticatorGetAssertion:
                        stringifiedCommand = printifyObject(CTAP2Enums.GetAssertionCommandParameter::valueOf, parsedCommand);
                        break;
                    case authenticatorClientPIN:
                        stringifiedCommand = printifyObject(CTAP2Enums.ClientPINCommandParameter::valueOf, parsedCommand);
                        break;
                    case authenticatorCredentialManagementPre:
                        stringifiedCommand = printifyObject(CTAP2Enums.CredentialManagementPreCommandParameter::valueOf, parsedCommand);
                        break;
                    default:
                        stringifiedCommand = (ObjectNode) hexify(parsedCommand);
                }
                ObjectNode cborNode = (ObjectNode) hexify(cborMapper.readTree(cbor));
                protocolDebug.println(pretty.writeValueAsString(stringifiedCommand));
            }
            byte[] response = transport.transmitCBOR(cmd);
            CTAP2Enums.Error err = valueOf(response[0]).orElseThrow(() -> new CTAPProtocolError("Unknown status " + response[0]));
            if (protocolDebug != null)
                protocolDebug.println("<< " + err.name());
            byte[] cbor = Arrays.copyOfRange(response, 1, response.length);
            if (err == CTAP1_ERR_SUCCESS && cbor.length > 0 && protocolDebug != null) {
                ObjectNode cborRespopnse = (ObjectNode) cborMapper.readTree(cbor);
                ObjectNode stringifiedResponse;
                switch (command) {
                    case authenticatorGetInfo:
                        stringifiedResponse = printifyObject(CTAP2Enums.GetInfoResponseParameter::valueOf, cborRespopnse);
                        break;
                    case authenticatorMakeCredential:
                        stringifiedResponse = printifyObject(CTAP2Enums.MakeCredentialResponseParameter::valueOf, cborRespopnse);
                        break;
                    case authenticatorGetAssertion:
                        stringifiedResponse = printifyObject(CTAP2Enums.GetAssertionResponseParameter::valueOf, cborRespopnse);
                        break;
                    case authenticatorClientPIN:
                        stringifiedResponse = printifyObject(CTAP2Enums.ClientPINResponseParameter::valueOf, cborRespopnse);
                        break;
                    case authenticatorCredentialManagementPre:
                        stringifiedResponse = printifyObject(CTAP2Enums.CredentialManagementPreResponseParameter::valueOf, cborRespopnse);
                        break;
                    default:
                        stringifiedResponse = (ObjectNode) hexify(cborRespopnse);
                }
                protocolDebug.println(pretty.writeValueAsString(stringifiedResponse));
            }
            return response;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }


    public static List<FIDOCredential> listCredentials(ObjectNode deviceInfo, CTAP2Transport transport, byte[] pinToken) throws IOException {
        // This is FIDO_2_1_PRE feature/implementation
        List<String> versions = Arrays.asList(mapper.treeToValue(deviceInfo.get("versions"), String[].class));
        if (!deviceInfo.get("options").has("credentialMgmtPreview") && !versions.contains("FIDO_2_1_PRE")) {
            throw new CTAPProtocolError("No FIDO_2_1_PRE version and credentialMgmtPreview option!");
        }
        CredentialManagementCommand cmd = CredentialManagementCommand.getCredsMetadata().withPinToken(pinToken);
        ObjectNode response = ctap2(cmd.build(), transport);
        int inUse = response.get("existingResidentCredentialsCount").asInt();
        int maxAvail = response.get("maxPossibleRemainingResidentCredentialsCount").asInt();

        List<FIDOCredential> credentials = new ArrayList<>();

        // List RP-s
        Map<String, byte[]> rpList = new LinkedHashMap<>();
        cmd = CredentialManagementCommand.getRPs().withPinToken(pinToken);
        response = ctap2(cmd.build(), transport);
        int rp_count = response.get(CTAP2Enums.CredentialManagementPreResponseParameter.totalRPs.name()).asInt();
        while (rp_count > 0) {
            String rpId = response.get(CTAP2Enums.CredentialManagementPreResponseParameter.rp.name()).get("id").asText();
            byte[] hash = response.get(CTAP2Enums.CredentialManagementPreResponseParameter.rpIDHash.name()).binaryValue();
            rpList.put(rpId, hash);
            rp_count--;
            if (rp_count > 0)
                response = ctap2(CredentialManagementCommand.getNextRP().build(), transport);
        }

        // Loop rp, getting credentials
        for (Map.Entry<String, byte[]> rpListEntry : rpList.entrySet()) {
            cmd = CredentialManagementCommand.getCredentials(rpListEntry.getValue()).withPinToken(pinToken);
            response = ctap2(cmd.build(), transport);
            int cred_count = response.get(CTAP2Enums.CredentialManagementPreResponseParameter.totalCredentials.name()).asInt();
            while (cred_count > 0) {
                String userName = response.get(CTAP2Enums.CredentialManagementPreResponseParameter.user.name()).get("name").asText();
                byte[] userId = response.get(CTAP2Enums.CredentialManagementPreResponseParameter.user.name()).get("id").binaryValue();
                byte[] credentialID = response.get(CTAP2Enums.CredentialManagementPreResponseParameter.credentialID.name()).get("id").binaryValue();
                COSEPublicKey publicKey = COSEPublicKey.fromParsedNode(response.get(CTAP2Enums.CredentialManagementPreResponseParameter.publicKey.name()));
                Map<String, Object> options = new HashMap<>();
                if (response.has(CTAP2Enums.CredentialManagementPreResponseParameter.credProtect.name())) {
                    options.put(CTAP2Enums.CredentialManagementPreResponseParameter.credProtect.name(), response.get(CTAP2Enums.CredentialManagementPreResponseParameter.credProtect.name()).booleanValue());
                }

                credentials.add(new FIDOCredential(userName, userId, rpListEntry.getKey(), rpListEntry.getValue(), credentialID, publicKey, options));

                cred_count--;
                if (cred_count > 0)
                    response = ctap2(CredentialManagementCommand.getNextCredential().build(), transport);
            }
        }
        // list credentials
        if (inUse != credentials.size()) {
            logger.warn("Credential count mismatch, {} found, {} reported.", credentials.size(), inUse);
        }
        logger.info("Found {} credential(s), {} slots remaining", credentials.size(), maxAvail);
        return credentials;
    }
}
