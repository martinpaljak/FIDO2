package pro.javacard.fido2.cli;

import apdu4j.core.ResponseAPDU;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.jna.Platform;
import joptsimple.OptionSet;
import org.bouncycastle.util.encoders.Hex;
import org.hid4java.HidDevice;
import pro.javacard.fido2.common.*;
import pro.javacard.fido2.transports.NFCTransport;
import pro.javacard.fido2.transports.TCPTransport;
import pro.javacard.fido2.transports.USBTransport;

import javax.security.auth.callback.*;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.*;

import static pro.javacard.fido2.common.PINProtocols.*;

public final class FIDOTool extends CommandLineInterface {
    static final long TIMEOUT = 15;

    static CallbackHandler handler; // We initialize this after logging options

    static void setupLogging(OptionSet args) {
        // Set up slf4j simple in a way that pleases us
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
        System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");

        if (args.has(OPT_VERBOSE)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info");
        }
        if (args.has(OPT_DEBUG)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
            System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
            System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss:SSS");
        }

        if (args.has(OPT_DEBUG) && System.getenv().containsKey("CTAP2_TRACE")) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
        }
    }

    static OptionSet options = null;

    static boolean useU2F(CTAP2Transport transport, OptionSet options) {
        return options.has(OPT_U2F) || !transport.getMetadata().getTransportVersions().contains(CTAPVersion.FIDO_2_0);
    }

    static Optional<String> logAndUseEnvironment(CallbackHandler handler, String env) {
        return Optional.ofNullable(System.getenv(env)).map(s -> {
            try {
                TextOutputCallback toc = new TextOutputCallback(TextOutputCallback.INFORMATION, String.format("Using $%s", env));
                handler.handle(new TextOutputCallback[]{toc});
                return s;
            } catch (UnsupportedCallbackException e) {
                throw new IllegalStateException("Invalid codebase");
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    static byte[] fileOrHex(String pathOrHex) throws IOException {
        Path path = Paths.get(pathOrHex);
        if (Files.exists(path)) {
            String data = Files.readAllLines(path).get(0).trim();
            return Hex.decode(data);
        } else {
            return Hex.decode(pathOrHex);
        }
    }


    public static void main(String[] args) {
        try {
            options = parseArguments(args);
            setupLogging(options);

            handler = new CLICallbacks(); // contains logger


            if (options.has(OPT_VERBOSE) || options.has(OPT_VERSION)) {
                System.out.println("# fido utility v" + VERSION);
                if (options.has(OPT_VERBOSE)) {
                    System.out.printf("# Running on %s %s %s", System.getProperty("os.name"), System.getProperty("os.version"), System.getProperty("os.arch"));
                    System.out.printf(", Java %s by %s%n", System.getProperty("java.version"), System.getProperty("java.vendor"));

                    List<String> env = System.getenv().entrySet().stream().filter(e -> e.getKey().startsWith("CTAP2_") || e.getKey().startsWith("FIDO_")).map(e -> String.format("$%s=%s", e.getKey(), e.getValue())).collect(Collectors.toList());
                    if (env.size() > 0)
                        System.out.println("# " + String.join(" ", env));
                    // Wrap parameters with spaces
                    List<String> argv = Arrays.stream(args).map(e -> e.contains(" ") ? String.format("'%s'", e) : e).collect(Collectors.toList());
                    System.out.println("# fido " + String.join(" ", argv));
                }
            }

            // Debug mode always shows messages as well.
            if (options.has(OPT_VERBOSE) || options.has(OPT_DEBUG)) {
                CTAP2ProtocolHelpers.setProtocolDebug(System.out);
            }

            // FIDO devices can only be accessed if in Admin mode. Also applies to NFC devices.
            if (Platform.isWindows() && !isUserWindowsAdmin()) {
                System.err.println("This tool must be run as an Administrator!");
                exitWith(1);
            }

            KeyPair ephemeral = P256.ephemeral();
            ECPublicKey deviceKey = null;
            byte[] sharedSecret = null;
            byte[] pinToken = null;
            ObjectNode deviceInfo = null;

            CTAP2Transport transport;

            // Default is USB, unless NFC given
            // USB requires parameter on Linux
            // USB without parameter lists devices
            // NFC requires parameter if more than one reader present
            // If more than one reader, NFC lists readers

            if (options.has(OPT_NFC) && options.has(OPT_USB)) {
                throw new IllegalArgumentException("Specify only HID device or NFC reader, not both");
            }

            Optional<String> readerName = optional(options, OPT_NFC).or(() -> logAndUseEnvironment(handler, "FIDO_NFC_DEVICE"));
            Optional<String> hidName = optional(options, OPT_USB).or(() -> logAndUseEnvironment(handler, "FIDO_USB_DEVICE"));

            if (options.has(OPT_NFC)) {
                List<String> readers = NFCTransport.list();
                final String chosenOne;
                // -N only - list readers
                if (options.has(OPT_NFC) && readerName.isEmpty() && readers.size() > 1) {
                    System.out.println("PC/SC readers:");
                    for (String reader : readers) {
                        System.out.printf("- %s%n", reader);
                    }
                    return;
                } else if (readers.size() == 1 && readerName.isEmpty() || (readerName.isPresent() && readerName.get().equals(readers.get(0)))) {
                    // Only one reader present - use it
                    chosenOne = readers.get(0);
                } else if (readers.size() > 0 && readerName.isPresent()) {
                    String q = readerName.get().toLowerCase(Locale.ROOT);
                    // Many readers present - need to specify one FIXME: exact match wins over partial!
                    List<String> filtered = readers.stream().filter(r -> q.length() > 2 && r.toLowerCase().contains(q)).collect(Collectors.toList());
                    if (filtered.size() == 0)
                        throw new IllegalArgumentException("Reader not found: " + readerName.get() + " " + readers);
                    else if (filtered.size() > 1) {
                        throw new IllegalArgumentException("Name not unique: " + readerName.get());
                    }
                    chosenOne = filtered.get(0);
                } else {
                    throw new IllegalArgumentException("No PC/SC readers available!");
                }
                transport = NFCTransport.getInstance(chosenOne);
            } else if (options.has(OPT_TCP)) {
                String[] elements = options.valueOf(OPT_TCP).split(":");
                if (elements.length != 2)
                    throw new IllegalArgumentException("Specify host:port");
                transport = TCPTransport.getInstance(elements[0], Integer.parseInt(elements[1]));
            } else {
                List<HidDevice> devices = USBTransport.list();
                final HidDevice chosenOne;
                // -H without parameter - list devices
                if (options.has(OPT_USB) && !options.hasArgument(OPT_USB)) {
                    // List HID devices
                    System.out.println("USB HID devices:");
                    for (HidDevice device : devices) {
                        if (Platform.isLinux()) {
                            System.out.printf("- %s (by %s): %s%n", device.getProduct(), device.getManufacturer(), device.getPath());
                        } else {
                            // List is filtered for valid devices, we can probe for more information
                            USBTransport probe = USBTransport.getInstance(device, handler);
                            String transports = probe.getMetadata().getTransportVersions().stream().map(Enum::toString).collect(Collectors.joining(", "));
                            System.out.printf("- %s (v%s by %s, supporting %s)%n", device.getProduct(), probe.getMetadata().getDeviceVersion(), device.getManufacturer(), transports);
                        }
                    }
                    chosenOne = null; // compiler sugar
                    exitWith(0);
                } else if (!Platform.isLinux() && devices.size() == 1 && hidName.isEmpty()) {
                    // DWIM: Not Linux and just one device in device list - use it
                    chosenOne = devices.get(0);
                } else if (hidName.isPresent()) {
                    String parameter = hidName.get();
                    String q = parameter.toLowerCase(Locale.ROOT);
                    List<HidDevice> filtered = devices.stream().filter(device -> {
                        if (device.getPath().equalsIgnoreCase(q)) {
                            return true;
                        } else if (device.getProduct() != null && device.getProduct().equalsIgnoreCase(q)) {
                            return true;
                        } else if (String.format("%04x:%04x", device.getVendorId(), device.getProductId()).equalsIgnoreCase(q)) {
                            return true;
                        } else if (String.format("0x%04x:0x%04x", device.getVendorId(), device.getProductId()).equalsIgnoreCase(q)) {
                            return true;
                        } else
                            return false;
                    }).collect(Collectors.toList());
                    // Look for partial match in name
                    if (filtered.size() == 0) {
                        filtered = devices.stream().filter(device -> {
                            if (device.getProduct() != null && device.getProduct().toLowerCase(Locale.ROOT).contains(q.toLowerCase(Locale.ROOT))) {
                                return true;
                            } else
                                return false;
                        }).collect(Collectors.toList());
                    }
                    if (filtered.size() == 0) {
                        throw new IllegalArgumentException("Device not found: " + parameter);
                    } else if (filtered.size() == 1) {
                        chosenOne = filtered.get(0);
                    } else
                        throw new IllegalArgumentException("Device identifier not unique: " + parameter);
                } else {
                    if (Platform.isLinux())
                        throw new IllegalArgumentException("Need a USB device path! Use " + OPT_USB);
                    else
                        throw new IllegalArgumentException("Need a USB device name! Use " + OPT_USB);
                }
                if (options.has(OPT_VERBOSE) && chosenOne != null) {
                    System.out.printf("# Using device: %s%n", chosenOne.getProduct());
                }
                transport = USBTransport.getInstance(chosenOne, handler);
            }

            // Everything below talks to an authenticator
            try {
                if (options.has(OPT_WINK)) {
                    transport.wink();
                }

                TransportMetadata metadata = transport.getMetadata();

                //  Both because we want to show remainingDiscoverableCredentials, re-using deviceInfo
                if (options.has(OPT_GET_INFO) || requiresPIN(options)) {
                    if (options.has(OPT_GET_INFO) && metadata.getTransportVersions().contains(CTAPVersion.U2F_V2)) {
                        //byte[] GET_VERSION = Hex.decode("00030000000000");
                        //byte[] response = transport.transmitCTAP1(GET_VERSION);
                        //ResponseAPDU resp = new ResponseAPDU(response);
                        //System.out.println("GET_VERSION: " + new String(resp.getData(), StandardCharsets.UTF_8));
                        String versions = metadata.getTransportVersions().stream().map(Enum::name).collect(Collectors.joining(", "));
                        System.out.printf("%s (v%s, %s)%n", metadata.getDeviceName(), metadata.getDeviceVersion(), versions);
                    }

                }
                // Always fetch device info
                if (metadata.getTransportVersions().contains(CTAPVersion.FIDO_2_0)) {
                    byte[] cmd = ctap2command(CTAP2Enums.Command.authenticatorGetInfo, new byte[0]);
                    deviceInfo = ctap2(cmd, transport);
                    // But only show it when explicitly asked
                    if (options.has(OPT_GET_INFO)) {
                        System.out.println(pretty(hexify(deviceInfo)));
                    }
                }

                // get PIN token
                if (!useU2F(transport, options) && (requiresPIN(options) || options.has(OPT_PIN) || (deviceInfo != null && deviceInfo.get("options").get("clientPin").asBoolean(false)))) {
                    // Get key agreement key
                    ObjectNode response = ctap2(ClientPINCommand.getKeyAgreementV1().build(), transport);

                    deviceKey = P256.node2pubkey(response.get("keyAgreement"));
                    sharedSecret = shared_secret(deviceKey, ephemeral);

                    // get PIN token
                    ObjectNode token = ctap2(CTAP2Commands.make_getPinToken(getPIN(options), deviceKey, ephemeral), transport);
                    pinToken = PINProtocols.aes256_decrypt(sharedSecret, token.get("pinToken").binaryValue());
                }

                if (options.has(OPT_CHANGE_PIN)) {
                    ctap2(CTAP2Commands.make_changePIN(options.valueOf(OPT_PIN), options.valueOf(OPT_CHANGE_PIN), deviceKey, ephemeral), transport);
                } else if (options.has(OPT_LIST_CREDENTIALS)) {
                    List<FIDOCredential> credentials = CTAP2ProtocolHelpers.listCredentials(deviceInfo, transport, pinToken);
                    OptionalInt maxnamelen = credentials.stream().mapToInt(e -> (e.getUsername() + "@" + e.getRpId()).length()).max();
                    if (maxnamelen.isPresent()) {
                        String format1 = String.format("%%-%ds%%s%%n", maxnamelen.getAsInt() + 3);
                        for (FIDOCredential credential : credentials) {
                            System.out.printf(format1, credential.toString(), Hex.toHexString(credential.getCredentialID()));
                            if (options.has(OPT_VERBOSE)) {
                                System.out.println(padLeft(maxnamelen.getAsInt() + 3, credential.getPublicKey().toString()));
                            }
                        }
                    }
                } else if (options.has(OPT_DELETE)) {
                    for (String param : options.valuesOf(OPT_DELETE)) {
                        final byte[] credential;
                        if (param.contains("@")) {
                            String[] elements = param.split("@");
                            if (elements.length != 2)
                                throw new IllegalArgumentException("Specify user@   domain");
                            List<FIDOCredential> credentials = CTAP2ProtocolHelpers.listCredentials(deviceInfo, transport, pinToken);
                            credentials = credentials.stream().filter(c -> Objects.equals(c.getRpId(), elements[1]) && c.getUsername().equals(elements[0])).collect(Collectors.toList());
                            if (credentials.size() == 0) {
                                System.err.println("Credential not found: " + param);
                                exitWith(1);
                                throw new IllegalStateException("Not reached, but IDE sugar");
                            } else if (credentials.size() > 1) {
                                System.err.println("More than one credential found:");
                                credentials.forEach(e -> System.err.printf("%s@%s (%s)%n", e.getUsername(), e.getRpId(), Hex.toHexString(e.getCredentialID())));
                                exitWith(1);
                                throw new IllegalStateException("Not reached, but IDE sugar");
                            } else {
                                credential = credentials.get(0).getCredentialID();
                            }
                        } else {
                            credential = Hex.decode(param);
                        }
                        CredentialManagementCommand cmd = CredentialManagementCommand.deleteCredential(credential).withPinToken(pinToken);
                        CTAP2ProtocolHelpers.ctap2(cmd.build(), transport);
                        System.out.printf("Credential %s deleted%n", Hex.toHexString(credential));
                    }
                } else if (options.has(OPT_REGISTER)) {
                    MakeCredentialCommand makeCredentialCommand = new MakeCredentialCommand();

                    byte[] clientDataHash = optional(options, OPT_CLIENTDATAHASH).map(Hex::decode).orElse(CryptoUtils.random(32));
                    makeCredentialCommand.withClientDataHash(clientDataHash);


                    String[] components = options.valueOf(OPT_REGISTER).split("@");
                    if (components.length != 2)
                        throw new IllegalArgumentException("Invalid format for " + options.valueOf(OPT_REGISTER));
                    makeCredentialCommand.withUserName(components[0]);
                    makeCredentialCommand.withDomainName(components[1]);

                    if (!useU2F(transport, options)) {
                        byte[] uid = optional(options, OPT_UID).map(Hex::decode).orElse(PINProtocols.sha256(components[0].getBytes(StandardCharsets.UTF_8)));
                        makeCredentialCommand.withUserID(uid);
                    }
                    if (!useU2F(transport, options)) {
                        if (options.has(OPT_RK))
                            makeCredentialCommand.withOption("rk");
                        if (options.has(OPT_NO_UP))
                            makeCredentialCommand.withOption("up", false);

                        if (options.has(OPT_HMAC_SECRET))
                            makeCredentialCommand.withExtension(new CTAP2Extension.HMACSecret());

                        if (options.has(OPT_PROTECT))
                            makeCredentialCommand.withExtension(new CTAP2Extension.CredProtect(options.valueOf(OPT_PROTECT).byteValue()));

                        if (options.has(OPT_PIN)) {
                            makeCredentialCommand.withV1PinAuth(left16(hmac_sha256(pinToken, clientDataHash)));
                        }

                        if (options.has(OPT_ED25519))
                            makeCredentialCommand.withAlgorithm(COSEPublicKey.Ed25519);
                        else
                            makeCredentialCommand.withAlgorithm(COSEPublicKey.P256);
                    }

                    final ObjectNode resp;

                    if (useU2F(transport, options)) {
                        // Send to device a mapped version
                        byte[] command = U2FRegister.toRegisterCommand(makeCredentialCommand);
                        byte[] u2f = U2FProtocolHelpers.presenceOrTimeout(transport, command, TIMEOUT, new CLICallbacks());
                        u2f = U2FProtocolHelpers.checkSuccess(u2f);
                        byte[] cbor = U2FRegister.toCBOR(makeCredentialCommand, u2f);
                        resp = CTAP2ProtocolHelpers.cbor2object(CTAP2Enums.Command.authenticatorMakeCredential, cbor);
                    } else {
                        // Construct command
                        byte[] cmd = makeCredentialCommand.build();

                        // Send to device
                        resp = CTAP2ProtocolHelpers.ctap2(cmd, transport);
                    }

                    System.out.println("Registration: \n" + pretty(hexify(resp)));

                    AuthenticatorData authenticatorData = AuthenticatorData.fromBytes(resp.get("authData").binaryValue());


                    if (options.has(OPT_CREDENTIAL)) {
                        Path credpath = Paths.get(options.valueOf(OPT_CREDENTIAL));
                        Files.writeString(credpath, Hex.toHexString(authenticatorData.getAttestation().getCredentialID()));
                    }
                    if (options.has(OPT_PUBKEY)) {
                        Path keypath = Paths.get(options.valueOf(OPT_PUBKEY));
                        Files.writeString(keypath, Hex.toHexString(COSEPublicKey.pubkey2bytes(authenticatorData.getAttestation().getPublicKey())));
                    }

                    System.out.println("Authenticator data: \n" + pretty(authenticatorData.toJSON()));
                    // TODO: verify attestation
                    AttestationVerifier.dumpAttestation(makeCredentialCommand, resp);
                    // If not U2F
                    if (!isZero(authenticatorData.getAttestation().getAAGUID())) {
                        System.out.println("Used device:   " + authenticatorData.getAttestation().getAAGUID());
                    }
                    System.out.println("Credential ID: " + Hex.toHexString(authenticatorData.getAttestation().getCredentialID()));
                    System.out.println("Public key:    " + Hex.toHexString(COSEPublicKey.pubkey2bytes(authenticatorData.getAttestation().getPublicKey())));

                } else if (options.has(OPT_AUTHENTICATE)) {
                    GetAssertionCommand getAssertionCommand = new GetAssertionCommand();

                    byte[] clientDataHash = optional(options, OPT_CLIENTDATAHASH).map(Hex::decode).orElse(CryptoUtils.random(32));
                    getAssertionCommand.withClientDataHash(clientDataHash);

                    if (options.has(OPT_HMAC_SECRET)) {
                        if (!options.hasArgument(OPT_HMAC_SECRET)) {
                            throw new IllegalArgumentException("Need hmac secret argument!");
                        }

                        // FIXME: should make it so as to never be null
                        if (deviceKey == null || sharedSecret == null) {
                            ObjectNode cardKeyResponse = ctap2(ClientPINCommand.getKeyAgreementV1().build(), transport);
                            deviceKey = P256.node2pubkey(cardKeyResponse.get("keyAgreement"));
                            sharedSecret = shared_secret(deviceKey, ephemeral);
                        }

                        // AES256-CBC(sharedSecret, IV=0, newPin)
                        byte[] saltEnc = aes256_encrypt(sharedSecret, Hex.decode(options.valueOf(OPT_HMAC_SECRET)));

                        // LEFT(HMAC-SHA-256(sharedSecret, saltEnc), 16).
                        byte[] saltAuth = left16(hmac_sha256(sharedSecret, saltEnc));

                        CTAP2Extension.HMACSecret hmacSecret = new CTAP2Extension.HMACSecret((ECPublicKey) ephemeral.getPublic(), saltEnc, saltAuth);
                        getAssertionCommand.withExtension(hmacSecret);
                    }

                    if (options.hasArgument(OPT_AUTHENTICATE)) {
                        String q = options.valueOf(OPT_AUTHENTICATE);
                        if (q.contains("@")) {
                            // Use domain from name@domain
                            String[] elements = q.split("@");
                            if (elements.length != 2) {
                                throw new IllegalArgumentException("Invalid formation: " + q);
                            }
                            getAssertionCommand.withDomain(elements[1]);
                        } else if (q.contains(".")) {
                            // Plain domain
                            getAssertionCommand.withDomain(q);
                        } else {
                            throw new IllegalArgumentException("Specify credential to use!");
                        }
                    }

                    if (options.has(OPT_CREDENTIAL)) {
                        for (String cred : options.valuesOf(OPT_CREDENTIAL)) {
                            getAssertionCommand.withAllowed(fileOrHex(cred));
                        }
                    }

                    // Require UP unless explicitly asked for the opposite
                    getAssertionCommand.withOption("up", !options.has(OPT_NO_UP));

                    if (options.has(OPT_UV)) {
                        getAssertionCommand.withOption("uv", true);
                    }

                    if (options.has(OPT_PIN))
                        getAssertionCommand.withV1PinAuth(left16(hmac_sha256(pinToken, clientDataHash)));


                    final ObjectNode resp;
                    // If explicitly asking for U2F or if not FIDO2
                    if (useU2F(transport, options)) {
                        // Send to device a mapped version
                        byte[] command = U2FAuthenticate.toAuthenticateCommand(getAssertionCommand);
                        byte[] u2f = U2FProtocolHelpers.presenceOrTimeout(transport, command, TIMEOUT, new CLICallbacks());
                        ResponseAPDU response = new ResponseAPDU(u2f);
                        if (response.getSW() == 0x6A80) {
                            System.err.println("Invalid credentialID!");
                            exitWith(3);
                        } else if (response.getSW() != 0x9000) {
                            throw new IOException(String.format("U2F error: 0x%04X", response.getSW()));
                        }
                        byte[] cbor = U2FAuthenticate.toCBOR(getAssertionCommand, u2f);
                        resp = CTAP2ProtocolHelpers.cbor2object(CTAP2Enums.Command.authenticatorGetAssertion, cbor);
                    } else {
                        // Construct command
                        byte[] cmd = getAssertionCommand.build();
                        // Send to device
                        resp = ctap2(cmd, transport);
                    }

                    byte[] authData = resp.get("authData").binaryValue();
                    byte[] signature = resp.get(CTAP2Enums.GetAssertionResponseParameter.signature.name()).binaryValue();

                    AuthenticatorData authenticatorData = AuthenticatorData.fromBytes(authData);
                    System.out.println("Authenticator data: \n" + pretty(authenticatorData.toJSON()));

                    // Verify assertion, if pubkey given
                    if (options.has(OPT_PUBKEY)) {
                        final PublicKey publicKey = CryptoUtils.bytes2pubkey(fileOrHex(options.valueOf(OPT_PUBKEY)));
                        if (AssertionVerifier.verify(authenticatorData, clientDataHash, signature, publicKey)) {
                            System.out.println("Verified OK.");
                        } else {
                            throw new GeneralSecurityException("Assertion not verified!");
                        }
                    }
                }

                // Management commands are only available via NFC/PCSC
                if (transport instanceof NFCTransport) {
                    if (options.has(OPT_X_INFO)) {
                        Map<Object, Object> infoCommand = new LinkedHashMap<>();
                        infoCommand.put("cmd", "info");
                        byte[] command = CTAP2ProtocolHelpers.ctap2command(CTAP2Enums.Command.vendorCBOR, infoCommand);
                        byte[] response = CTAP2ProtocolHelpers.ctap2raw(command, transport);
                    } else if (options.has(OPT_X_LIST)) {
                        Map<Object, Object> readList = new LinkedHashMap<>();
                        readList.put("cmd", "read");
                        readList.put("what", options.valueOf(OPT_X_LIST));
                        byte[] command = ctap2command(CTAP2Enums.Command.vendorCBOR, readList);
                        byte[] response = ctap2raw(command, transport);
                        while (CTAP2ProtocolHelpers.status(response) == CTAP2Enums.Error.CTAP1_ERR_SUCCESS) {
                            readList.put("cmd", "next");
                            readList.put("what", options.valueOf(OPT_X_LIST));
                            command = CTAP2ProtocolHelpers.ctap2command(CTAP2Enums.Command.vendorCBOR, readList);
                            response = CTAP2ProtocolHelpers.ctap2raw(command, transport);
                        }
                    } else if (options.has(OPT_X_READ)) {
                        Map<Object, Object> readList = new LinkedHashMap<>();
                        readList.put("cmd", "read");
                        readList.put("what", options.valueOf(OPT_X_READ));
                        byte[] command = CTAP2ProtocolHelpers.ctap2command(CTAP2Enums.Command.vendorCBOR, readList);
                        byte[] response = CTAP2ProtocolHelpers.ctap2raw(command, transport);
                    }
                }
            } catch (IOException e) {
                // FIXME
                e.printStackTrace();
            } finally {
                if (transport != null)
                    transport.close();
            }
        } catch (Throwable e) {
            System.err.printf("%s: %s%n", e.getClass().getSimpleName(), e.getMessage());
            if (System.getenv().containsKey("CTAP2_TRACE")) {
                e.printStackTrace(System.err);
            }
            exitWith(2);
        }
        exitWith(0);
    }

    static String getPIN(OptionSet options) {
        if (options.has(OPT_PIN) && options.hasArgument(OPT_PIN))
            return options.valueOf(OPT_PIN);

        PasswordCallback[] pc = {new PasswordCallback("Authenticator PIN", true)};
        try {
            new CLICallbacks().handle(pc);
        } catch (IOException | UnsupportedCallbackException e) {
            throw new RuntimeException("Can not log into authenticator: " + e.getMessage(), e);
        }
        return String.valueOf(pc[0].getPassword());
    }

    static String padLeft(int n, String s) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < n; ++i) {
            buf.append(" ");
        }
        buf.append(s);
        return buf.toString();
    }

    static boolean isZero(UUID uuid) {
        return uuid.getMostSignificantBits() == 0 && uuid.getLeastSignificantBits() == 0;
    }
}
