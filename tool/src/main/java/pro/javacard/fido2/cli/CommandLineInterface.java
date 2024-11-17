package pro.javacard.fido2.cli;

import com.sun.jna.LastErrorException;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.win32.StdCallLibrary;
import joptsimple.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

abstract class CommandLineInterface {
    static final String VERSION = "0.1";
    protected static OptionParser parser = new OptionParser();

    // Generic options
    protected static OptionSpec<Void> OPT_VERSION = parser.acceptsAll(Arrays.asList("V", "version"), "Show program version");
    protected static OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "help"), "Show information about the program").forHelp();
    protected static OptionSpec<Void> OPT_DEBUG = parser.acceptsAll(Arrays.asList("debug"), "Show wire traces");
    protected static OptionSpec<Void> OPT_VERBOSE = parser.acceptsAll(Arrays.asList("v", "verbose"), "Show CBOR messages");

    protected static OptionSpec<Void> OPT_SHORT = parser.acceptsAll(Arrays.asList("S"), "Use short APDU mode");

    // Transport options
    protected static OptionSpec<String> OPT_USB = parser.acceptsAll(Arrays.asList("U", "usb"), "Use specific USB HID device").withOptionalArg().describedAs("name/path");
    protected static OptionSpec<String> OPT_NFC = parser.acceptsAll(Arrays.asList("N", "nfc"), "Use specific NFC reader").withOptionalArg().describedAs("reader");
    protected static OptionSpec<String> OPT_TCP = parser.acceptsAll(Arrays.asList("T", "tcp"), "Use APDU over TCP (test)").withOptionalArg().describedAs("host:port");

    // Universal options
    protected static OptionSpec<Void> OPT_U2F = parser.acceptsAll(Arrays.asList("1", "u2f"), "Force use of U2F");

    // Registration/authentication
    protected static OptionSpec<Void> OPT_WINK = parser.acceptsAll(Arrays.asList("W", "wink"), "Wink ;)");

    // PIN options
    protected static OptionSpec<String> OPT_PIN = parser.acceptsAll(Arrays.asList("p", "pin"), "Use PIN (FIDO2)").withOptionalArg().describedAs("PIN");
    protected static OptionSpec<String> OPT_CHANGE_PIN = parser.acceptsAll(Arrays.asList("change-pin"), "Set new PIN (FIDO2)").withRequiredArg().describedAs("new PIN");


    // Credential Management
    protected static OptionSpec<Void> OPT_LIST_CREDENTIALS = parser.acceptsAll(Arrays.asList("l", "list-credentials"), "List credentials (pre)");
    protected static OptionSpec<String> OPT_DELETE = parser.acceptsAll(Arrays.asList("D", "delete"), "Delete credential (pre)").withRequiredArg().describedAs("user@domain|credential");

    // CTAP2/CTAP2 commands
    protected static OptionSpec<Void> OPT_GET_INFO = parser.acceptsAll(Arrays.asList("i", "info"), "Get info (FIDO2)");
    protected static OptionSpec<String> OPT_REGISTER = parser.acceptsAll(Arrays.asList("r", "register"), "Make credential / register").withRequiredArg().describedAs("[user@]domain");
    protected static OptionSpec<String> OPT_AUTHENTICATE = parser.acceptsAll(Arrays.asList("a", "authenticate"), "Get assertion / authenticate").withRequiredArg().describedAs("[user@]domain");

    // Arguments for registration/authentication
    protected static OptionSpec<Integer> OPT_EA = parser.acceptsAll(Arrays.asList("ea"),  "Enterprise Attestation (FIDO2)").withOptionalArg().ofType(Integer.class).defaultsTo(1);
    protected static OptionSpec<Void> OPT_RK = parser.acceptsAll(Arrays.asList("rk", "discoverable"), "Discoverable (FIDO2)");
    protected static OptionSpec<String> OPT_HMAC_SECRET = parser.acceptsAll(Arrays.asList("hmac-secret"), "Use hmac-secret (FIDO2)").withOptionalArg().describedAs("hex");
    protected static OptionSpec<Integer> OPT_PROTECT = parser.acceptsAll(Arrays.asList("protect"), "Use credProtect (FIDO2)").withRequiredArg().ofType(Integer.class);
    protected static OptionSpec<String> OPT_UID = parser.accepts("uid", "User identifier").withRequiredArg().describedAs("value/file");

    protected static OptionSpec<String> OPT_PUBKEY = parser.acceptsAll(Arrays.asList("pubkey"), "Credential public key").withRequiredArg().describedAs("value/file");

    protected static OptionSpec<String> OPT_CLIENTDATAHASH = parser.acceptsAll(Arrays.asList("client-data-hash"), "Client data hash").withRequiredArg().describedAs("hex/b64url");

    protected static OptionSpec<String> OPT_CREDENTIAL = parser.acceptsAll(Arrays.asList("c", "credential"), "Credential ID").withRequiredArg().describedAs("hex/b64url/file");
    protected static OptionSpec<Void> OPT_NO_UP = parser.acceptsAll(Arrays.asList("no-up", "no-presence"), "Do not require UP (touch)");
    protected static OptionSpec<Void> OPT_UV = parser.acceptsAll(Arrays.asList("uv", "verification"), "Do UV (PIN/biometrics)");

    protected static OptionSpec<Void> OPT_P256 = parser.acceptsAll(Arrays.asList("p256"), "Use P-256 keys");
    protected static OptionSpec<Void> OPT_ED25519 = parser.acceptsAll(Arrays.asList("ed25519"), "Use Ed25519 keys");

    // X-FIDO commands
    protected static OptionSpec<String> OPT_X_AUTH_GP_KEY = parser.acceptsAll(Arrays.asList("x-auth-gp-key"), "Use GP key").withRequiredArg().describedAs("hex/file");

    protected static OptionSpec<String> OPT_X_AUTH_KEY = parser.acceptsAll(Arrays.asList("x-auth-key"), "Use key").availableUnless(OPT_X_AUTH_GP_KEY).withRequiredArg().describedAs("hex/file");

    protected static OptionSpec<String> OPT_X_AUTH_ORIGIN = parser.acceptsAll(Arrays.asList("x-auth-origin"), "Use origin").availableUnless(OPT_X_AUTH_GP_KEY).withRequiredArg().describedAs("domain");

    protected static OptionSpec<String> OPT_X_GET = parser.acceptsAll(Arrays.asList("get", "x-get", "G"), "Send {get: ...}").withRequiredArg().describedAs("msg");
    protected static OptionSpec<String> OPT_X_SET = parser.acceptsAll(Arrays.asList("set", "x-set", "S"), "Send {set: ...}").withRequiredArg().describedAs("msg");
    protected static OptionSpec<String> OPT_X_DEL = parser.acceptsAll(Arrays.asList("del", "x-del", "D"), "Send {del: ...}").withRequiredArg().describedAs("msg");

    protected static <V> Optional<V> optional(OptionSet args, OptionSpec<V> v) {
        return args.hasArgument(v) ? Optional.ofNullable(args.valueOf(v)) : Optional.empty();
    }

    protected static OptionSet parseArguments(String[] argv) throws IOException {
        OptionSet args = null;

        parser.formatHelpWith(new BuiltinHelpFormatter(100, 3));
        // Parse arguments
        try {
            args = parser.parse(argv);
        } catch (OptionException e) {
            parser.printHelpOn(System.err);
            System.err.println();
            System.err.println("More information: https://github.com/martinpaljak/FIDO2");
            System.err.println();
            if (e.getCause() != null) {
                System.err.println(e.getMessage() + ": " + e.getCause().getMessage());
            } else {
                System.err.println(e.getMessage());
            }
            exitWith(1);
            throw new IllegalStateException("XXX: never reached but makes spotbugs happy."); // XXX
        }

        if (args.nonOptionArguments().size() > 0) {
            System.err.println();
            System.err.println("Invalid non-option arguments: " + args.nonOptionArguments().stream().map(e -> e.toString()).collect(Collectors.joining(" ")));
            System.err.println("Try " + argv[0] + " --help");
            exitWith(1);
        }

        if (args.has(OPT_HELP) || args.specs().size() == 0) {
            parser.printHelpOn(System.out);
            System.err.println();
            System.err.println("More information: https://github.com/martinpaljak/FIDO2");

            if (Platform.isWindows()) {
                System.out.println();
                System.out.println("NB! This tool must be run as an Administrator on Windows!");
            }
            exitWith(0);
        }

        return args;
    }


    static void exitWith(int code) {
        if (Platform.isWindows()) {
            // If run via wrapper and uac was triggered to open a new window, then PROMPT is not present
            if (System.getenv().containsKey("FIDO_EXE_WRAPPER") && !System.getenv().containsKey("PROMPT")) {
                System.console().readLine("Press ENTER to close this window ...");
            }
        }
        System.exit(code);
    }

    static boolean requiresPIN(OptionSet options) {
        return options.has(OPT_CHANGE_PIN) || options.has(OPT_LIST_CREDENTIALS) ||  options.has(OPT_DELETE) || options.has(OPT_REGISTER) || options.has(OPT_AUTHENTICATE);
    }

    static boolean hasX(OptionSet options) {
        return options.has(OPT_X_GET) || options.has(OPT_X_SET) || options.has(OPT_X_DEL) || options.has(OPT_X_AUTH_KEY) || options.has(OPT_X_AUTH_ORIGIN);
    }


    // See https://stackoverflow.com/questions/18631597/java-on-windows-test-if-a-java-application-is-run-as-an-elevated-process-with
    interface Shell32 extends StdCallLibrary {
        boolean IsUserAnAdmin() throws LastErrorException;
    }

    static final Shell32 INSTANCE = Platform.isWindows() ? Native.load("shell32", Shell32.class) : null;

    static boolean isUserWindowsAdmin() {
        return INSTANCE != null && INSTANCE.IsUserAnAdmin();
    }
}
