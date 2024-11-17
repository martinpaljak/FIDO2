package pro.javacard.fido2.transports;

import com.sun.jna.Platform;
import org.bouncycastle.util.encoders.Hex;
import org.hid4java.HidDevice;
import org.hid4java.HidManager;
import org.hid4java.HidServices;
import org.hid4java.HidServicesSpecification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.fido2.common.CTAP2Transport;
import pro.javacard.fido2.common.CryptoUtils;
import pro.javacard.fido2.common.TransportMetadata;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

// Docs: raw messages (ctap1) https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
// HID: https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-hid-protocol-ps-20141009.html
public class USBTransport implements CTAP2Transport {
    private static final Logger logger = LoggerFactory.getLogger(USBTransport.class);
    private static final int CHUNKSIZE = 64; // XXX: query interface descriptor if possible, or always 64? According to u2f 64
    private static final SecureRandom random = new SecureRandom(); // for channel opening

    private static HidServices services;
    private final HidDevice device;
    private final CallbackHandler callbackHandler;

    private DefaultTransportMetadata metadata;
    private boolean hasWink = false;

    private byte[] channelID;

    // CTAPHID command opcodes
    public static final byte CTAP_CMD_PING = 0x01;
    public static final byte CTAP_CMD_MSG = 0x03; // U2F
    public static final byte CTAP_CMD_LOCK = 0x04;
    public static final byte CTAP_CMD_INIT = 0x06;
    public static final byte CTAP_CMD_WINK = 0x08;
    public static final byte CTAP_CMD_CBOR = 0x10;
    public static final byte CTAP_CMD_CANCEL = 0x11;
    public static final byte CTAP_KEEPALIVE = 0x3B;

    public static final byte CTAP_ERROR = 0x3F;

    public static final byte CAPABILITY_WINK = 0x01; // If set to 1, authenticator implements CTAPHID_WINK function
    public static final byte CAPABILITY_CBOR = 0x04; //	If set to 1, authenticator implements CTAPHID_CBOR function
    public static final byte CAPABILITY_NMSG = 0x08; // If set to 1, authenticator DOES NOT implement CTAPHID_MSG function

    static final byte STATUS_PROCESSING = 1; //	The authenticator is still processing the current request.
    static final byte STATUS_UPNEEDED = 2; // The authenticator is waiting for user presence.
    static final byte[] BROADCAST = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};


    private static synchronized HidServices getServices() {
        if (services == null) {
            HidServicesSpecification hidServicesSpecification = new HidServicesSpecification();
            hidServicesSpecification.setAutoStart(false);
            services = HidManager.getHidServices(hidServicesSpecification);
            services.start();
        }
        return services;
    }

    // Probe if valid
    boolean isFIDO(HidDevice device) {
        return false;
    }

    public static List<HidDevice> list() {

        List<HidDevice> devices;

        if (Platform.isLinux()) {
            // Can't filter by usage page, due to hidapi and hid4java missing feature.
            devices = getServices().getAttachedHidDevices().stream().filter(device -> device.getProduct() != null).collect(Collectors.toList());
        } else {
            // We can filter devices!
            devices = getServices().getAttachedHidDevices().stream().filter(device -> (device.getUsagePage() & 0xFFFF) == 0xf1d0 && device.getUsage() == 0x01).collect(Collectors.toList());
        }
        return devices;
    }

    public static USBTransport getInstance(String path, CallbackHandler cb) {
        // Filter authenticators
        List<HidDevice> authenticators = getServices().getAttachedHidDevices().stream().filter(device -> device.getPath().equals(path)).collect(Collectors.toList());

        // Require exactly one matching device.
        if (authenticators.size() != 1) {
            logger.error("Invalid path: " + path);
            if (authenticators.size() == 0)
                throw new IllegalArgumentException("Path not found: " + path);
            else
                throw new IllegalArgumentException("Invalid path: " + path);
        }

        return new USBTransport(authenticators.get(0), cb);
    }

    public static USBTransport getInstance(HidDevice dev, CallbackHandler cb) {
        return new USBTransport(dev, cb);
    }

    @SuppressWarnings("deprecation")
    private USBTransport(HidDevice dev, CallbackHandler cb) {
        device = dev;
        callbackHandler = cb;
        if (!device.isOpen()) device.open(); //FIXME: isOpen is deprecated
        try {
            channelID = openChannel(device);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public byte[] transmitCBOR(byte[] cmd) throws IOException {
        byte[] response = transmit(device, channelID, CTAP_CMD_CBOR, cmd);
        logger.debug("Received: {}", Hex.toHexString(response));
        return response;
    }

    @Override
    public void close() throws IOException {
        // Send cancel frame, ignoring errors
        try {
            List<byte[]> packets = toPackets(channelID, CTAP_CMD_CANCEL, new byte[0]);
            for (byte[] packet : packets) {
                send(device, packet);
            }
        } catch (IOException e) {
            // Do nothing
        }
        device.close();
    }

    // Takes a padded package.
    void send(HidDevice device, byte[] packet) throws IOException {
        int written = device.write(packet, packet.length, (byte) 0x00);
        if (written != packet.length + 1) {
            throw new IOException("Could not send, wrote " + written + " instead of " + packet.length);
        }
        logger.debug("HID send: {}", Hex.toHexString(packet));
    }

    byte[] read(HidDevice device, int chunksize) throws IOException {
        byte[] payload = new byte[chunksize];
        int readlen = device.read(payload);
        if (readlen != chunksize) throw new IOException("Invalid read length: " + payload.length);
        logger.debug("HID recv: {}", Hex.toHexString(payload));
        return payload;
    }

    byte[] openChannel(HidDevice device) throws IOException {
        byte[] nonce = new byte[8];
        random.nextBytes(nonce);

        byte[] response = transmit(device, BROADCAST, CTAP_CMD_INIT, nonce);

        byte[] response_challenge = Arrays.copyOf(response, 8);
        if (!Arrays.equals(nonce, response_challenge)) {
            throw new IOException("Nonce does not match!");
        }
        byte u2fhidversion = response[12];
        String version = String.format("%d.%d.%d", response[13], response[14], response[15]);
        byte capabilities = response[16];

        if (u2fhidversion != 2) {
            logger.warn("U2FHID protocol version is not 2: {}", u2fhidversion);
        }
        hasWink = (capabilities & CAPABILITY_WINK) == CAPABILITY_WINK;
        metadata = new DefaultTransportMetadata(version, device.getProduct(), capabilities);
        logger.debug("INIT response: {}", metadata);

        // returns 4 byte channel ID.
        return Arrays.copyOfRange(response, 8, 12);
    }


    List<byte[]> toPackets(byte[] channel, byte cmd, byte[] payload) {
        int n = CHUNKSIZE - 5;
        List<byte[]> result = new ArrayList<>();

        // Add byte count to payload
        payload = add_bcnt(payload);

        // Make payload to be equally chunked.
        if (payload.length % n != 0) payload = Arrays.copyOf(payload, (payload.length / n + 1) * n);

        // split into chunks
        List<byte[]> chunks = CryptoUtils.splitArray(payload, n);

        // First command has 0x80, rest have counter
        int i = 0;
        for (byte[] chunk : chunks) {
            result.add(CryptoUtils.concatenate(channel, new byte[]{i == 0 ? (byte) (0x80 | cmd) : (byte) ((i - 1) & 0x7f)}, chunk));
            i++;
        }
        return result;
    }

    byte[] transmit(HidDevice device, byte[] channel, byte cmd, byte[] payload) throws IOException {
        List<byte[]> packets = toPackets(channel, cmd, payload);
        logger.debug("Sending {} packet{}", packets.size(), packets.size() == 1 ? "" : "s");

        for (byte[] packet : packets) {
            send(device, packet);
        }
        int len = 0;
        byte[] result = new byte[0];
        // Keepalive is every 100ms, thus 1000 = 100s. Basically we let the authenticator time out.
        int j = 0;
        boolean upNotified = false;
        for (int i = 0; i < 1000; i++) {
            byte[] packet = read(device, 64);
            ByteBuffer byteBuffer = ByteBuffer.wrap(packet);
            byte[] recv_channel = new byte[4];
            byteBuffer.get(recv_channel);
            if (!Arrays.equals(recv_channel, channel)) {
                throw new IOException("Channel mismatch during transaction!");
            }
            byte cmdOrIndex = (byte) (byteBuffer.get() & 0x7f);
            if ((cmdOrIndex & CTAP_ERROR) == CTAP_ERROR) {
                throw new IOException("Error: " + Error.valueOf(packet[7]));
            }
            if ((cmdOrIndex & CTAP_KEEPALIVE) == CTAP_KEEPALIVE) {
                if (packet[7] == STATUS_UPNEEDED) {
                    if (upNotified == false) {
                        try {
                            TextOutputCallback toc = new TextOutputCallback(TextOutputCallback.INFORMATION, String.format("Touch \"%s\"", device.getProduct()));
                            callbackHandler.handle(new Callback[]{toc});
                        } catch (UnsupportedCallbackException e) {
                            throw new IOException("Invalid configuration: " + e.getMessage(), e);
                        }
                        upNotified = true;
                    }
                } else if (packet[7] == STATUS_PROCESSING) {
                    logger.trace("Still processing");
                } else {
                    logger.warn("Unknown status of keepalive: {}", packet[7]);
                }
                continue;
            }
            if (j == 0) {
                if (cmdOrIndex != cmd)
                    throw new IOException("Command mismatch during transaction: " + cmdOrIndex + " vs " + cmd);
                len = byteBuffer.getShort();
            } else {
                if (cmdOrIndex != (j - 1)) {
                    throw new IOException("Chunk index mismatch: " + cmdOrIndex + " vs " + (j - 1));
                }
            }
            byte[] chunk = new byte[byteBuffer.remaining()];
            byteBuffer.get(chunk);

            // XXX: use bytebuffer or similar.
            result = CryptoUtils.concatenate(result, chunk);
            if (result.length >= len) break;
            j++;
        }
        return Arrays.copyOf(result, len);
    }


    static byte[] add_bcnt(byte[] data) {
        return CryptoUtils.concatenate(new byte[]{(byte) (data.length >>> 8), (byte) (data.length & 0xFF)}, data);
    }


    public enum Error {
        ERR_INVALID_CMD((byte) 0x01),
        ERR_INVALID_PAR((byte) 0x02),
        ERR_INVALID_LEN((byte) 0x03),
        ERR_INVALID_SEQ((byte) 0x04),
        ERR_MSG_TIMEOUT((byte) 0x05),
        ERR_CHANNEL_BUSY((byte) 0x06),
        ERR_LOCK_REQUIRED((byte) 0x0A),
        ERR_INVALID_CHANNEL((byte) 0x0B),
        ERR_OTHER((byte) 0x7F);

        public final byte v;

        Error(byte v) {
            this.v = v;
        }

        public static Optional<USBTransport.Error> valueOf(byte v) {
            return Arrays.stream(values()).filter(e -> e.v == v).findFirst();
        }
    }

    @Override
    public void wink() throws IOException, UnsupportedOperationException {
        if (!hasWink)
            throw new UnsupportedOperationException("Device does not report wink support");
        transmit(device, channelID, CTAP_CMD_WINK, new byte[0]);
    }

    @Override
    public TransportMetadata getMetadata() {
        return metadata;
    }

    @Override
    public byte[] transmitCTAP1(byte[] cmd) throws IOException {
        logger.debug("CTAP1 send: {}", Hex.toHexString(cmd));
        byte[] response = transmit(device, channelID, CTAP_CMD_MSG, cmd);
        logger.debug("CTAP1 recv: {}", Hex.toHexString(response));
        return response;
    }
}
