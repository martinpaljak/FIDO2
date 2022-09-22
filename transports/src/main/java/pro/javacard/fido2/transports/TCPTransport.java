package pro.javacard.fido2.transports;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.fido2.common.TransportMetadata;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

// To a simulator accepting APDU-s as HEX lines and replies as HEX lines.
public class TCPTransport extends ISO7816Transport {
    private static final Logger logger = LoggerFactory.getLogger(TCPTransport.class);

    final Socket socket;
    final BufferedReader in;
    final BufferedWriter out;

    private TCPTransport(Socket socket, BufferedReader in, BufferedWriter out) {
        this.socket = socket;
        this.in = in;
        this.out = out;
    }

    public static TCPTransport getInstance(String host, int port) throws IOException {
        Socket socket = new Socket(host, port);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
        logger.info("Connected to {}:{}", host, port);
        TCPTransport transport = new TCPTransport(socket, in, out);
        TransportMetadata metadata = transport.probe();
        if (metadata != null) {
            transport.metadata = metadata;
            return transport;
        } else {
            throw new IllegalStateException("Did not detect FIDO device");
        }
    }

    @Override
    public byte[] transmit(byte[] bytes) throws IOException {
        out.write(Hex.toHexString(bytes) + "\n");
        out.flush();
        logger.debug("TCP >>> {}", Hex.toHexString(bytes));
        byte[] recv = Hex.decode(in.readLine());
        logger.debug("TCP <<< {}", Hex.toHexString(recv));
        return recv;
    }

    @Override
    public void close() throws IOException {
        in.close();
        out.close();
        socket.close();
    }

    @Override
    public String getDeviceName() {
        InetAddress address = socket.getInetAddress();
        return String.format("Simulator at %s:%d", address.getHostName(), socket.getPort());
    }
}
