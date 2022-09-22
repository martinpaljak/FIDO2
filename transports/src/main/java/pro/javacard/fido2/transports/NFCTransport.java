package pro.javacard.fido2.transports;

import apdu4j.core.BIBO;
import apdu4j.pcsc.CardBIBO;
import apdu4j.pcsc.TerminalManager;
import apdu4j.pcsc.terminals.LoggingCardTerminal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.fido2.common.TransportMetadata;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class NFCTransport extends ISO7816Transport {
    private static final Logger logger = LoggerFactory.getLogger(NFCTransport.class);
    private final BIBO bibo;

    private String terminalName;

    public static NFCTransport getInstance(String readerName) {
        TerminalManager manager = TerminalManager.getDefault();
        return getInstance(manager.getTerminal(readerName));
    }

    public static NFCTransport getInstance(CardTerminal terminal) {
        try {
            terminal = LoggingCardTerminal.getInstance(terminal);
            BIBO bibo = CardBIBO.wrap(terminal.connect("*"));
            NFCTransport transport = new NFCTransport(bibo);
            transport.terminalName = terminal.getName();
            TransportMetadata metadata = transport.probe();
            if (metadata == null)
                throw new IllegalStateException("Not a FIDO2/U2F device!");
            transport.metadata = metadata;
            return transport;
        } catch (CardException e) {
            throw new RuntimeException("Could not connect: " + e.getMessage(), e);
        }
    }

    private NFCTransport(BIBO bibo) {
        this.bibo = bibo;
    }

    public static List<String> list() {
        try {
            return TerminalManager.getDefault().terminals().list().stream().map(CardTerminal::getName).collect(Collectors.toList());
        } catch (CardException e) {
            logger.error("Failed to list readers: " + e.getMessage());
            throw new RuntimeException("Failed to list readers: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] transmit(byte[] apdu) throws IOException {
        return bibo.transceive(apdu);
    }

    @Override
    public String getDeviceName() {
        return terminalName;
    }

    @Override
    public void close() throws IOException {
        bibo.close();
    }
}
