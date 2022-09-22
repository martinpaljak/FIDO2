package pro.javacard.fido2.common;

import apdu4j.core.ResponseAPDU;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class U2FProtocolHelpers {

    final static long TICK_MS = 100;

    // Run a command until presence check succeeds or time out after specified time.
    // This only makes sense for USB HID devices

    static public byte[] presenceOrTimeout(CTAP1Transport transport, byte[] command, long timeoutInSeconds, CallbackHandler cb) throws IOException, TimeoutException, UnsupportedCallbackException {
        Clock wall = Clock.tickSeconds(ZoneId.systemDefault());
        Instant start = wall.instant();

        TextOutputCallback msg = new TextOutputCallback(TextOutputCallback.INFORMATION, "Provide user presence for " + transport.getMetadata().getDeviceName());

        cb.handle(new Callback[]{msg});

        while (true) {
            byte[] response = transport.transmitCTAP1(command);
            ResponseAPDU responseAPDU = new ResponseAPDU(response);
            if (responseAPDU.getSW() == 0x6985) {
                if (wall.instant().isAfter(start.plus(timeoutInSeconds, ChronoUnit.SECONDS)))
                    throw new TimeoutException(String.format("Timeout (%d seconds) when waiting for user presence", timeoutInSeconds));
                try {
                    TimeUnit.MILLISECONDS.sleep(TICK_MS);
                    continue;
                } catch (InterruptedException e) {
                    // ignore
                }
            } else {
                return response;
            }
        }
    }

    public static byte[] checkSuccess(byte[] u2f) throws IOException {
        ResponseAPDU response = new ResponseAPDU(u2f);
        if (response.getSW() != 0x9000) {
            throw new IOException(String.format("U2F error: 0x%04X", response.getSW()));
        }
        return response.getData();
    }
}
