package pro.javacard.fido2.common;

import java.util.Set;
import java.util.stream.Collectors;

public abstract class TransportMetadata {

    public abstract String getDeviceVersion();

    public abstract String getDeviceName();

    public abstract Set<CTAPVersion> getTransportVersions();

    @Override
    public String toString() {
        String transports = getTransportVersions().stream().map(Enum::toString).collect(Collectors.joining(", "));
        return String.format("%s (v%s, %s)", getDeviceName(), getDeviceVersion(), transports);
    }
}
