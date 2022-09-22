package pro.javacard.fido2.transports;

import pro.javacard.fido2.common.CTAPVersion;
import pro.javacard.fido2.common.TransportMetadata;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public class DefaultTransportMetadata extends TransportMetadata {
    private final String deviceVersion;
    private final String deviceName;
    private final EnumSet<CTAPVersion> transportVersions = EnumSet.noneOf(CTAPVersion.class);

    DefaultTransportMetadata(String version, String deviceName, byte capabilities) {
        this.deviceName = deviceName;
        this.deviceVersion = version;
        if ((capabilities & USBTransport.CAPABILITY_CBOR) == USBTransport.CAPABILITY_CBOR)
            transportVersions.add(CTAPVersion.FIDO_2_0);
        if (!((capabilities & USBTransport.CAPABILITY_NMSG) == USBTransport.CAPABILITY_NMSG)) {
            transportVersions.add(CTAPVersion.U2F_V2);
        }
    }

    DefaultTransportMetadata(String version, String deviceName, Collection<CTAPVersion> versions) {
        this.deviceName = deviceName;
        this.deviceVersion = version;
        this.transportVersions.addAll(versions);
    }

    @Override
    public String getDeviceVersion() {
        return deviceVersion;
    }

    @Override
    public String getDeviceName() {
        return deviceName;
    }

    @Override
    public Set<CTAPVersion> getTransportVersions() {
        return Collections.unmodifiableSet(transportVersions);
    }
}
