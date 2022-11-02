package pro.javacard.fido2.common;

import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

public class AuthenticatorDataTests {

    @Test
    public void testExtensions() throws Exception {
        byte[] data = Hex.decode("a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947c100000000ac5ebf97149e4b1c977300db72d399e2004104581233f9dac60a774112844c7c3d65914cf0e89df72a3f965c0219661db35183de63b351a0cbea84a068dbda631c65948c7c6f06407076a374540b5532a69224a5010203262001215820581233f9dac60a774112844c7c3d65914cf0e89df72a3f965c0219661db35183225820de63b351a0cbea84a068dbda631c65948c7c6f06407076a374540b5532a69224a16b6372656450726f7465637401");

        AuthenticatorData ad = AuthenticatorData.fromBytes(data);
        System.out.println(ad);
    }

    @Test
    public void testExtensions2() throws Exception {
        byte[] data = Hex.decode("a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce19474300000000ac5ebf97149e4b1c977300db72d399e20041049e1dc4a08b4f53a1d90b065830e6ba6a0a39689bf00979617b9a01737334320bbc4e5a10e92d5f0651c0e07d17b81b1b7e38e4a5a16ed89f29c0945f16a7b827a5010203262001215820361aea8447ec5990f2abe551829ea4fde6c7410a401b1f44b775233a9f4e82882258208f4b260401a1bf3fbf9eb29898f4ff7149cb1e61094611a339692d3af0b3b0fd00000000000000000000000000");

        AuthenticatorData ad = AuthenticatorData.fromBytes(data);
        System.out.println(ad);
    }

    @Test
    public void testSample3() throws Exception {
        byte[] data = Hex.decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634500000000ac5ebf97149e4b1c977300db72d399e200404af6baaa9772a84dea3ecfc5db47cc5e1e19b57b0ddd00b9ba11ed8339bb773eaa0d355c5e67be81c2576f5eb364a14f08da3e65559741dcbe624fca8cfca33fa501020326200121582067143081d43900fe7c856515fb5522fa68eb0b2ff783b98e2dc28beaf18f2c4d22582082b8695877c6c434918e1d2ba2c755292518122f366cdfaafc35a072335177b7");

        AuthenticatorData ad = AuthenticatorData.fromBytes(data);
        System.out.println(ad);
    }


}
