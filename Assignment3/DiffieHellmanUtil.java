package Assignment3;

import java.math.BigInteger;

public class DiffieHellmanUtil {

    private final BigInteger p;
    private final BigInteger g;

    public DiffieHellmanUtil(BigInteger g, BigInteger p) {
        this.g = g;
        this.p = p;
    }

    public BigInteger calculatePublicKey(BigInteger privateKey) {
        return g.modPow(privateKey, p);
    }

    public BigInteger calculateSharedKey(BigInteger receivedPublicKey, BigInteger privateKey) {
        return receivedPublicKey.modPow(privateKey, p);
    }
}
