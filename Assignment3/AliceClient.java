package Assignment3;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;

public class AliceClient {

    private static final BigInteger g = BigInteger.valueOf(1907);
    private static final BigInteger p = BigInteger.valueOf(784313);
    private static final BigInteger Sa = BigInteger.valueOf(160031);
    private static DiffieHellmanUtil diffieHellmanUtil = new DiffieHellmanUtil(g, p);

    public static void main(String[] args) throws IOException {
        Socket socket = new Socket("localhost", 12345);
        System.out.println("Alice connected to Bob.");

        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            // Calculate and send Alice's public key
            BigInteger Ta = diffieHellmanUtil.calculatePublicKey(Sa);
            out.println(Ta.toString());
            System.out.println("Sent Alice's public key: " + Ta);

            // Receive Bob's public key
            BigInteger Tb = new BigInteger(in.readLine());
            System.out.println("Received Bob's public key: " + Tb);

            // Calculate the shared key
            BigInteger sharedKey = diffieHellmanUtil.calculateSharedKey(Tb, Sa);
            System.out.println("Shared key: " + sharedKey);
        } finally {
            socket.close();
        }
    }
}
