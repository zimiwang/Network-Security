package Assignment3;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

public class BobServer {

    private static final BigInteger g = BigInteger.valueOf(1907);
    private static final BigInteger p = BigInteger.valueOf(784313);
    private static final BigInteger Sb = BigInteger.valueOf(12077);
    private static DiffieHellmanUtil diffieHellmanUtil = new DiffieHellmanUtil(g, p);

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Bob waiting for a connection...");
        Socket socket = serverSocket.accept();
        System.out.println("Alice connected.");

        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            // Receive Alice's public key
            BigInteger Ta = new BigInteger(in.readLine());
            System.out.println("Received Alice's public key: " + Ta);

            // Calculate and send Bob's public key
            BigInteger Tb = diffieHellmanUtil.calculatePublicKey(Sb);
            out.println(Tb.toString());
            System.out.println("Sent Bob's public key: " + Tb);

            // Calculate the shared key
            BigInteger sharedKey = diffieHellmanUtil.calculateSharedKey(Ta, Sb);
            System.out.println("Shared key: " + sharedKey);
        } finally {
            socket.close();
            serverSocket.close();
        }
    }
}
