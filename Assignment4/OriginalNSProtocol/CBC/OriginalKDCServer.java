package Assignment4.OriginalNSProtocol.CBC;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;

public class OriginalKDCServer {

    private ServerSocket serverSocket;
    private OriginalNeedhamSchroederUtil util;
    private SecretKey key_Alice;
    private SecretKey key_Bob;
    private Map<String, Integer> sessionState;

    public OriginalKDCServer(int port, SecretKey keyAlice, SecretKey keyBob) throws Exception {

        serverSocket = new ServerSocket(port);
        sessionState = new HashMap<>();
        util = new OriginalNeedhamSchroederUtil();
        key_Alice = keyAlice;
        key_Bob = keyBob;
    }

    public void start() throws Exception{

        while(true){
            try(Socket clientSocket = serverSocket.accept();
                ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())){

                // Firstly receive and verify the sessionId
                String sessionId = (String) in.readObject();
                int state = sessionState.getOrDefault(sessionId, 0);

                // KDA received N1, Alice, Bob from Alice - Message 1
                byte[] N1 = (byte[]) in.readObject();
                String sender_name = (String) in.readObject();
                String receiver_name = (String) in.readObject();

                // Generate shared key KAB for Alice and Bob
                SecretKey key_AB = util.generateSecretKey();

                // Convert String names to bytes
                byte[] Alice = sender_name.getBytes();
                byte[] Bob = receiver_name.getBytes();
                byte[] byte_key_AB = key_AB.getEncoded();

                // KDC sent K_Alice to Alice - Message 2
                // Encrypt N1, Bob, K_AB, ticket (K_AB, Alice)
                List<byte[]> byte_ticket = Arrays.asList(byte_key_AB, Alice);
                byte[] encrypted_ticket = util.encryptTripleDES(byte_ticket, key_Bob);

                List<byte[]> byte_K_Alice = Arrays.asList(N1, Bob, byte_key_AB, encrypted_ticket);
                byte[] encrypted_K_Alice = util.encryptTripleDES(byte_K_Alice, key_Alice);

                out.writeObject(encrypted_K_Alice);
//                System.out.println("KDC sent encrypted N1, Bob, K_AB, ticket (K_AB, Alice) to Alice");

                // Record the sessionId
                sessionState.put(sessionId, state + 1);
            }
        }
    }

}
