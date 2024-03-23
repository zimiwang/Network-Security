package Assignment4.ExtendNSProtocol;

import Assignment4.ExtendNSProtocol.ExtendNeedhamSchroederUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

public class ExtendAliceClient {
    private ExtendNeedhamSchroederUtil util;
    private SecretKey key_Alice;
    private int bobPort;
    private int KDCPort;
    private String host;
    private String sessionId;
    private byte[] encrypted_NB;
    private byte[] ticketToBob;
    private SecretKey key_K_AB;

    public ExtendAliceClient(SecretKey key1, String Host, int bPort, int kPort) throws Exception {

        util = new ExtendNeedhamSchroederUtil();
        key_Alice = key1;
        host = Host;
        bobPort = bPort;
        KDCPort = kPort;
        sessionId = UUID.randomUUID().toString();
    }

    public void requestCommunicationWithBob() throws Exception{

        try (Socket socket = new Socket(host, bobPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream  in = new ObjectInputStream(socket.getInputStream())) {

            // Send sessionId to Bob
            out.writeObject(sessionId);

            // ---------------------Alice sends the initial message to Bob - Message 1--------------------
            String request_message = "I want to talk to you\n";
            String my_name = "Alice";
            byte[] my_name_byte = my_name.getBytes();
            System.out.println("Message 1: Alice sent a request message to Bob: " + request_message);
            out.write(request_message.getBytes(StandardCharsets.UTF_8));
            out.writeObject(my_name_byte);
            out.flush();
            // ------------------Message 1 End------------------

            // Receive encrypted N_b from Bob - Message 2
            encrypted_NB = (byte[]) in.readObject();
            System.out.println("Message 2: Alice received K_Bob{NB} from Bob");
            // ------------------Message 2 End------------------
        }

        try (Socket socket = new Socket(host, KDCPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream  in = new ObjectInputStream(socket.getInputStream())) {

            // Send sessionId to KDC
            out.writeObject(sessionId);

            // ---------------------Alice sends the request to KDC server - Message 3---------------
            byte[] N1 = util.generateChallenge(64);
            String sender_name = "Alice";
            String receiver_name = "Bob";
            byte[] receiver_name_byte = receiver_name.getBytes();
            out.writeObject(N1);
            out.writeObject(sender_name);
            out.writeObject(receiver_name);
            out.writeObject(encrypted_NB);

            System.out.println("Message 3: Alice sent N1, Alice, Bob, K_Bob{NB} to KDC");
            // ------------------Message 3 End------------------

            // ---------------------Received session key and the ticket from KDC server - Message 4-----------------
            byte[] encrypted_K_Alice = (byte[]) in.readObject();
            List<byte[]> decrypted_K_Alice = util.decryptTripleDes(encrypted_K_Alice, key_Alice);
            byte[] back_N1 = decrypted_K_Alice.get(0);
            byte[] back_ReceiverName = decrypted_K_Alice.get(1);

            // VERIFY if the receiver's name and N1 are correct
            if (!Arrays.equals(back_N1, N1)){
                throw new Exception("Received N1 from KDC does not match the expected N1.");
            }
            else {
                System.out.println("Pass Challenge N1");
            }
            if (!Arrays.equals(back_ReceiverName, receiver_name_byte)){
                throw new Exception("Received receiver's name from KDC does not match the expected name.");
            }
            else {
                System.out.println("Pass the receiver's name challenge");
            }

            byte[] byte_K_AB = decrypted_K_Alice.get(2);
            // Convert byte_KAB to SecretKey type
            key_K_AB = new SecretKeySpec(byte_K_AB, "DESede");

            ticketToBob = decrypted_K_Alice.get(3);

            System.out.println("Message 4: Alice received K_Alice{N1, Bob, KAB, ticket} from KDC");
            // ------------------Message 4 End------------------
        }
        try (Socket socket = new Socket(host, bobPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream  in = new ObjectInputStream(socket.getInputStream())) {

            // Send sessionId to Bob
            out.writeObject(sessionId);

            // ---------------------Alice sends ticket and encrypted K_AB{N2} to Bob - message 5------------------
            byte[] N2 = util.generateChallenge(64);
            byte[] K_AB_N2 = util.encryptTripleDes_single(N2, key_K_AB);
            out.writeObject(ticketToBob);
            out.writeObject(K_AB_N2);

            System.out.println("Message 5: Alice sent ticket, K_AB{N2} to Bob");
            // ------------------Message 5 End------------------

            // ---------------------Alice receives K_AB{N_2-1, N_3} from Bob - Message 6---------------------
            byte[] encrypted_KAB_N2_N3 = (byte[]) in.readObject();
            List<byte[]> decrypted_KAB_N2_N3 = util.decryptTripleDes(encrypted_KAB_N2_N3, key_K_AB);
            byte[] decrementN2 = decrypted_KAB_N2_N3.get(0);
            byte[] N3 = decrypted_KAB_N2_N3.get(1);

            System.out.println("Message 6: Alice received K_AB{N2-1, N3} from Bob");

            // Verify if (N2-1)+1 == N2
            byte[] increment_decrement_N2 = util.incrementOneByte(decrementN2);
            if (!Arrays.equals(N2, increment_decrement_N2)){
                throw new Exception("Received N2-1 does not match the expected value N2.");
            }
            else {
                System.out.println("Pass challenge N2");
            }
            // ------------------Message 6 End------------------

            // ---------------------Alice sends KAB{N3-1} to Bob - Message 7-------------------
            byte[] decrementN3 = util.decrementOneByte(N3);
            byte[] encrypted_decrementN3 = util.encryptTripleDes_single(decrementN3, key_K_AB);
            out.writeObject(encrypted_decrementN3);

            System.out.println("Message 7: Alice sent K_AB{N3-1} to Bob");
            // ------------------Message 7 End------------------
        }
    }
}
