package Assignment4.OriginalNSProtocol.ECB;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

public class OriginalAliceClient {
    private OriginalNeedhamSchroederUtil util;
    private SecretKey key_Alice;
    private int bobPort;
    private int KDCPort;
    private String host;
    private String sessionId;
    private byte[] ticketToBob;
    private byte[] Trudy_K_AB_N2;
    private SecretKey key_K_AB;

    public OriginalAliceClient(SecretKey key1, String Host, int bPort, int kPort) throws Exception {

        util = new OriginalNeedhamSchroederUtil();
        key_Alice = key1;
        host = Host;
        bobPort = bPort;
        KDCPort = kPort;
        sessionId = UUID.randomUUID().toString();
    }

    public void requestCommunicationWithBob() throws Exception{

        try (Socket socket = new Socket(host, KDCPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream  in = new ObjectInputStream(socket.getInputStream())) {

            // Send sessionId to KDC
            out.writeObject(sessionId);

            // ---------------------Alice sends the request to KDC server - Message 1---------------
            byte[] N1 = util.generateChallenge(64);
            String sender_name = "Alice";
            String receiver_name = "Bob";
            byte[] receiver_name_byte = receiver_name.getBytes();

            out.writeObject(N1);
            out.writeObject(sender_name);
            out.writeObject(receiver_name);

            System.out.println("Message 1: Alice sent N1, Alice, Bob to KDC");
            // ------------------Message 1 End------------------

            // ---------------------Received session key and the ticket from KDC server - Message 2-----------------
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

            System.out.println("Message 2: Alice received K_Alice{N1, Bob, KAB, ticket} from KDC");
            // ------------------Message 2 End------------------
        }catch (IOException e) {
            System.out.println("An error occurred during communication with KDC: " + e.getMessage());
        }

        try (Socket socket = new Socket(host, bobPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream  in = new ObjectInputStream(socket.getInputStream())) {

            // Send sessionId to Bob
            out.writeObject(sessionId);

            // ---------------------Alice sends ticket and encrypted K_AB{N2} to Bob - message 3------------------
            byte[] N2 = util.generateChallenge(64);
            byte[] K_AB_N2 = util.encryptTripleDes_single(N2, key_K_AB);
            out.writeObject(ticketToBob);
            out.writeObject(K_AB_N2);

            String sender_name = "Alice";
            byte[] sender_name_byte = sender_name.getBytes();

            out.writeObject(sender_name_byte);

            System.out.println("Message 3: Alice sent ticket, K_AB{N2} to Bob");
            // ------------------Message 3 End------------------

            // ---------------------Alice receives K_AB{N_2-1, N_3} from Bob - Message 4---------------------
            byte[] encrypted_KAB_N2_N3 = (byte[]) in.readObject();
            List<byte[]> decrypted_KAB_N2_N3 = util.decryptTripleDes(encrypted_KAB_N2_N3, key_K_AB);
            byte[] decrementN2 = decrypted_KAB_N2_N3.get(0);
            byte[] N3 = decrypted_KAB_N2_N3.get(1);

            System.out.println("Message 4: Alice received K_AB{N2-1, N3} from Bob");

            // Verify if (N2-1)+1 == N2
            byte[] increment_decrement_N2 = util.incrementOneByte(decrementN2);
            if (!Arrays.equals(N2, increment_decrement_N2)){
                throw new Exception("Received N2-1 does not match the expected value N2.");
            }
            else {
                System.out.println("Pass challenge N2");
            }
            // ------------------Message 4 End------------------

            // ---------------------Alice sends KAB{N3-1} to Bob - Message 5-------------------
            byte[] decrementN3 = util.decrementOneByte(N3);
            byte[] encrypted_decrementN3 = util.encryptTripleDes_single(decrementN3, key_K_AB);
            out.writeObject(encrypted_decrementN3);

            System.out.println("Message 5: Alice sent K_AB{N3-1} to Bob");
            // ------------------Message 5 End------------------

            String str_Kab_decrementN2_N3 = util.bytesToHex1(encrypted_KAB_N2_N3);
            String str_decrementN2 = util.bytesToHex1(decrementN2);
            String str_N3 = util.bytesToHex1(N3);
            String str_encrypted_decrementN3 = util.bytesToHex1(encrypted_decrementN3);
            String str_decrementN3 = util.bytesToHex1(decrementN3);

            System.out.println("CBC vs ECB outputs in last two messages: \n");
            System.out.println("ECB encrypted KAB_{N2-1, N3} output : " + str_Kab_decrementN2_N3);
            System.out.println("ECB decrypted N2-1 output : " + str_decrementN2);
            System.out.println("ECB decrypted N3 output : " + str_N3);
            System.out.println("ECB decrypted N3-1 output : " + str_decrementN3);
            System.out.println("ECB encrypted N3-1 output : " + str_encrypted_decrementN3);
            System.out.println("CBC vs ECB outputs in last two messages end\n");

        }catch (IOException e) {
            System.out.println("An error occurred during communication with Bob: " + e.getMessage());
        }
    }

    public void ReflectionAttack() throws Exception{

        /*
        These steps are the normal communication between Alice and Bob.
        Now I will let Trudy intercept the messages 3.
        Thus, Trudy has ticket and Kab{N2}
         */
        try (Socket socket = new Socket(host, KDCPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream  in = new ObjectInputStream(socket.getInputStream())) {

            // Send sessionId to KDC
            out.writeObject(sessionId);

            // ---------------------Alice sends the request to KDC server - Message 1---------------
            byte[] N1 = util.generateChallenge(64);
            String sender_name = "Alice";
            String receiver_name = "Bob";
            byte[] receiver_name_byte = receiver_name.getBytes();

            out.writeObject(N1);
            out.writeObject(sender_name);
            out.writeObject(receiver_name);

            System.out.println("Message 1: Alice sent N1, Alice, Bob to KDC");
            // ------------------Message 1 End------------------

            // ---------------------Received session key and the ticket from KDC server - Message 2-----------------
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

            System.out.println("Message 2: Alice received K_Alice{N1, Bob, KAB, ticket} from KDC");
            // ------------------Message 2 End------------------
        }catch (IOException e) {
            System.out.println("An error occurred during communication with KDA: " + e.getMessage());
        }

        /*
        Now Trudy has ticket and Kab{N2}.
        Then Trudy will send the K_AB{N2} to Bob repeatedly to compare ECB and CBC
         */
        try (Socket socket = new Socket(host, bobPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream  in = new ObjectInputStream(socket.getInputStream())) {

            // Send sessionId to Bob
            out.writeObject(sessionId);

            String sender_name = "Alice";
            byte[] sender_name_byte = sender_name.getBytes();

            byte[] N2 = util.generateChallenge(64);
            byte[] K_AB_N2 = util.encryptTripleDes_single(N2, key_K_AB);

            // ---------------------Trudy sends ticket and encrypted K_AB{N2'} to Bob - message 3------------------
            // Trudy generates a new N2_Trudy
            // Now Trudy has the ticket and K_AB_N2
            System.out.println("\n Now Trudy impersonate Alice to communicate with Bob!!!!!!!!! \n");
            Trudy_K_AB_N2 = K_AB_N2;


            out.writeObject(ticketToBob);
            out.writeObject(Trudy_K_AB_N2);

            out.writeObject(sender_name_byte);

            System.out.println("Message 3: Trudy sent ticket, K_AB{N2_Trudy} to Bob");
            // ------------------Message 3 End------------------

            // ---------------------Trudy receives K_AB{N_2-1, N_3} from Bob - Message 4---------------------
            byte[] encrypted_KAB_N2_N3 = (byte[]) in.readObject();

            System.out.println("Message 4: Trudy received K_AB{N2_Trudy-1, N3} from Bob");
            // ------------------Message 4 End------------------
            socket.close();

            System.out.println("Connection to Bob has been closed.");
        }catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error closing the connection or connection already closed.");
        }

        System.out.println("Attempting to create a new communication with Bob...");

        // Repeatedly sent the message 3 to Bob
        try (Socket socket = new Socket(host, bobPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream  in = new ObjectInputStream(socket.getInputStream())) {
            // Send sessionId to Bob
            out.writeObject(sessionId);

            String sender_name = "Alice";
            byte[] sender_name_byte = sender_name.getBytes();

            System.out.println("\n Now Trudy impersonate Alice to communicate with Bob!!!!!!!!! \n");

            out.writeObject(ticketToBob);
            out.writeObject(Trudy_K_AB_N2);

            out.writeObject(sender_name_byte);

            System.out.println("Message 3: Trudy sent ticket, K_AB{N2_Trudy} to Bob");
            // ------------------Message 3 End------------------

            // ---------------------Trudy receives K_AB{N_2-1, N_3} from Bob - Message 4---------------------
            byte[] encrypted_KAB_N2_N3 = (byte[]) in.readObject();

            System.out.println("Message 4: Trudy received K_AB{N2_Trudy-1, N3} from Bob");
            // ------------------Message 4 End------------------
        }
    }
}
