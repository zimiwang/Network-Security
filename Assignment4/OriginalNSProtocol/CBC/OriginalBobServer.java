package Assignment4.OriginalNSProtocol.CBC;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;

public class OriginalBobServer {

    private ServerSocket serverSocket;
    private OriginalNeedhamSchroederUtil util;
    private SecretKey key_Bob;
    private int port;
    private Map<String, Integer> sessionState;
    private byte[] sender_name;

    public OriginalBobServer(int Port, SecretKey k_Bob) throws IOException {
        serverSocket = new ServerSocket(Port);
        util = new OriginalNeedhamSchroederUtil();
        key_Bob = k_Bob;
        port = Port;
        sessionState = new HashMap<>();
    }

    public void listen() throws Exception{

        while(true){
            try(Socket aliceSocket = serverSocket.accept();
                ObjectInputStream in = new ObjectInputStream(aliceSocket.getInputStream());
                ObjectOutputStream out = new ObjectOutputStream(aliceSocket.getOutputStream())){

                // Receive the sessionId
                String sessionId = (String) in.readObject();
                int state = sessionState.getOrDefault(sessionId, 0);

                // Bob received the ticket and KAB{N2} from Alice - message 5
                byte[] ticket = (byte[]) in.readObject();
                byte[] KAB_N2 = (byte[]) in.readObject();

                // Extract shared key KAB
                List<byte[]> decrypted_ticket = util.decryptTripleDes(ticket, key_Bob);
                byte[] key_KAB_byte = decrypted_ticket.get(0);
                byte[] back_sender_name = decrypted_ticket.get(1);
                sender_name = (byte[]) in.readObject();

                // VERIFY if sender_name are correct.
                if (!Arrays.equals(back_sender_name, sender_name)){
                    throw new Exception("Received sender's name does not match the expected name.");
                }
                else{
                    System.out.println("Pass the sender's name challenge");
                }

                // Convert the key_KAB from byte to SecretKey variable
                SecretKey key_KAB = new SecretKeySpec(key_KAB_byte, "DESede");

                // Decrypt N2
                byte[] N2 = util.decryptTripleDes_single(KAB_N2, key_KAB);
                byte[] decrement_N2 = util.decrementOneByte(N2);

                // Generate N3
                byte[] N3 = util.generateChallenge(64);
                List<byte[]> message_6 = Arrays.asList(decrement_N2, N3);
                byte[] encrypted_message_6 = util.encryptTripleDES(message_6, key_KAB);

                // Bob sent message 6 to Alice
                out.writeObject(encrypted_message_6);

                // ------------------Message 6 End------------------

                // Bob received KAB{N3-1} from Alice - message 7----------
                byte[] KAB_decrement_N3 = (byte[]) in.readObject();
                byte[] decrement_N3 = util.decryptTripleDes_single(KAB_decrement_N3, key_KAB);
                byte[] increment_decrement_N3 = util.incrementOneByte(decrement_N3);
                // Verify if N3-1 == (N3-1)+1
                if (!Arrays.equals(N3, increment_decrement_N3)) {
                    throw new Exception("Received N3-1 does not match the expected value N3.");
                } else {
                    System.out.println("Authentication successful.");
                }
                // ------------------Message 7 End------------------

                sessionState.put(sessionId, state + 1);
            }catch (EOFException e) {
                System.out.println("Connection closed by client.");
            } catch (IOException e) {
                System.out.println("Error during communication with Alice: " + e.getMessage());
            }
        }
    }
}
