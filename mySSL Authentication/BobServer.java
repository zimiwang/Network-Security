import org.bouncycastle.operator.OperatorCreationException;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.Map;
import java.util.Objects;

import static org.bouncycastle.oer.its.ieee1609dot2dot1.AdditionalParams.encryptionKey;

public class BobServer {
    private mySSLUtils utils;
    private String serverName;
    private ServerSocket serverSocket;
    private PublicKey bobPublicKey;
    private PrivateKey bobPrivateKey;
    private PublicKey alicePublicKey;

    public BobServer(int port) throws Exception {
        serverName = "Bob";
        serverSocket = new ServerSocket(port);
        utils = new mySSLUtils();

        KeyPair keypair = utils.generateKeyPair();
        bobPrivateKey = keypair.getPrivate();
        bobPublicKey = keypair.getPublic();
    }

    // Handshake Phase - Bob received hello message and return information back - message 2
    public Map.Entry<String[], X509Certificate> message_two(ObjectOutputStream out, String[] ciphers) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, OperatorCreationException, IOException {

        // Server chooses the ciphers from suits
        String encryptAlgo = "RSA";
        String integrityAlgo = "HMAC";
        String[] cipherChoose = new String[]{encryptAlgo, integrityAlgo};

        // Generate certificate with self-signed
        X509Certificate bobCertificate = utils.certificateGenerator(serverName, bobPublicKey, bobPrivateKey);

        // Send both to Alice
        out.writeObject(cipherChoose);
        out.writeObject(bobCertificate);

        return new AbstractMap.SimpleEntry<>(cipherChoose, bobCertificate);
    }

    public Map.Entry<byte[], byte[]> message_four(ObjectOutputStream out, String[] ciphers){

        try {
            // Generate nonce
            byte[] nonceBob = utils.generateNonce(64);
            byte[] encrypted_nonce_Bob = utils.encryptRSA(nonceBob, alicePublicKey);
            out.writeObject(encrypted_nonce_Bob);

            return new AbstractMap.SimpleEntry<>(nonceBob, encrypted_nonce_Bob);

        } catch (SignatureException | InvalidKeyException e) {
            System.out.println("Certificate verification failure.");
            return null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Initialize the Bob server and wait for the hello request
    public void listen() throws Exception{

        while(true){
            try(Socket aliceSocket = serverSocket.accept();
                ObjectInputStream in = new ObjectInputStream(aliceSocket.getInputStream());
                ObjectOutputStream out = new ObjectOutputStream(aliceSocket.getOutputStream())) {

                // message 0: Assume Alice and Bob got each other's public key by KDC (Third party)
                alicePublicKey = (PublicKey) in.readObject();
                out.writeObject(bobPublicKey);

                // Message 1: Handshake Phase - information from hello message - Received information
                String clientName = (String) in.readObject();
                String[] ciphersSuits = (String[]) in.readObject();

                // message 2: Handshake Phase - Bob received hello message and return information back -
                Map.Entry<String[], X509Certificate> messageTwo_output = message_two(out, ciphersSuits);
                System.out.println(serverName + " sends message 2 -----------------------> Client");

                // message 3: Handshake Phase - Bob received certificate from client and nonce encrypted by client's public key
                X509Certificate aliceCertificate = (X509Certificate) in.readObject();
                byte[] encryptedNonceAlice = (byte[]) in.readObject();

                // Verify whether the certificate belongs to alice
                try{
                    // Verify the certificate from Bob
                    aliceCertificate.verify(alicePublicKey);
                    System.out.println("Certificate verification successful.");
                    System.out.println(aliceCertificate.toString());
                } catch (SignatureException | InvalidKeyException e) {
                    System.out.println("Certificate verification failure.");
                }

                // message 4: Handshake Phase - Bob sends KA+[nonce_Bob] to Alice
                System.out.println(serverName + " received the message <----------------------- Client");
                Map.Entry<byte[], byte[]> messageFour_output = message_four(out, ciphersSuits);
                System.out.println(serverName + " sends message 4 nonce and Alice's certificate -----------------------> Server");

                // Calculate and get master key
                byte[] Nonce_Alice = utils.decryptRSA(encryptedNonceAlice, bobPrivateKey);
                SecretKey masterKey = utils.generateMasterKey(Nonce_Alice, messageFour_output.getKey());
                SecretKey[] sessionKeys = utils.deriveSessionKeys(masterKey.getEncoded());

                // Calculate all messages of HMAC
                Object[] clientMessages = new Object[] {
                        clientName, // client name - String
                        ciphersSuits, // ciphers suits - String[]
                        aliceCertificate, // Alice's Certificate - X509Certificate
                        encryptedNonceAlice // KB+{R_Alice} - byte[]
                };

                Object[] serverMessages = new Object[] {
                        messageTwo_output.getKey(),   // Ciphers bob chooses from messageTwo - String[]
                        messageTwo_output.getValue(), // Bob's certificate from messageTwo - X509Certificate
                        messageFour_output.getValue() // KA+[nonce_Bob] from messageFour - byte[]
                };
                String HMAC_Bob = utils.calculateHmacForMessages(clientMessages, serverMessages,
                        sessionKeys[3], false);
                String HMAC_Alice_verify = utils.calculateHmacForMessages(clientMessages, serverMessages,
                        sessionKeys[1], true);

                // message 5: Handshake Phase - Server received HMAC from client
                String HMAC_Alice = (String) in.readObject();

                // message 6: Handshake Phase - Server sent HMAC to client
                out.writeObject(HMAC_Bob);

                // Verify whether HMAC are same
                if (Objects.equals(HMAC_Alice_verify, HMAC_Alice)){
                    System.out.println("Alice's HMAC verification pass.");

                    // -------------Data transfer phase--------------
                    System.out.println("Start to transfer encrypted file to client········");
                    File file = new File("src/file/little_prince.txt");
                    byte[] fileContent = new byte[(int) file.length()];
                    try(FileInputStream fileInputStream = new FileInputStream(file)){
                        fileInputStream.read(fileContent);
                    } catch (Exception e){
                        System.out.println("Load file failed");
                    }

                    // Encrypt fileContent by AES
                    byte[] encrypted_file = utils.encryptAES(fileContent, sessionKeys[2]);
                    out.writeObject(encrypted_file);
                    System.out.println("Sent the encrypted file to client---------------------> Client");
                }
                else {
                    System.out.println("Alice's HMAC verification failed.");
                    throw new SecurityException("HMAC verification failed.");
                }
            }catch (Exception e) {
                System.out.println("An error occurred: " + e.getMessage());
                throw e;
            }
        }
    }
}
