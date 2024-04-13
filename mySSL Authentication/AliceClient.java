import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;


public class AliceClient {

    private String clientName;
    private mySSLUtils utils;
    private PrivateKey alicePrivateKey;
    private PublicKey alicePublicKey;
    private PublicKey bobPublicKey;

    public AliceClient() throws Exception {

        clientName = "Alice";
        utils = new mySSLUtils();

        KeyPair keypair = utils.generateKeyPair();
        alicePrivateKey = keypair.getPrivate();
        alicePublicKey = keypair.getPublic();

        // Assume Alice gets Bob's public key by face to face or get it from the existed public key center,
        // because Bob is a server so many people may want to build connection with the server.
        // bobPublicKey = bKey;
    }

    // Handshake Phase - Alice sent a hello request to Bob server - message 1
    public Map.Entry<String, String[]> message_one(ObjectOutputStream out) throws Exception{

        // Message 1 - Alice sent a message with
        String request = clientName + ": I want to talk";
        String[] cipher_suits = new String[]{"AES", "RSA", "3DES_CBC", "ChaCha20", "SHA2", "SHA3", "HMAC"};

        out.writeObject(request);
        out.writeObject(cipher_suits);

        System.out.println(clientName + " sends message 1 with providing ciphers suits: "
                + Arrays.toString(cipher_suits) + " -----------------------> Server");

        return new AbstractMap.SimpleEntry<>(request, cipher_suits);
    }

    public MessageThreeResponse message_three(ObjectOutputStream out, String[] ciphers) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        try {
            // Generate Alice's certificate
            X509Certificate certificateAlice = utils.certificateGenerator(clientName, alicePublicKey, alicePrivateKey);

            // Generate KB+{R_Alice}
            byte[] nonceAlice = utils.generateNonce(64);
            byte[] encrypted_nonce_Alice = utils.encryptRSA(nonceAlice, bobPublicKey);

            out.writeObject(certificateAlice);
            out.writeObject(encrypted_nonce_Alice);

            return new MessageThreeResponse(certificateAlice, encrypted_nonce_Alice, nonceAlice);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void successfulMutualAuthentication(String host, int port) throws Exception {

        try (Socket socket = new Socket(host, port);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // message 0: Assume Alice and Bob got each other's public key by KDC (Third party)
            out.writeObject(alicePublicKey);
            bobPublicKey = (PublicKey) in.readObject();

            // message 1: Handshake Phase - Client sends hello request with ciphers provided
            Map.Entry<String, String[]> messageOne_output = message_one(out);

            // message 2: Handshake Phase - Server received message and choose ciphers, then send certificate
            String[] ciphersBobChoose = (String[]) in.readObject();
            X509Certificate bobCertificate = (X509Certificate) in.readObject();

            // Verify whether the certificate belongs to Bob
            try {
                // Verify the certificate from Bob
                bobCertificate.verify(alicePublicKey);
                System.out.println("Alice's Certificate verification successful.");
                System.out.println(bobCertificate.toString());
            } catch (SignatureException | InvalidKeyException e) {
                System.out.println("Alice's Certificate verification failure.");
            }

            // message 3: Handshake Phase -Alice sends her certificate and KB+[nonce] to Bob
            System.out.println(clientName + " received the message <----------------------- Server");
            MessageThreeResponse messageThree_output = message_three(out, ciphersBobChoose);
            System.out.println(clientName + " sends message 3: KB+{R_Alice} and Alice's certificate -----------------------> Server");

            // message 4: Handshake Phase - Client received message 4: KA+[nonce_Bob]
            byte[] encryptedNonceBob = (byte[]) in.readObject();

            // Calculate and get master key
            byte[] Nonce_Bob = utils.decryptRSA(encryptedNonceBob, alicePrivateKey);
            byte[] Nonce_Alice = messageThree_output.getNonce();
            SecretKey masterKey = utils.generateMasterKey(Nonce_Alice, Nonce_Bob);
            SecretKey[] sessionKeys = utils.deriveSessionKeys(masterKey.getEncoded());

            // Calculate all messages of HMAC
            Object[] clientMessages = new Object[] {
                    messageOne_output.getKey(), // client name
                    messageOne_output.getValue(), // ciphers suits
                    messageThree_output.getCertificate(), // Alice's Certificate
                    messageThree_output.getEncryptedNonce(), // KB+{R_Alice}
            };

            Object[] serverMessages = new Object[] {
                    ciphersBobChoose,   // Ciphers bob chooses from messageTwo
                    bobCertificate, // Bob's certificate from messageTwo
                    encryptedNonceBob // KA+[nonce_Bob] from messageFour
            };

            String HMAC_Alice = utils.calculateHmacForMessages(clientMessages, serverMessages,
                    sessionKeys[1], true);
            String HMAC_Bob_verify = utils.calculateHmacForMessages(clientMessages, serverMessages,
                    sessionKeys[3], false);
            // message 5: Handshake Phase - All messages of HMAC
            out.writeObject(HMAC_Alice);

            // message 6: Handshake Phase - All message of HMAC from Bob
            String HMAC_Bob = (String) in.readObject();

            // Verify whether HMAC are same
            if (Objects.equals(HMAC_Bob_verify, HMAC_Bob)){
                System.out.println("Bob's HMAC verification pass.");
                // Receive encrypted file
                byte[] encrypt_file = (byte[])in.readObject();
                byte[] decrypt_file = utils.decryptAES(encrypt_file, sessionKeys[2]);

                // Save decrypted file
                try (FileOutputStream fos = new FileOutputStream("src/file/decrypted_file.txt")) {
                    fos.write(decrypt_file);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                // Save encrypted file
                try (FileOutputStream fos = new FileOutputStream("src/file/encrypted_file.txt")) {
                    fos.write(encrypt_file);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                // Load original file
                File file = new File("src/file/little_prince.txt");
                byte[] original_file = new byte[(int) file.length()];
                try(FileInputStream fileInputStream = new FileInputStream(file)){
                    fileInputStream.read(original_file);
                } catch (Exception e){
                    System.out.println("Load file failed");
                }

                byte[] originalChecksum = utils.SHA3_byte(original_file);
                byte[] decryptedChecksum = utils.SHA3_byte(decrypt_file);

                // Compare both checksums by Hash value
                if (MessageDigest.isEqual(originalChecksum, decryptedChecksum)){
                    System.out.println("The files are identical.");
                } else {
                    System.out.println("The files are not identical.");
                }
            }
            else {
                System.out.println("Bob's HMAC verification failed.");
                throw new SecurityException("HMAC verification failed.");
            }
        }catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
            throw e;
        }
    }

    public void filedMutualAuthentication(String host, int port) throws Exception {

        try (Socket socket = new Socket(host, port);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // message 0: Assume Alice and Bob got each other's public key by KDC (Third party)
            out.writeObject(alicePublicKey);
            bobPublicKey = (PublicKey) in.readObject();

            // message 1: Handshake Phase - Client sends hello request with ciphers provided
            Map.Entry<String, String[]> messageOne_output = message_one(out);

            // message 2: Handshake Phase - Server received message and choose ciphers, then send certificate
            String[] ciphersBobChoose = (String[]) in.readObject();
            X509Certificate bobCertificate = (X509Certificate) in.readObject();

            // Verify whether the certificate belongs to Bob
            try {
                // Verify the certificate from Bob
                bobCertificate.verify(alicePublicKey);
                System.out.println("Alice's Certificate verification successful.");
                System.out.println(bobCertificate.toString());
            } catch (SignatureException | InvalidKeyException e) {
                System.out.println("Alice's Certificate verification failure.");
            }

            // message 3: Handshake Phase -Alice sends her certificate and KB+[nonce] to Bob
            System.out.println(clientName + " received the message <----------------------- Server");
            MessageThreeResponse messageThree_output = message_three(out, ciphersBobChoose);
            System.out.println(clientName + " sends message 3: KB+{R_Alice} and Alice's certificate -----------------------> Server");

            // message 4: Handshake Phase - Client received message 4: KA+[nonce_Bob]
            byte[] encryptedNonceBob = (byte[]) in.readObject();

            // Calculate and get master key
            byte[] Nonce_Bob = utils.decryptRSA(encryptedNonceBob, alicePrivateKey);
            byte[] Nonce_Alice = messageThree_output.getNonce();
            SecretKey masterKey = utils.generateMasterKey(Nonce_Alice, Nonce_Bob);
            SecretKey[] sessionKeys = utils.deriveSessionKeys(masterKey.getEncoded());

            // --------------------------------Wrong total messages-----------------------------------
            // By changing the client name to simulate the situation

            // ————————————————————————————————————————————————————————————————————————————————————————

            // Calculate all messages of HMAC
            Object[] clientMessages = new Object[] {

                    // --------------------------------Wrong total messages-----------------------------------
                    // By changing the client name to simulate the situation
                    messageOne_output.getKey() + "ZW", // client name
                    // ————————————————————————————————————————————————————————————————————————————————————————

                    messageOne_output.getValue(), // ciphers suits
                    messageThree_output.getCertificate(), // Alice's Certificate
                    messageThree_output.getEncryptedNonce(), // KB+{R_Alice}
            };

            Object[] serverMessages = new Object[] {
                    ciphersBobChoose,   // Ciphers bob chooses from messageTwo
                    bobCertificate, // Bob's certificate from messageTwo
                    encryptedNonceBob // KA+[nonce_Bob] from messageFour
            };

            String HMAC_Alice = utils.calculateHmacForMessages(clientMessages, serverMessages,
                    sessionKeys[1], true);
            String HMAC_Bob_verify = utils.calculateHmacForMessages(clientMessages, serverMessages,
                    sessionKeys[3], false);
            // message 5: Handshake Phase - All messages of HMAC
            out.writeObject(HMAC_Alice);

            // message 6: Handshake Phase - All message of HMAC from Bob
            String HMAC_Bob = (String) in.readObject();

            // Verify whether HMAC are same
            if (Objects.equals(HMAC_Bob_verify, HMAC_Bob)){
                System.out.println("Bob's HMAC verification pass.");
                // Receive encrypted file
                byte[] encrypt_file = (byte[])in.readObject();
                byte[] decrypt_file = utils.decryptAES(encrypt_file, sessionKeys[2]);

                // Save decrypted file
                try (FileOutputStream fos = new FileOutputStream("src/file/decrypted_file.txt")) {
                    fos.write(decrypt_file);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                // Save encrypted file
                try (FileOutputStream fos = new FileOutputStream("src/file/encrypted_file.txt")) {
                    fos.write(encrypt_file);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                // Load original file
                File file = new File("src/file/little_prince.txt");
                byte[] original_file = new byte[(int) file.length()];
                try(FileInputStream fileInputStream = new FileInputStream(file)){
                    fileInputStream.read(original_file);
                } catch (Exception e){
                    System.out.println("Load file failed");
                }

                byte[] originalChecksum = utils.SHA3_byte(original_file);
                byte[] decryptedChecksum = utils.SHA3_byte(decrypt_file);

                // Compare both checksums by Hash value
                if (MessageDigest.isEqual(originalChecksum, decryptedChecksum)){
                    System.out.println("The files are identical.");
                } else {
                    System.out.println("The files are not identical.");
                }
            }
            else {
                System.out.println("Bob's HMAC verification failed.");
                throw new SecurityException("HMAC verification failed.");
            }
        }catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
            throw e;
        }
    }
}
