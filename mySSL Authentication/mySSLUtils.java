import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Date;

public class mySSLUtils {
/**
 *
 * 1. Sun.Security version, but it can't access internal API.
 *
 */
//    public X509Certificate generateCertificate(String name, PublicKey pbKey, PrivateKey pvKey) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
//
//        // Construct an empty certificate
//        X509CertInfo certificateInfo = new X509CertInfo();
//        SecureRandom random = new SecureRandom();
//
//        // Valid data is one year in this certificate
//        Date start = new Date();
//        Date end = new Date(start.getTime() + (365 * 86400000L));
//        CertificateValidity interval = new CertificateValidity(start, end);
//        certificateInfo.setValidity(interval);
//
//        // Randomly generate a serial number of this certificate
//        BigInteger serialNumber = new BigInteger(64, random);
//        certificateInfo.setSerialNumber(new CertificateSerialNumber(serialNumber));
//
//        // Set the owner name of this certificate
//        X500Name owner = new X500Name(name);
//        certificateInfo.setIssuer(owner);
//        certificateInfo.setSubject(owner);
//
//        // Set a list of parameters in the certificate
//        certificateInfo.setVersion(new CertificateVersion(CertificateVersion.V3));
//
//        // Set the sender's public key in this certificate
//        certificateInfo.setKey(new CertificateX509Key(pbKey));
//
//        // Set the integrity algorithm of certificate
//        AlgorithmId algorithm = new AlgorithmId(AlgorithmId.SHA256withRSA_oid);
//        certificateInfo.setAlgorithmId(new CertificateAlgorithmId(algorithm));
//
//        // Sign this certificate with sender's private key
//        Signature signature = Signature.getInstance("SHA256withRSA");
//        signature.initSign(pvKey);
//        signature.update(certificateInfo.getEncodedInfo());
//
//        // Generate the certificate using a factory or builder
//        byte[] signedCert = signature.sign();
//        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//        InputStream in = new ByteArrayInputStream(signedCert);
//        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);
//
//        return certificate;
//    }

    /**
     *
     * 2. Bouncy Castle version
     *
     */
    public X509Certificate certificateGenerator(String name, PublicKey pbKey, PrivateKey pvKey)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, OperatorCreationException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365 * 86400000L);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        X500Name issuer = new X500Name("CN=" + name);
        X500Name subject = issuer;

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber, notBefore, notAfter, subject, pbKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(pvKey);
        X509CertificateHolder certHolder = certBuilder.build(signer);

        X509Certificate certificate =  new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);

        return certificate;
    }

    public byte[] generateNonce(int num_bits){

        int num_bytes = num_bits/8;
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[num_bytes];
        secureRandom.nextBytes(nonce);

        return nonce;
    }

    public static byte[] xor(byte[] nonce1, byte[] nonce2) {
        byte[] result = new byte[nonce1.length];
        for (int i = 0; i < nonce1.length; i++) {
            result[i] = (byte) (nonce1[i] ^ nonce2[i]); // XOR
        }
        return result;
    }

    /**  Generate Keys Section **/
    public KeyPair generateKeyPair() throws Exception{
        try {
            // Initialize a KeyPairGenerator with "ECC" algorithm, and set a key size
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            // Generate KeyPairSHA
            KeyPair keypair = keyPairGenerator.generateKeyPair();

            return keypair;

        } catch (NoSuchAlgorithmException e){

            e.printStackTrace();
            return null;
        }
    }

    /**  Generate Integrity Protection Schemes Section **/
    // Convert Byte variables to hexadecimal
    // Reference: https://www.baeldung.com/sha-256-hashing-java
    private String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public SecretKey generateMasterKey(byte[] nonce1, byte[] nonce2) throws Exception {
        // Xor operation for nonce1 and nonce2
        byte[] combinedNonce = xor(nonce1, nonce2);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // PBEKeySpec: The second parameter is the salt, here we use the XOR result
        // The third parameter is the number of iterations and the fourth parameter is the length of the generated key
        KeySpec spec = new PBEKeySpec(null, combinedNonce, 65536, 256);
        SecretKey key = skf.generateSecret(spec);

        return key;
    }

    public SecretKey[] deriveSessionKeys(byte[] masterKeyBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        // Define the labels used for key derivation
        byte[] encryptionLabelClient = "encryption_client".getBytes();
        byte[] authenticationLabelClient = "authentication_client".getBytes();
        byte[] encryptionLabelServer = "encryption_server".getBytes();
        byte[] authenticationLabelServer = "authentication_server".getBytes();

        // Initialize the HMAC algorithm
        SecretKey masterKey = new SecretKeySpec(masterKeyBytes, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(masterKey);

        // Generate four keys
        SecretKey[] sessionKeys = new SecretKey[4];
        sessionKeys[0] = new SecretKeySpec(mac.doFinal(encryptionLabelClient), "AES");
        sessionKeys[1] = new SecretKeySpec(mac.doFinal(authenticationLabelClient), "HmacSHA256");
        sessionKeys[2] = new SecretKeySpec(mac.doFinal(encryptionLabelServer), "AES");
        sessionKeys[3] = new SecretKeySpec(mac.doFinal(authenticationLabelServer), "HmacSHA256");

        return sessionKeys;
    }

    // 1. Integrity Protection Algorithm - SHA2
    public String SHA2(String text){

        try{
            // Initialize the hash algorithm
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            byte[] hashedText = digest.digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            return bytesToHex(hashedText);

        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        }
    }

    // 2. Integrity Protection Algorithm - SHA3
    public String SHA3(String text){

        try{
            // Initialize the hash algorithm
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedText = digest.digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return bytesToHex(hashedText);

        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        }
    }
    public byte[] SHA3_byte(byte[] data) {
        try {
            // Initialize the hash algorithm
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Hash the data
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    // 3. Integrity Protection Algorithm - HMAC
    public byte[] serializeData(Object... parts) throws IOException, CertificateEncodingException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

        // Serialize each part of the data
        for (Object part : parts) {
            if (part instanceof String) {
                objectOutputStream.writeUTF((String) part);
            } else if (part instanceof byte[]) {
                objectOutputStream.write((byte[]) part);
            } else if (part instanceof String[]) {
                // Handle serialization of String array
                objectOutputStream.writeObject(part);
            } else if (part instanceof X509Certificate) {
                objectOutputStream.write(((X509Certificate) part).getEncoded());
            } else {
                throw new IllegalArgumentException("Unsupported data type: " + part.getClass());
            }
        }

        objectOutputStream.flush();
        return outputStream.toByteArray();
    }

    public String HMAC(byte[] data, SecretKey secretKey) {
        try {
            // Get an instance of the HMAC algorithm
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);

            // Encrypt the Hashed text
            byte[] hmacBytes = mac.doFinal(data);
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (Exception e) {
            throw new RuntimeException("Fail to calculate HMAC", e);
        }
    }

    public String calculateHmacForMessages(Object[] clientMessages, Object[] serverMessages, SecretKey secretKey, boolean isClient) {
        try {
            // Serialize client and server messages
            byte[] clientData = serializeData(clientMessages);
            byte[] serverData = serializeData(serverMessages);

            // Splice client and server data and append "CLIENT" or "SERVER".
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(clientData);
            byteArrayOutputStream.write(serverData);
            byteArrayOutputStream.write(isClient ? "CLIENT".getBytes() : "SERVER".getBytes());

            // Calculate and return HMAC
            return HMAC(byteArrayOutputStream.toByteArray(), secretKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate HMAC for messages", e);
        }
    }

    /**  Generate Encryption Algorithms Section **/
    // 0. RSA encryption algorithm
    public byte[] encryptRSA(byte[] plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    public byte[] decryptRSA(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    // 1. Encryption Algorithm - 3DES_CBC
    public byte[] encryptTripleDes_single(byte[] plaintext, SecretKey secretKey) throws Exception {

        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");

        // initialize the randomized IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParam);

        // Encode the plaintext
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] ciphertextWithIv = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ciphertextWithIv, 0, iv.length);
        System.arraycopy(ciphertext, 0, ciphertextWithIv, iv.length, ciphertext.length);

        return ciphertextWithIv;
    }
    public byte[] decryptTripleDes_single(byte[] ciphertextWithIv, SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        System.arraycopy(ciphertextWithIv, 0, iv, 0, iv.length);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParam);

        // Only decrypt the actual ciphertext part without IV
        byte[] ciphertextWithoutIv = new byte[ciphertextWithIv.length - iv.length];
        System.arraycopy(ciphertextWithIv, iv.length, ciphertextWithoutIv, 0, ciphertextWithoutIv.length);

        // Decode the plaintext
        byte[] plaintext = cipher.doFinal(ciphertextWithoutIv);

        return plaintext;
    }

    // 2. Encryption Algorithm - AES
    public byte[] encryptAES(byte[] plaintext, SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // initialize the randomized IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParam);

        // Encode the plaintext
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] ciphertextWithIv = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ciphertextWithIv, 0, iv.length);
        System.arraycopy(ciphertext, 0, ciphertextWithIv, iv.length, ciphertext.length);

        return ciphertextWithIv;
    }
    public byte[] decryptAES(byte[] ciphertextWithIv, SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        System.arraycopy(ciphertextWithIv, 0, iv, 0, iv.length);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParam);

        // Only decrypt the actual ciphertext part without IV
        byte[] ciphertextWithoutIv = new byte[ciphertextWithIv.length - iv.length];
        System.arraycopy(ciphertextWithIv, iv.length, ciphertextWithoutIv, 0, ciphertextWithoutIv.length);

        // Decode the plaintext
        byte[] plaintext = cipher.doFinal(ciphertextWithoutIv);

        return plaintext;
    }

    // 3. Encryption Algorithm - ChaCha20
    public byte[] encryptChaCha20(byte[] plaintext, SecretKey secretKey) throws Exception{

        // Generate nonce with 12-byte (96 bits)
        byte[] nonce = generateNonce(96);

        // Initialize the parameters of ChaCha20
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec parameterSpec = new ChaCha20ParameterSpec(nonce, 1);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // Apply encryption
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] ciphertextWithNonce = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, ciphertextWithNonce, 0, nonce.length);
        System.arraycopy(ciphertext, 0, ciphertextWithNonce, nonce.length, ciphertext.length);

        return ciphertextWithNonce;
    }
    public byte[] decryptChaCha20(byte[] ciphertextWithNonce, SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance("ChaCha20");
        byte[] nonce = new byte[12];
        System.arraycopy(ciphertextWithNonce, 0, nonce, 0, nonce.length);

        ChaCha20ParameterSpec nonceParam = new ChaCha20ParameterSpec(nonce, 1);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, nonceParam);

        // Only decrypt the actual ciphertext part without nonce
        byte[] ciphertextWithoutNonce = new byte[ciphertextWithNonce.length - nonce.length];
        System.arraycopy(ciphertextWithNonce, nonce.length, ciphertextWithoutNonce, 0, ciphertextWithoutNonce.length);

        // Decode the plaintext
        byte[] plaintext = cipher.doFinal(ciphertextWithoutNonce);

        return plaintext;
    }

//    public static void main(String[] args) {
//        try {
//            mySSLUtils utils = new mySSLUtils();
//
//            // Generate key pairs for the certificate
//            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//            keyGen.initialize(2048, new SecureRandom());
//            KeyPair keyPair = keyGen.generateKeyPair();
//
//            X509Certificate cert = utils.certificateGenerator("Test User", keyPair.getPublic(), keyPair.getPrivate());
//
//            System.out.println(cert.toString());
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }

}

