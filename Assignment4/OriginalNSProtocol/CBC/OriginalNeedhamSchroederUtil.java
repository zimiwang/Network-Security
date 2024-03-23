package Assignment4.OriginalNSProtocol.CBC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.math.BigInteger;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

public class OriginalNeedhamSchroederUtil {

    public String bytesToHex1(byte[] bytes) {
        BigInteger number = new BigInteger(1, bytes);
        StringBuilder hexString = new StringBuilder(number.toString(16));

        while (hexString.length() < bytes.length * 2) {
            hexString.insert(0, '0');
        }

        return hexString.toString();
    }

    public byte[] incrementOneByte(byte[] input) {
        BigInteger number = new BigInteger(input);
        number = number.add(BigInteger.ONE);

        byte[] result = number.toByteArray();

        // Make sure the result array is the same size as the input array
        if (result.length > input.length) {
            // If the result array is longer than the input array, it is usually because the highest bit (sign bit) is 0 and the excess 0s need to be removed.
            byte[] trimmedResult = new byte[input.length];
            System.arraycopy(result, 1, trimmedResult, 0, input.length);
            return trimmedResult;
        } else if (result.length < input.length) {
            // If the result array is shorter than the input array, it is usually because the highest bit (the sign bit) has been increased by 1.
            byte[] paddedResult = new byte[input.length];
            System.arraycopy(result, 0, paddedResult, input.length - result.length, result.length);
            return paddedResult;
        }

        return result;
    }

    public byte[] decrementOneByte(byte[] input){

        BigInteger number = new BigInteger(input);
        number = number.subtract(BigInteger.ONE);

        byte[] result = number.toByteArray();

        // Make sure the result array is the same size as the input array (BigInteger's toByteArray sometimes returns a larger array)
        if (result.length > input.length) {
            // If the result array is longer than the input array, it is usually because the highest bit (sign bit) is 0
            byte[] trimmedResult = new byte[input.length];
            System.arraycopy(result, 1, trimmedResult, 0, input.length);
            return trimmedResult;
        } else if (result.length < input.length) {
            // If the result array is shorter than the input array, it is usually because the highest bit (the sign bit) was subtracted
            byte[] paddedResult = new byte[input.length];
            System.arraycopy(result, 0, paddedResult, input.length - result.length, result.length);
            return paddedResult;
        }

        return result;
    }

    public byte[] generateChallenge(int num_bits){

        int num_bytes = num_bits/8;
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[num_bytes];
        secureRandom.nextBytes(nonce);

        return nonce;
    }

    public SecretKey generateSecretKey() throws Exception {

        // Generate a 3DES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        keyGenerator.init(168);
        SecretKey secretKey = keyGenerator.generateKey();

        return secretKey;
    }

    public byte[] encryptTripleDES(List<byte[]> parts, SecretKey secretKey) throws Exception {

        try{
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");

            // Initialize the IV
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[cipher.getBlockSize()];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParam = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParam);

            // Create a ByteArrayOutputStream to hold our length-prefixed parts
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            // Write each part with its length prefix
            for (byte[] part : parts) {

                outputStream.write(part.length);
                outputStream.write(part);
            }

            // Encrypt the combined parts
            byte[] ciphertext = cipher.doFinal(outputStream.toByteArray());

            // Combine IV and ciphertext
            byte[] ciphertextWithIv = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, ciphertextWithIv, 0, iv.length);
            System.arraycopy(ciphertext, 0, ciphertextWithIv, iv.length, ciphertext.length);

            return ciphertextWithIv;
        } catch (Exception e) {
            System.out.println("Failed to encrypt: " + e.getMessage());
            return null;
        }
    }

    public List<byte[]> decryptTripleDes(byte[] ciphertextWithIv, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        System.arraycopy(ciphertextWithIv, 0, iv, 0, iv.length);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParam);

        // Extract the actual ciphertext from the input parameter, removing the IV part
        byte[] ciphertextWithoutIv = new byte[ciphertextWithIv.length - iv.length];
        System.arraycopy(ciphertextWithIv, iv.length, ciphertextWithoutIv, 0, ciphertextWithoutIv.length);

        // Decrypt the ciphertext
        byte[] decrypted = cipher.doFinal(ciphertextWithoutIv);

        // Now extract each part using the length prefixes
        ByteArrayInputStream inputStream = new ByteArrayInputStream(decrypted);
        List<byte[]> parts = new ArrayList<>();

        while (inputStream.available() > 0) {
            int partLength = inputStream.read();
            byte[] part = inputStream.readNBytes(partLength);
            parts.add(part);
        }

        return parts;
    }

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
}
