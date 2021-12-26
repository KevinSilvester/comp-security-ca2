package org.encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

public class AESCipher {
    // Configuration values
    private static final String KEY_SPEC_TYPE   = "AES";
    private static final String CIPHER_TYPE     = "AES/CBC/PKCS5Padding";
    private static final String CIPHERTEXT_OUT  = "ciphertext.txt";
    private static final String PLAINTEXT_OUT   = "plaintext.txt";
    public static final int BITS_PER_BYTE   = 8;
    public static final int KEY_BITS_SMALL  = 128;
    public static final int KEY_BITS_MEDIUM = 192;
    public static final int KEY_BITS_LARGE  = 256;

    /**
     * Checks if the key is of a valid size for the AES process
     * @param key The secret key
     * @return True if the key is of a valid size
     */
    public static boolean isValidKeySize(byte[] key) {
        int keyLengthBits = key.length * BITS_PER_BYTE;

        return keyLengthBits == KEY_BITS_SMALL
                || keyLengthBits == KEY_BITS_MEDIUM
                || keyLengthBits == KEY_BITS_LARGE;
    }

    /**
     * Checks if a file exists
     * @param fileName The file to check for
     * @return True if the file does exist, else false
     */
    public boolean fileExists(String fileName) {
        return new File(fileName).exists();
    }

    /**
     * Reads all line from a text and returns it as string
     * @param fileName Name of the text file
     * @return The content of the file
     */
    public String loadTextFile(String fileName) {
        // https://stackoverflow.com/questions/14169661/read-complete-file-without-using-loop-in-java
        try { return new String(Files.readAllBytes(Paths.get(fileName))); }
        catch (IOException e ) { return null; }
    }

    /**
     * Encrypts the plaintext with key provided using AES256-CBC (configurable in CIPHER_TYPE).
     *
     * Note the returned string bundles the initialization
     * vector and ciphertext, separated by a | character
     * 
     * @param plaintext The plaintext to be encrypted
     * @param base64Key The key that is to be used to encrypt the plaintext
     * @return The encrypted plaintext with initialization vector.
     */
    public String encrypt(String plaintext, String base64Key) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        SecretKey key = new SecretKeySpec(decodedKey, KEY_SPEC_TYPE);

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] ivBytes      = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
            byte[] encPlaintext = cipher.doFinal(plaintext.getBytes());
            String ciphertext   = Base64.getEncoder().encodeToString(ivBytes)
                                + "|"
                                + Base64.getEncoder().encodeToString(encPlaintext);

            PrintWriter writer = new PrintWriter(new FileWriter(CIPHERTEXT_OUT), false);
            writer.print(ciphertext);
            writer.close();
            return ciphertext;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException | IllegalArgumentException
                | InvalidParameterSpecException | IOException  e) {
            return null;
        }
    }

    public String decrypt(String ciphertext, String base64Key) {
        try {
            String[] ciphertextParts = ciphertext.split("\\|");
            byte[] decodedKeyBytes   = Base64.getDecoder().decode(base64Key);
            byte[] ivBytes           = Base64.getDecoder().decode(ciphertextParts[0]);
            byte[] ciphertextBytes   = Base64.getDecoder().decode(ciphertextParts[1]);

            if (!AESCipher.isValidKeySize(decodedKeyBytes)) return null;

            SecretKey secret    = new SecretKeySpec(decodedKeyBytes, KEY_SPEC_TYPE);
            Cipher cipher       = Cipher.getInstance(CIPHER_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
            String plaintext    = new String(cipher.doFinal(ciphertextBytes));
            PrintWriter writer  = new PrintWriter(new FileWriter(PLAINTEXT_OUT), false);

            writer.print(plaintext);
            writer.close();

            return plaintext;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException
                | IOException | IllegalArgumentException e) {
            return null;
        }
    }
}
