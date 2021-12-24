package org.encryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;

public class MasterKey {
    private static final String KEY_SPEC_TYPE = "AES";
    private static final String KEYSTORE_TYPE = "JCEKS";
    private static final String ENCRYPT_OUT   = "ciphertext.txt";
    private static final String DECRYPT_OUT   = "plaintext.txt";
    private static final String KEYSTORE_ENTRY_ALIAS = "masterKey";
    private static final String KEYSTORE_PATH = "keystore";
    private static final char[] KEYSTORE_PASSWORD = "not-a-password".toCharArray();
    private static final int    KEY_SIZE      = 256;

    // https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/#:~:text=AES%20is%20block%20cipher%20capable,and%20256%2Dbits%2C%20respectively.
    // https://stackoverflow.com/questions/18228579/how-to-create-a-secure-random-aes-key-in-java/18229498#18229498

    public String generateMasterKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(KEY_SPEC_TYPE);
            keyGen.init(KEY_SIZE);
            SecretKey tmp = keyGen.generateKey();
            SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), KEY_SPEC_TYPE);
            return Base64.getEncoder().encodeToString(key.getEncoded());
        }
        catch (NoSuchAlgorithmException e) {
//            throw new PasswordException(ERROR_BAD_ALGORITHM);
            e.printStackTrace();
        }
        return null;
    }

    private void saveToFile(String base64key) {
        File file = null;
        FileWriter fileWriter = null;
        PrintWriter writer = null;
        try {
//            file = new File(ENCRYPT_OUT);
//            fileWriter = new FileWriter(file);
            writer = new PrintWriter(new FileWriter(ENCRYPT_OUT), false);
            writer.println(base64key);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            assert writer != null;
            writer.close();
        }
    }

    private void saveToKeyStore(String base64Key) {
        // https://www.tutorialspoint.com/java_cryptography/java_cryptography_storing_keys.htm
        // https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html
        // https://stackoverflow.com/questions/11536848/keystore-type-which-one-to-use
        // https://stackoverflow.com/questions/21406884/storing-aes-secret-key-using-keystore-in-java
        try {
            KeyStore store = KeyStore.getInstance(KEYSTORE_TYPE);
            FileInputStream fis = null;

            try {
                fis = new FileInputStream(KEYSTORE_PATH);
                store.load(fis, KEYSTORE_PASSWORD);
            } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            } finally {
                assert fis != null;
                try { fis.close(); }
                catch (IOException e) { e.printStackTrace(); }
            }

            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(KEYSTORE_PASSWORD);
            byte[] decodedKeyBytes = Base64.getDecoder().decode(base64Key);
            SecretKey key = new SecretKeySpec(decodedKeyBytes, KEY_SPEC_TYPE);
            KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
            store.setEntry(KEYSTORE_ENTRY_ALIAS, keyEntry, protectionParam);
        }
        catch (KeyStoreException e) { e.printStackTrace(); }
    }

    public void saveMasterKey(String base64key, SaveOptions option) {
        switch (option) {
            case FILE:
                saveToFile(base64key);
                break;
            case KEY_STORE:
                saveToKeyStore(base64key);
                break;
            case BOTH:
                saveToKeyStore(base64key);
                saveToFile(base64key);
                break;
            default:
                break;
        }
    }
}