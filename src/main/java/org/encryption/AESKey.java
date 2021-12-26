package org.encryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.sql.SQLOutput;
import java.util.Base64;

public class AESKey {
    private static final String KEY_SPEC_TYPE = "AES";
    private static final String KEYSTORE_TYPE = "JCEKS";
    private static final String ENCRYPT_OUT   = "keystore.txt";
    private static final String DECRYPT_OUT   = "plaintext.txt";
    private static final String KEYSTORE_ENTRY_ALIAS = "secret-key";
    private static final String KEYSTORE_PATH = "keystore.jks";
    private static final char[] KEYSTORE_PASSWORD = "password".toCharArray();
    private static final int    KEY_SIZE      = 256;


    private void error(Exception e) {
        System.out.println(e.getMessage());
    }

    // https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/#:~:text=AES%20is%20block%20cipher%20capable,and%20256%2Dbits%2C%20respectively.
    // https://stackoverflow.com/questions/18228579/how-to-create-a-secure-random-aes-key-in-java/18229498#18229498
    public String generateMasterKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(KEY_SPEC_TYPE);
            keyGen.init(KEY_SIZE);
            SecretKey key = new SecretKeySpec(keyGen.generateKey().getEncoded(), KEY_SPEC_TYPE);;
            return Base64.getEncoder().encodeToString(key.getEncoded());
        }
        catch (NoSuchAlgorithmException e) {
            error(e);
        }
        return null;
    }

    private void saveToFile(String base64key) {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(ENCRYPT_OUT), false);
            writer.print(base64key);
            writer.close();
        }
        catch (IOException e) { error(e); }
    }

    private void saveToKeyStore(String base64Key) {
        // https://www.tutorialspoint.com/java_cryptography/java_cryptography_storing_keys.htm
        // https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html
        // https://stackoverflow.com/questions/11536848/keystore-type-which-one-to-use
        // https://stackoverflow.com/questions/21406884/storing-aes-secret-key-using-keystore-in-java
        // https://www.youtube.com/watch?v=NRHJ8R8Omx4&list=TLPQMjUxMjIwMjEBbFpGLUV4pw&index=3
        try {
            FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH);
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(null, KEYSTORE_PASSWORD);
            byte[] decodedKeyBytes = Base64.getDecoder().decode(base64Key);
            SecretKey key = new SecretKeySpec(decodedKeyBytes, KEY_SPEC_TYPE);
            KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(KEYSTORE_PASSWORD);
            ks.setEntry(KEYSTORE_ENTRY_ALIAS, keyEntry, protectionParam);
            ks.store(fos, KEYSTORE_PASSWORD);
            fos.close();
        } catch (IOException | CertificateException | KeyStoreException| NoSuchAlgorithmException e) {
            error(e);
        }
    }

    public String loadFromKeyStore(LoadOption option, String fileName, char[] password, String alias) {
        try {
            FileInputStream fis = null;
            KeyStore ks = null;
            switch (option) {
                case DEFAULT:
                    fis = new FileInputStream(KEYSTORE_PATH);
                    ks  = KeyStore.getInstance(KEYSTORE_TYPE);
                    ks.load(fis, KEYSTORE_PASSWORD);
                    if (ks.containsAlias(KEYSTORE_ENTRY_ALIAS)) {
                        SecretKey key = (SecretKey) ks.getKey(KEYSTORE_ENTRY_ALIAS, KEYSTORE_PASSWORD);
                        fis.close();
                        return Base64.getEncoder().encodeToString(key.getEncoded());
                    }
                case MANUAL:
                    fis = new FileInputStream(fileName);
                    ks  = KeyStore.getInstance(KEYSTORE_TYPE);
                    ks.load(fis, password);
                    if (ks.containsAlias(alias)) {
                        SecretKey key = (SecretKey) ks.getKey(alias, password);
                        fis.close();
                        return Base64.getEncoder().encodeToString(key.getEncoded());
                    }
            }
        }
        catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            error(e);
        }
        return null;
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
