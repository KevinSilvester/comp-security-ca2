package org.encryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public class AESKey {
    // Configuration values
    private static final String KEY_SPEC_TYPE   = "AES";
    private static final String KEYSTORE_TYPE   = "JCEKS";
    private static final String KEYSTORE_ALIAS  = "secret-key";
    private static final String KEYSTORE_PATH   = "keystore.jceks";
    private static final char[] KEYSTORE_PASSWORD = "password".toCharArray();
    private static final String ENCRYPT_OUT     = "keystore.txt";
    private static final int    KEY_SIZE        = 256;

    /**
     * Generates master key for AES encryption process using KeyGenerator.
     * KeyGenerator uses default configuration values KEY_SPEC_TYPE and KEY_SIZE specified at the top.
     *
     * References:
     * @see <a href="https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/#:~:text=AES%20is%20block%20cipher%20capable,and%20256%2Dbits%2C%20respectively." >
     *          Encryption Example
     *      </a>
     * @see <a href="https://stackoverflow.com/questions/18228579/how-to-create-a-secure-random-aes-key-in-java/18229498#18229498" >
     *          KeyGenrator Example
     *      </a>
     *
     * @return The generated key encoded to base64 as a string.
     *         If the generation fails return null.
     */
    public String generateMasterKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(KEY_SPEC_TYPE);
            keyGen.init(KEY_SIZE);
            SecretKey key = new SecretKeySpec(keyGen.generateKey().getEncoded(), KEY_SPEC_TYPE);;
            return Base64.getEncoder().encodeToString(key.getEncoded());
        }
        catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Writes the key in base64 encoded format to a text file keystore.txt in the application root directory.
     * If write fails, an error message will be printed.
     * @param base64key Encoded key
     */
    private void saveToFile(String base64key) {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(ENCRYPT_OUT), false);
            writer.print(base64key);
            writer.close();
        }
        catch (IOException e) {
            System.out.println("\nError!\nFailed to write to file!");
        }
    }

    /**
     * Saves the encoded key to java keystore file keystore.jks in the application root directory.
     *
     * The keystore instance is of type 'JCEKS' (configurable in KEYSTORE_TYPE) as it is capable of storing
     * secret keys, and also enabled me to view the saved keys using 'keytools' in the command line.
     *
     * The keystore and the key entry are password protected (configurable in KEYSTORE_PASSWORD) with the entry
     * alias being 'secret-key' (configurable in KEYSTORE_ALIAS).
     *
     * If the process fails, and error message is displayed.
     *
     * @param base64Key Encoded key as string
     */
    private void saveToKeyStore(String base64Key) {
        try {
            // load the keystore
            FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH);
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(null, KEYSTORE_PASSWORD);

            // parse the base64key into a keystore secret key entry with password protection
            byte[] decodedKeyBytes = Base64.getDecoder().decode(base64Key);
            SecretKey key = new SecretKeySpec(decodedKeyBytes, KEY_SPEC_TYPE);
            KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(KEYSTORE_PASSWORD);

            // set the new entry and store to keystore.jceks and close the FileOutputStream
            ks.setEntry(KEYSTORE_ALIAS, keyEntry, protectionParam);
            ks.store(fos, KEYSTORE_PASSWORD);
            fos.close();
        } catch (IOException | CertificateException | KeyStoreException| NoSuchAlgorithmException e) {
            System.out.println("\nError!\nFailed to write to keystore!");
        }
    }

    /**
     * Retrieves the secret key stored in the keystore.
     * If the LoadOption is DEFAULT then the file name, password and entry alias will be default values used in the
     * {@link #saveToKeyStore(String)} method.
     *
     * If the value is MANUAL then the user defined file name, password and entry alias will be attempted. If the attempt
     * fails the method returns null.
     *
     * @param option {@link LoadOption} Enumerators to determine if the user wants to retrieve the key using the default
     *                                  credentials or their own credentials.
     * @param fileName The filename of the keystore
     * @param password The password for the keystore and key entry
     * @param alias The alias of th key entry
     *
     * @return The secret key encoded to base64.
     *         Or null if the retrieval fails.
     */
    public String loadFromKeyStore(LoadOption option, String fileName, char[] password, String alias) {
        try {
            FileInputStream fis = null;
            KeyStore ks = null;
            switch (option) {
                case DEFAULT:
                    fis = new FileInputStream(KEYSTORE_PATH);
                    ks  = KeyStore.getInstance(KEYSTORE_TYPE);
                    ks.load(fis, KEYSTORE_PASSWORD);
                    if (ks.containsAlias(KEYSTORE_ALIAS)) {
                        SecretKey key = (SecretKey) ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
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
            return null;
        }
        return null;
    }

    /**
     * Saves the key to the use defined location.
     * @param base64key The secret key encoded to bas64
     * @param option {@link SaveOptions} Enumerator representing the options the user has when saving the key.
     */
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
