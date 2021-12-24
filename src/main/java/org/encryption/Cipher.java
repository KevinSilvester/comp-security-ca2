package org.encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

public class Cipher {
    private static final String KEY_SPEC_TYPE = "AES";
    private static final String CYPHER_TYPE = "AES/CBC/PKCS5Padding";

    public Cipher() {}

    public boolean checkIfFileExists(String fileName) {
        return new File(fileName).exists();
    }

    public String loadPlaintext(String fileName) {
        // https://stackoverflow.com/questions/14169661/read-complete-file-without-using-loop-in-java
        try { return new String(Files.readAllBytes(Paths.get(fileName))); }
        catch (IOException e ) { e.printStackTrace(); }
        return null;
    }

    public String encryptPlaintext(String plaintext, String base64Key) {
        byte[] decodedKeyBytes = Base64.getDecoder().decode(base64Key);
        SecretKey key = new SecretKeySpec(decodedKeyBytes, KEY_SPEC_TYPE);

        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CYPHER_TYPE);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
            byte[] ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(ivBytes)
                    + "|"
                    + Base64.getEncoder().encodeToString(ciphertext);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidParameterSpecException e) {
            e.printStackTrace();
        }
        return null;
    }
}
