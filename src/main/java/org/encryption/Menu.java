package org.encryption;

import java.io.Console;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.Scanner;
import java.util.regex.Pattern;

public class Menu {
    private static final Scanner KB      = new Scanner(System.in);
    private static final Console CONSOLE = System.console();
    private static AESCipher AESCipher   = null;
    private static AESKey AESKey         = null;

    private static final Pattern JKS_REGEX = Pattern.compile("^.+\\.jks$");
    private static final Pattern TXT_REGEX = Pattern.compile("^.+\\.txt$");

    public Menu(AESCipher AESCipher, AESKey AESKey) {
        Menu.AESCipher = AESCipher;
        Menu.AESKey = AESKey;
    }

    public void greeting() {
        String message = "##################################################\n" +
                         "\tAES Encryption/Decryption program\n" +
                         "\t\tby Kevin Silvester\n" +
                         "##################################################\n";
        System.out.println(message);
    }

    public void mainMenu() {
        final String MENU = "\n\n*** MAIN MENU ***\n" +
                            "  1. Encrypt a file\n" +
                            "  2. Decrypt a file\n" +
                            "  3. Exit program";

        final int ENCRYPT = 1,
                  DECRYPT = 2,
                  EXIT    = 3;

        int option = 0;
        String input = null;

        do {
            try {
                System.out.println(MENU);
                System.out.print("\nEnter Option[1 - 3]: ");
                input = KB.next();
                option = Integer.parseInt(input);

                switch (option) {
                    case ENCRYPT:
                        encryptionMenu();
                        break;
                    case DECRYPT:
                        decryptionMenu();
                        break;
                    case EXIT:
                        System.out.println("\nExiting Program...");
                        break;
                    default:
                        System.out.print("\nInvalid option - please enter number in range\n");
                        break;
                }
            }
            catch (InputMismatchException | NumberFormatException e) {
                System.out.print("\nInvalid option - please enter number in range\n");
            }
        } while (option != EXIT);
    }

    private boolean isValidFile(FileTypes type, String fileName) {
        boolean res = false;
        switch (type) {
            case JKS:
                res = JKS_REGEX.matcher(fileName).find();
                break;
            case TXT:
                res = TXT_REGEX.matcher(fileName).find();
                break;
        }
        if (!res) System.out.println("\nError!\nPlease enter the right file type!");
        return res;
    }

    private void encryptionMenu() {
        String fileName = null;
        do {
            System.out.print("\nEnter the input file name: ");
            fileName = KB.next();
        } while (!isValidFile(FileTypes.TXT, fileName));

        if (!AESCipher.fileExists(fileName))
            System.out.println("\nError!\nFile Not Found.\n");
        else {
            String secretKey  = AESKey.generateMasterKey();
            String plaintext  = AESCipher.loadTextFile(fileName);
            String ciphertext = AESCipher.encrypt(plaintext, secretKey);

            System.out.println("\nEncryption Key:\n"     + secretKey);
            System.out.println("\nOriginal Plaintext:\n" + plaintext);
            System.out.println("\nCiphertext:\n"        + ciphertext);

            saveKeyMenu(secretKey);
        }
    }

    private void saveKeyMenu(String base64key) {
        final String MENU = "\n\n*** SAVE KEY MENU ***\n" +
                            "  1. Write encryption key to file keystore.txt\n" +
                            "  2. Write key in Java KeyStore\n" +
                            "  3. Write to both";

        final int FILE = 1,
                  KEY_STORE = 2,
                  BOTH = 3;

        int option = 0;
        String input = null;

        do {
            try {
                System.out.println(MENU);
                System.out.print("\nEnter Option[1 - 3]: ");
                input = KB.next();
                option = Integer.parseInt(input);

                switch (option) {
                    case FILE:
                        AESKey.saveMasterKey(base64key, SaveOptions.FILE);
                        System.out.println("\n<<Key saved to text file>>");
                        break;
                    case KEY_STORE:
                        AESKey.saveMasterKey(base64key, SaveOptions.KEY_STORE);
                        System.out.println("\n<<Key saved to key store>>");
                        break;
                    case BOTH:
                        AESKey.saveMasterKey(base64key, SaveOptions.BOTH);
                        System.out.println("\n<<Key saved to text file and key store>>");
                        break;
                    default:
                        System.out.print("\nInvalid option - please enter number in range\n");
                        break;
                }
            }
            catch (InputMismatchException | NumberFormatException e) {
                System.out.print("\nInvalid option - please enter number in range\n");
            }
        } while (option != FILE && option != KEY_STORE && option != BOTH);
    }



    private void decryptionMenu() {
        String fileName = null;
        do {
            System.out.print("\nEnter the name of the file with the encrypted message: ");
            fileName = KB.next();
        } while (!isValidFile(FileTypes.TXT, fileName));

        if (!AESCipher.fileExists(fileName))
            System.out.println("\nError!\nFile Not Found.\n");
        else {
            try {
                String decryptionKey = decryptionKeyMenu();
                String ciphertext    = AESCipher.loadTextFile(fileName);
                if (decryptionKey == null || ciphertext == null) throw new IllegalArgumentException();
                String plaintext = AESCipher.decrypt(ciphertext, decryptionKey);
                if (plaintext == null) throw new IllegalArgumentException();
                System.out.println("\nDecrypted ciphertext:\n" + plaintext);
            } catch (IllegalArgumentException e) {
                System.out.println("\nError!\nDecryption not possible!!\nPlease try again!\n");
            }
        }
    }

    private String decryptionKeyMenu() {
        final String MENU = "\n\n*** DECRYPTION KEY MENU ***\n" +
                            "  1. Enter the decryption key manually\n" +
                            "  2. Load the decryption key a text file\n" +
                            "  3. Load the decryption key from java key store (.jks file)";

        final int MANUAL    = 1,
                  FILE      = 2,
                  KEY_STORE = 3;

        int option = 0;
        String input = null;

        do {
            try {
                System.out.println(MENU);
                System.out.print("\nEnter Option[1 - 3]: ");
                input = KB.next();
                option = Integer.parseInt(input);

                switch (option) {
                    case MANUAL:
                        return manualKeyEntry();
                    case FILE:
                        return loadKeyFromFile();
                    case KEY_STORE:
                        return loadFromKeyStore();
                    default:
                        System.out.print("\nInvalid option - please enter number in range\n");
                        break;
                }
            }
            catch (InputMismatchException | NumberFormatException e) {
                System.out.print("\nInvalid option - please enter number in range\n");
            }
        } while (option != MANUAL && option != FILE && option != KEY_STORE);
        return null;
    }

    private String manualKeyEntry() {
        char[] key = CONSOLE.readPassword("\nEnter your decryption key: ");
        return new String(key);
    }

    private String loadKeyFromFile() {
        String fileName = null;
        do {
            System.out.print("\nEnter the name of the file with your decryption key (hint: keystore.txt): ");
            fileName = KB.next();
        } while (!isValidFile(FileTypes.TXT, fileName));
        if (!AESCipher.fileExists(fileName)) {
            System.out.println("\nError!\nFile Not Found.\n");
        }
        else {
            return AESCipher.loadTextFile(fileName);
        }
        return null;
    }

    private String loadFromKeyStore() {
        final String MENU = "\n\n*** LOAD KEY FROM KEYSTORE MENU ***\n" +
                            "  1. Load with default credentials\n" +
                            "  2. Manually enter credentials";

        final int DEFAULT = 1,
                  MANUAL  = 2;

        int option = 0;
        String input = null;

        do {
            try {
                System.out.println(MENU);
                System.out.print("\nEnter Option[1 - 2]: ");
                input = KB.next();
                option = Integer.parseInt(input);

                switch (option) {
                    case DEFAULT:
                        return AESKey.loadFromKeyStore(LoadOption.DEFAULT, null, null, null);
                    case MANUAL:
                        String fileName = null;
                        do {
                            System.out.print("\nEnter the keystore file name (hint: keystore.jks): ");
                            fileName = KB.next();
                        } while (!isValidFile(FileTypes.JKS, fileName));

                        if (!AESCipher.fileExists(fileName))
                            System.out.println("\nError!\nFile Not Found.\n");
                        else {
                            char[] password = CONSOLE.readPassword("\nEnter the password for the key store (hint: password): ");
                            System.out.print("\nEnter the alias for the decryption key (hint: secret-key): ");
                            String alias = KB.next();
                            return AESKey.loadFromKeyStore(LoadOption.MANUAL, fileName, password, alias);
                        }
                        break;
                    default:
                        System.out.print("\nInvalid option - please enter number in range\n");
                        break;
                }
            }
            catch (InputMismatchException | NumberFormatException e) {
                System.out.print("\nInvalid option - please enter number in range\n");
            }
        } while (option != DEFAULT && option != MANUAL);
        return null;
    }
}
