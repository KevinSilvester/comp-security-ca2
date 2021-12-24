package org.encryption;

import java.io.Console;
import java.util.InputMismatchException;
import java.util.Scanner;

/**
 * TODO
 *  - Display option to encrypt/decrypt/quit
 *  - Input validation
 *  - loop back to menu if not quiting
 */

public class Menu {
    private static final Scanner KB = new Scanner(System.in);
    private static final Console CONSOLE = System.console();
    private static Cipher cipher = null;
    private static MasterKey masterKey = null;

    public Menu(Cipher cipher, MasterKey masterKey) {
        Menu.cipher = cipher;
        Menu.masterKey = masterKey;
    }

    public void greeting() {
        String message = "##################################################\n" +
                         "\tAES Encryption/Decryption program\n" +
                         "\t\tby Kevin Silvester\n" +
                         "##################################################\n";
        System.out.println(message);
    }

    public void mainMenu() {
        final String MENU = "\n\n*** MAIN MENU OPTIONS ***\n" +
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
                        System.out.println("");
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

    public void encryptionMenu() {
        System.out.print("\nEnter the file name: ");
        String fileName = KB.next();

        if (!cipher.checkIfFileExists(fileName))
            System.out.println("\nError!\nFile Not Found.\n");
        else {
            String secretKey = masterKey.generateMasterKey();
            String plaintext = cipher.loadPlaintext(fileName);
            String ciphertext = cipher.encryptPlaintext(plaintext, secretKey);

            System.out.println("\nEncryption Key: ");
            System.out.println(secretKey);

            System.out.println("\nOriginal Plaintext: ");
            System.out.println(plaintext);

            System.out.println("\nCiphertext: ");
            System.out.println(ciphertext);

            keySaveMenu(secretKey);
        }
    }

    public void keySaveMenu(String base64key) {
        final String MENU = "\n\n*** KEY SAVING OPTION ***\n" +
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
                        masterKey.saveMasterKey(base64key, SaveOptions.FILE);
                        System.out.println("\n<<Key saved to text file>>");
                        break;
                    case KEY_STORE:
                        masterKey.saveMasterKey(base64key, SaveOptions.KEY_STORE);
                        System.out.println("\n<<Key saved to key store>>");
                        break;
                    case BOTH:
                        masterKey.saveMasterKey(base64key, SaveOptions.BOTH);
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
}
