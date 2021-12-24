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

    public void displayWelcome() {
        String message = "##################################################\n" +
                         "\tAES Encryption/Decryption program\n" +
                         "\t\tby Kevin Silvester\n" +
                         "##################################################\n";
        System.out.println(message);
    }

    public void displayMainMenu() {
        final String MENU = "\n*** MAIN MENU OPTIONS ***\n" +
                            "  1. Encrypt a file\n" +
                            "  2. Decrypt a file\n" +
                            "  3. Exit program";

        final int ENCRYPT = 1,
                  DECRYPT = 2,
                  EXIT    = 3;

        int option = 0;
        String input = null;

        System.out.println(MENU);

        do {
            try {
                System.out.print("\nEnter Option[1 - 3]: ");
                input = KB.next();
                option = Integer.parseInt(input);

                switch (option) {
                    case ENCRYPT:
                        displayEncryptionMenu();
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

    public void displayEncryptionMenu() {
        System.out.print("\nEnter the file name: ");
        String fileName = KB.next();

        if (!cipher.checkIfFileExists(fileName))
            System.out.println("\nError!\nFile Not Found.\n");
        else {
            String secretKey = masterKey.generateMasterKey();
            String plaintext = cipher.loadPlaintext(fileName);

            String encryptedPlaintext = cipher.encryptPlaintext(plaintext, secretKey);
            System.out.println(encryptedPlaintext);
        }
    }
}
