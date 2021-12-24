package org.encryption;

public class App {
    private static Menu menu;

    private void init() {
        menu.displayWelcome();
        menu.displayMainMenu();
    }

    public static void main(String[] args) {
        App app = new App();
        MasterKey masterKey = new MasterKey();
        Cipher cipher = new Cipher();
        menu = new Menu(cipher, masterKey);

        app.init();
    }
}
