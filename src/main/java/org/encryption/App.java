package org.encryption;

public class App {
    private static Menu menu;

    private void init() {
        menu.greeting();
        menu.mainMenu();
    }

    public static void main(String[] args) {
        menu = new Menu(new AESCipher(), new AESKey());
        new App().init();
    }
}
