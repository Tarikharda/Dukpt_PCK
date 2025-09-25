package org.example;

import org.example.utils.security.RSAKeyUtil;

import java.security.interfaces.RSAPublicKey;


public class Main {
    public static void main(String[] args) throws Exception {
        RSAKeyUtil util = new RSAKeyUtil();
        util.generateRSAKey();

        String message = "Test DUKPT IPEK";
        String encrypted = util.encrypt(message);
        System.out.println("Encrypted (hex): " + encrypted);

        String decrypted = util.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);

        String publicHex = util.getPublicKeyDERHex();
        System.out.println("Public Key Der  Hex: " + publicHex);

    }
}