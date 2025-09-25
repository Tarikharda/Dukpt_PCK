package org.example.utils;


import java.math.BigInteger;

public class Converter {


    //Decimal to Hex ----------------------------------
    private static final int sizeOfIntInHalfBytes = 5;
    private static final int numberOfBitsInAHalfByte = 4;
    private static final int halfByte = 0x0F;
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String decimalToHex(int dec) {
        StringBuilder hexBuilder = new StringBuilder(sizeOfIntInHalfBytes);
        hexBuilder.setLength(sizeOfIntInHalfBytes);
        for (int i = sizeOfIntInHalfBytes - 1; i >= 0; --i) {
            int j = dec & halfByte;
            hexBuilder.setCharAt(i, HEX_ARRAY[j]);
            dec >>= numberOfBitsInAHalfByte;
        }
        return hexBuilder.toString();
    }

    //Hex to Decimal ----------------------------------
    public static int hexToDecimal(String hex) {
        int decimalValue = 0;
        int base = 1;

        for (int i = hex.length() - 1; i >= 0; i--) {
            char hexChar = hex.charAt(i);
            int hexDigit;

            if (hexChar >= '0' && hexChar <= '9') {
                hexDigit = hexChar - '0';
            } else if (hexChar >= 'A' && hexChar <= 'F') {
                hexDigit = hexChar - 'A' + 10;
            } else {
                throw new IllegalArgumentException("Invalid hexadecimal character: " + hexChar);
            }

            decimalValue += hexDigit * base;
            base *= 16;
        }
        return decimalValue;
    }

    //Server Function -----------------------------------
    public static byte[] getByteDESKey(String DESkey) {
        byte[] DESkeyHex = hexStringToByteArray_2(DESkey);

        byte[] key = new byte[24];

        if (DESkeyHex.length == 8) {
            System.arraycopy(DESkeyHex, 0, key, 0, 8);
            System.arraycopy(DESkeyHex, 0, key, 8, 8);
            System.arraycopy(DESkeyHex, 0, key, 16, 8);

        } else if (DESkeyHex.length == 16) {
            System.arraycopy(DESkeyHex, 0, key, 0, 16);
            System.arraycopy(DESkeyHex, 0, key, 16, 8);

        } else if (DESkeyHex.length == 24) {
            System.arraycopy(DESkeyHex, 0, key, 0, 24);
        }

        return key;
    }

    /**
     * <p>Converts a byte array into a hexadecimal string (Big-Endian).
     *
     * @return A representation of a hexadecimal number without any leading qualifiers such as "0x" or "x".
     */
    public static String byteArrayToHexString_2(byte[] b) {

        BigInteger bi = new BigInteger(1, b);
        return String.format("%0" + (b.length << 1) + "X", bi);

    }

    /**
     * <p>Converts a hexadecimal String into a byte array (Big-Endian).
     *
     * @param s A representation of a hexadecimal number without any leading qualifiers such as "0x" or "x".
     */
    public static byte[] hexStringToByteArray_2(String s) {

        if (s.length() % 2 != 0 || !s.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("Invalid hex string");
        }

        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String asciiToHex(String fieldTmp) {
        StringBuilder hex = new StringBuilder();

        for (int i=0; i < fieldTmp.length(); i++) {
            hex.append( String.format("%02X", (int)fieldTmp.charAt(i)));
        }
        return hex.toString();

    }

    public static String hexToAscii(String hex) {
        StringBuilder ascii = new StringBuilder();

        for (int i = 0; i < hex.length(); i += 2) {
            String hexPair = hex.substring(i, i + 2);
            char ch = (char) Integer.parseInt(hexPair, 16);
            ascii.append(ch);
        }

        return ascii.toString();
    }
}
