package org.example.utils.security.dukpt;

import org.example.utils.security.KeyStoreUtil;

public final class DukptDK {

    private String TAG = "DukptDK";
    private String KSI, IPEK, KSN;
    private KeyStoreUtil keyStoreUtil;
    private final int MAX_COUNTER = 1048575;
    public String currentDerivedKey = "";
    public static String PIN_DERIVED_KEY = "";
    public static String DATA_DERIVED_KEY = "";
    public static String MAC_DERIVED_KEY = "";

    // Simulate persistent storage with simple variables
    private String ENCRYPTED_KEY = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"; // Example
    private String KSI_KEY = "0123456789";
    private String KSN_KEY = "";

    public DukptDK() throws Exception {
        keyStoreUtil = new KeyStoreUtil();
        this.setIPEK();
        this.setKSI();

        if (getKSN() != null && getKSN().startsWith("FFFFF", 10)) {
            throw new Exception("Cannot Increment KSN. Request new IPEK and reset the counter.");
        } else {
            this.setKSN();
        }
        System.out.println(TAG + " - Current KSN : " + getKSN());
    }

    private void setIPEK() {
        try {
            keyStoreUtil.generateRSAKey("RSA_KEYSTORE");
            byte[] encryptData = hexStringToByteArray(ENCRYPTED_KEY);
            byte[] decryptData = keyStoreUtil.decrypt("RSA_KEYSTORE", encryptData);
            String hexDecryptData = byteArrayToHexString(decryptData);
            this.IPEK = hexDecryptData.substring(8, 40);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String getIPEK() {
        System.out.println(TAG + " - IPEK : " + this.IPEK);
        return this.IPEK;
    }

    private String getSharedKSN() {
        return KSN_KEY;
    }

    private void setSharedKSN(String ksn) {
        KSN_KEY = ksn;
    }

    private void setKSI() {
        try {
            byte[] decryptedKSI = keyStoreUtil.decrypt("RSA_KEYSTORE", hexStringToByteArray(KSI_KEY));
            this.KSI = new String(decryptedKSI);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getKSI() {
        return this.KSI;
    }

    private void setKSN() {
        String preKSN = getSharedKSN();
        System.out.println(TAG + " - SetKSN : " + preKSN);
        if (preKSN == null || preKSN.isEmpty()) {
            System.out.println(TAG + " - PreKSN empty");
            this.KSN = getKSI() + "00000";
        } else {
            this.KSN = preKSN;
        }
    }

    public String getKSN() {
        System.out.println(TAG + " - KSN : " + this.KSN);
        return this.KSN;
    }

    public void incrementKSN() {
        String currentKSN = incrementKSN(this.KSN);
        setSharedKSN(currentKSN);
    }

    public String encryptByDerivedKey(Dukpt.KeyType keyType, String... input) throws Exception {
        byte[] ipek = hexStringToByteArray(getIPEK());
        byte[] ksn = hexStringToByteArray(getKSN());
        byte[] derivedKey = Dukpt.computeKey(ipek, ksn, keyType);
        String hexDerivedKey = byteArrayToHexString(derivedKey);
        System.out.println(TAG + " - Derived Key : " + hexDerivedKey);

        String encryptedKey = "";

        if (keyType == Dukpt.KeyType.PIN) {
            String formatedPinblock = createFormat0PinBlock(input[0], input[1]);
            System.out.println(TAG + " - Formated PIN input : " + formatedPinblock);
            encryptedKey = keyStoreUtil.encrypt3DES(hexDerivedKey, formatedPinblock);
            PIN_DERIVED_KEY = encryptedKey;
        } else if (keyType == Dukpt.KeyType.DATA) {
            String paddedDATAinput = keyStoreUtil.padHexMessage(input[0]);
            System.out.println(TAG + " - Padded Data input : " + paddedDATAinput);
            String expendedKey = calculeDataDerivedKey(hexDerivedKey);
            this.currentDerivedKey = expendedKey;
            encryptedKey = keyStoreUtil.encrypt3DES(expendedKey, paddedDATAinput);
            DATA_DERIVED_KEY = expendedKey;
        } else if (keyType == Dukpt.KeyType.MAC) {
            String paddedMacInput = keyStoreUtil.padHexMessage(input[0]);
            encryptedKey = keyStoreUtil.encryptISO9797Alg3Mac(hexDerivedKey, paddedMacInput);
            MAC_DERIVED_KEY = encryptedKey;
        }

        System.out.println(TAG + " - Encrypted Input by DerivedKey : " + encryptedKey);
        return encryptedKey;
    }

    public String generateDerivedKey(String _ksn, Dukpt.KeyType keyType) throws Exception {
        byte[] ipek = hexStringToByteArray(getIPEK());
        byte[] ksn = hexStringToByteArray(_ksn);
        byte[] derivedKey;
        String hexDerivedKey = null;

        if (keyType == Dukpt.KeyType.DATA) {
            derivedKey = Dukpt.computeKey(ipek, ksn, Dukpt.KeyType.DATA);
            hexDerivedKey = byteArrayToHexString(derivedKey);
            return calculeDataDerivedKey(hexDerivedKey);
        } else if (keyType == Dukpt.KeyType.MAC) {
            derivedKey = Dukpt.computeKey(ipek, ksn, Dukpt.KeyType.MAC);
            return byteArrayToHexString(derivedKey);
        }

        return null;
    }

    public String encryptDataByKsn(String ksn, String input, Dukpt.KeyType keyType) throws Exception {
        String derivedKey = generateDerivedKey(ksn, keyType);
        String paddedInput = keyStoreUtil.padHexMessage(input);

        if (keyType == Dukpt.KeyType.DATA) {
            String encryptedInput = keyStoreUtil.encrypt3DES(derivedKey, paddedInput);
            return KeyStoreUtil.addEncryptionTag(encryptedInput, "V1");
        } else if (keyType == Dukpt.KeyType.MAC) {
            return keyStoreUtil.encryptISO9797Alg3Mac(derivedKey, paddedInput);
        }
        return null;
    }

    public String decryptDataByKsn(String ksn, String input, Dukpt.KeyType keyType) throws Exception {
        if (isDataEncrypted(input)) {
            String derivedKey = generateDerivedKey(ksn, keyType);
            input = KeyStoreUtil.removeEncryptionTag(input);
            String decrypted = keyStoreUtil.decrypt3DES(derivedKey, input);
            return keyStoreUtil.removeHexPadding(decrypted);
        }
        return input;
    }

    public String decryptByDerivedKey(String hexDerivedKey, String input) throws Exception {
        input = KeyStoreUtil.removeEncryptionTag(input);
        String decrypted = keyStoreUtil.decrypt3DES(hexDerivedKey, input);
        return keyStoreUtil.removeHexPadding(decrypted);
    }

    private String createFormat0PinBlock(String pin, String pan) {
        String pinBlockString = "0" + pin.length() + pin;
        while (pinBlockString.length() < 16) {
            pinBlockString += "F";
        }
        String panPart = pan.substring(pan.length() - 13, pan.length() - 1);
        byte[] pinBlock = hexStringToByteArray(pinBlockString);
        byte[] panBlock = hexStringToByteArray("0000" + panPart);

        byte[] finalPinBlock = new byte[8];
        for (int i = 0; i < 8; i++) {
            finalPinBlock[i] = (byte) (pinBlock[i] ^ panBlock[i]);
        }

        String hexFinalPinBlock = byteArrayToHexString(finalPinBlock);
        return hexFinalPinBlock + hexFinalPinBlock;
    }

    private String calculeDataDerivedKey(String key) throws Exception {
        String left = key.substring(0, key.length() / 2);
        String right = key.substring(key.length() / 2);
        String the24key = key + left;
        String encryptLeft = keyStoreUtil.encrypt3DES(the24key, left);
        String encryptRight = keyStoreUtil.encrypt3DES(the24key, right);
        return encryptLeft + encryptRight;
    }

    public static String incrementKSN(String ksn) {
        String ksi = ksn.substring(0, 10);
        String pedId = ksn.substring(10, 15);
        String tc = ksn.substring(15);

        int tcValue = Integer.parseInt(tc, 16);
        tcValue++;
        tc = String.format("%05X", tcValue & 0x1FFFFF);
        return ksi + pedId + tc;
    }

    public String macConcatenation(String... args) {
        StringBuilder sb = new StringBuilder();
        for (String arg : args) {
            if (arg != null && !arg.isEmpty() && !arg.equals("null"))
                sb.append(arg);
        }
        return sb.toString();
    }

    public boolean isDataEncrypted(String data) {
        return data.startsWith("@@V1@@");
    }

    // Simple helper methods for testing
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
