package org.example.utils.security;

import org.example.utils.Converter;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * DukptManager - testing/demo-only DUKPT helper.
 *
 * - Hardcoded IPEK / initial KSN for testing
 * - Registers for derived keys (PIN, DATA, MAC)
 * - KSN 21-bit counter increment
 * - Derive function (TEST implementation) producing 16-byte derived key (hex)
 * - 3DES encrypt/decrypt helpers using derived key
 *
 * Replace computeDerivedKeyWithStandardAlgorithm(...) with a proper DUKPT algorithm
 * (ANSI X9.24 / your HSM vendor reference) for production.
 */
public class DukptManager {

    // ---------------------
    // Config / Hardcoded - replace for tests or inject from server
    // ---------------------
    // IPEK (16 bytes hex string) - in production this comes encrypted from server/HSM and then unwrapped securely
    private byte[] ipek = Converter.hexStringToByteArray_2("0123456789ABCDEFFEDCBA9876543210"); // example 16 bytes hex

    // KSI or device-specific id part (10 hex chars as in your old code). We'll treat KSI as the left 10 hex chars of KSN when needed.
    private String hardCodedKSI = "FFFFB2D988004C0"; // example (15 hex chars)
    // Current KSN (10 bytes hex string) - 20 hex chars
    private String ksn = hardCodedKSI + "00000"; // baseline: KSI + 5 hex chars counter

    // ---------------------
    // Key registers (hex strings) - stores last used derived keys
    // ---------------------
    public String pinDerivedKeyHex = null;   // stores the encrypted/presentable derived key for PIN
    public String dataDerivedKeyHex = null;  // stores the derived key used for DATA
    public String macDerivedKeyHex = null;   // stores the derived key used for MAC

    // current derived key in hex (last generated)
    public String currentDerivedKeyHex = null;

    // ---------------------
    // Variant masks (16-bytes hex) - adjust to HSM/your specs
    // These masks are XORed with the derived key to get the final variant key.
    // For real world use these must exactly match your HSM vendor docs.
    // ---------------------
    // NOTE: These are placeholders. Replace with vendor-provided variant masks.
    private static final String PIN_VARIANT_MASK_HEX  = "00000000000000FF00000000000000FF";
    private static final String DATA_VARIANT_MASK_HEX = "000000000000FF00000000000000FF00";
    private static final String MAC_VARIANT_MASK_HEX  = "00000000000000FF000000000000FFFF";

    // ---------------------
    // Constructor
    // ---------------------
    public DukptManager(String initialIpekHex, String initialKsnHex) {
        if (initialIpekHex != null && !initialIpekHex.isEmpty()) {
            this.ipek = Converter.hexStringToByteArray_2(initialIpekHex);
        }
        if (initialKsnHex != null && !initialKsnHex.isEmpty()) {
            this.ksn = initialKsnHex;
        }
    }

    // ---------------------
    // KSN helpers
    // KSN format assumed: 10 bytes = 20 hex chars. Counter is low 21 bits (last 5 hex chars = 20 bits, but actually 21 bits across boundaries).
    // This implementation treats the counter as the last 5 hex characters (20bits) + 1 extra bit handled correctly by using BigInteger on full hex string.
    // ---------------------
    public String getKSN() {
        return ksn;
    }

    /**
     * Increment the 21-bit transaction counter embedded in the KSN.
     * This uses BigInteger to safely operate on the entire 10-byte KSN.
     */
    public void incrementKSN() {
        // KSN is hex string representing 10 bytes
        BigInteger ksnBig = new BigInteger(ksn, 16);
        // mask for 21 bits (lowest 21 bits)
        BigInteger one = BigInteger.ONE;
        BigInteger counterMask = one.shiftLeft(21).subtract(one); // (1<<21)-1
        BigInteger counter = ksnBig.and(counterMask);
        BigInteger maxCounter = counterMask;
        if (counter.compareTo(maxCounter) >= 0) {
            throw new IllegalStateException("KSN counter overflow. Request new IPEK and reset KSN.");
        }
        // increment low 21 bits
        BigInteger ksnBase = ksnBig.and(counterMask.not()); // clear low 21 bits
        BigInteger newCounter = counter.add(one);
        BigInteger newKsnBig = ksnBase.or(newCounter);
        // convert back to hex, padded to 20 hex chars (10 bytes)
        String newKsnHex = padHex(newKsnBig.toString(16).toUpperCase(), 20);
        this.ksn = newKsnHex;
    }

    // ---------------------
    // Derivation / Key lifecycle
    // ---------------------

    /**
     * Derive a key for the provided keyType (PIN/DATA/MAC).
     *
     * NOTE: This implementation uses a **TEST derivation**:
     *  - Takes IPEK (16 bytes) -> extended to 24 bytes for 3DES
     *  - Encrypts the last 8 bytes of KSN (rightmost 8 bytes) with 3DES using IPEK
     *  - Builds a 16-byte derived key from the 8-byte result (duplicated)
     *  - Applies the requested KEY VARIANT mask by XOR
     *
     * This is **NOT** the full ANSI X9.24 DUKPT algorithm. Replace computeDerivedKeyWithStandardAlgorithm()
     * with a proper DUKPT engine (or use HSM) for production.
     *
     * @param keyType "PIN" | "DATA" | "MAC"
     * @return derived key hex (16 bytes -> 32 hex chars)
     */
    public String deriveAndRegisterKey(String keyType) throws Exception {
        if (ipek == null) throw new IllegalStateException("IPEK is not present");

        byte[] derived = computeDerivedKeyWithTestAlgorithm(ipek, Converter.hexStringToByteArray_2(ksn));

        // derived is 16 bytes (we build it that way)
        String derivedHex = Converter.byteArrayToHexString_2(derived);

        // apply variant mask depending on type
        if ("PIN".equalsIgnoreCase(keyType)) {
            byte[] masked = xorHex(derivedHex, PIN_VARIANT_MASK_HEX);
            pinDerivedKeyHex = Converter.byteArrayToHexString_2(masked);
            currentDerivedKeyHex = pinDerivedKeyHex;
            return pinDerivedKeyHex;
        } else if ("DATA".equalsIgnoreCase(keyType)) {
            byte[] masked = xorHex(derivedHex, DATA_VARIANT_MASK_HEX);
            dataDerivedKeyHex = Converter.byteArrayToHexString_2(masked);
            currentDerivedKeyHex = dataDerivedKeyHex;
            return dataDerivedKeyHex;
        } else if ("MAC".equalsIgnoreCase(keyType)) {
            byte[] masked = xorHex(derivedHex, MAC_VARIANT_MASK_HEX);
            macDerivedKeyHex = Converter.byteArrayToHexString_2(masked);
            currentDerivedKeyHex = macDerivedKeyHex;
            return macDerivedKeyHex;
        } else {
            throw new IllegalArgumentException("Unknown keyType: " + keyType);
        }
    }

    /**
     * Wipes IPEK from memory. After this call, the manager no longer holds the raw IPEK.
     * Future derivation should be done by storing only derived keys or re-requesting IPEK from HSM.
     */
    public void destroyIPEK() {
        if (ipek != null) Arrays.fill(ipek, (byte)0x00);
        ipek = null;
    }

    // ---------------------
    // Encryption / Decryption with derived keys (3DES)
    // ---------------------
    // Input plaintextHex is hex (e.g. formatted PIN block or padded data) OR plain string - we accept plain UTF-8 for simplicity.
    public String encryptWithCurrentDerivedKeyHex(String plainText) throws Exception {
        if (currentDerivedKeyHex == null) throw new IllegalStateException("No current derived key registered");
        byte[] keyBytes = Converter.hexStringToByteArray_2(currentDerivedKeyHex); // 16 bytes expected
        byte[] ciphertext = tripleDesEncryptWith16ByteKey(keyBytes, plainText.getBytes());
        return Converter.byteArrayToHexString_2(ciphertext);
    }

    public String decryptWithCurrentDerivedKeyHex(String cipherHex) throws Exception {
        if (currentDerivedKeyHex == null) throw new IllegalStateException("No current derived key registered");
        byte[] keyBytes = Converter.hexStringToByteArray_2(currentDerivedKeyHex); // 16 bytes expected
        byte[] plain = tripleDesDecryptWith16ByteKey(keyBytes, Converter.hexStringToByteArray_2(cipherHex));
        return new String(plain);
    }

    // ---------------------
    // --------- Internal helpers ----------
    // ---------------------

    // TEST derivation: NOT the standard DUKPT. It produces 16-byte key from IPEK + KSN last 8 bytes.
    private byte[] computeDerivedKeyWithTestAlgorithm(byte[] ipek16, byte[] ksn10) throws Exception {
        // get rightmost 8 bytes of KSN (bytes 2..9)
        byte[] ksn8 = Arrays.copyOfRange(ksn10, Math.max(0, ksn10.length - 8), ksn10.length);

        // Build 3DES key from 16-byte IPEK: K(24) = IPEK(16) + IPEK[0..7]
        byte[] key24 = new byte[24];
        System.arraycopy(ipek16, 0, key24, 0, 16);
        System.arraycopy(ipek16, 0, key24, 16, 8);

        // Encrypt ksn8 with 3DES (ECB, no padding; ksn8 is 8 bytes so fits)
        byte[] enc = tripleDesEncryptRaw(key24, ksn8);

        // Build 16-byte derived by duplicate enc (simple pattern for test)
        byte[] derived16 = new byte[16];
        System.arraycopy(enc, 0, derived16, 0, 8);
        System.arraycopy(enc, 0, derived16, 8, 8);
        return derived16;
    }

    // XOR two hex-strings, return raw bytes of result
    private static byte[] xorHex(String hexA, String hexB) {
        byte[] a = Converter.hexStringToByteArray_2(hexA);
        byte[] b = Converter.hexStringToByteArray_2(hexB);
        int len = Math.max(a.length, b.length);
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            byte ba = (i < a.length) ? a[a.length - len + i] : 0;
            byte bb = (i < b.length) ? b[b.length - len + i] : 0;
            out[i] = (byte)(ba ^ bb);
        }
        return out;
    }

    // 3DES encrypt raw 8-byte block with 24-byte key
    private static byte[] tripleDesEncryptRaw(byte[] key24, byte[] block8) throws Exception {
        if (block8.length != 8) throw new IllegalArgumentException("block must be 8 bytes");
        SecretKeySpec keySpec = new SecretKeySpec(key24, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(block8);
    }

    // Convenient wrapper: encrypt arbitrary bytes using 16-byte derivedKey (expand to 24)
    private static byte[] tripleDesEncryptWith16ByteKey(byte[] key16, byte[] plain) throws Exception {
        if (key16.length != 16) throw new IllegalArgumentException("Derived key must be 16 bytes");
        byte[] key24 = new byte[24];
        System.arraycopy(key16, 0, key24, 0, 16);
        System.arraycopy(key16, 0, key24, 16, 8); // K1 appended
        SecretKeySpec keySpec = new SecretKeySpec(key24, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plain);
    }

    private static byte[] tripleDesDecryptWith16ByteKey(byte[] key16, byte[] cipherText) throws Exception {
        if (key16.length != 16) throw new IllegalArgumentException("Derived key must be 16 bytes");
        byte[] key24 = new byte[24];
        System.arraycopy(key16, 0, key24, 0, 16);
        System.arraycopy(key16, 0, key24, 16, 8);
        SecretKeySpec keySpec = new SecretKeySpec(key24, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(cipherText);
    }

    // hex padding helper to fixed width (upper-case)
    private static String padHex(String h, int width) {
        if (h.length() >= width) return h.substring(h.length() - width);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < width - h.length(); i++) sb.append('0');
        sb.append(h);
        return sb.toString().toUpperCase();
    }
}
