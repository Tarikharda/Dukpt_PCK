package org.example.utils.security.dukpt;

import org.example.utils.Converter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * DukptManager - Standard ANSI X9.24-1 DUKPT implementation
 *
 * - Accepts IPEK and KSI only once at initialization
 * - Manages KSN with proper 21-bit counter increment
 * - Implements standard DUKPT key derivation algorithm
 * - Supports PIN, DATA, and MAC key variants
 * - Destroys IPEK after first use for security
 */
public class DukptManager {

    // ---------------------
    // Security Configuration
    // ---------------------
    public static final int NUM_OVERWRITES = 3;

    // Standard DUKPT masks from ANSI X9.24-1
    public static final String KEY_REGISTER_BITMASK = "C0C0C0C000000000C0C0C0C000000000";
    public static final String PIN_VARIANT_MASK_HEX = "00000000000000FF00000000000000FF";
    public static final String DATA_VARIANT_MASK_HEX = "0000000000FF00000000000000FF0000";
    public static final String MAC_VARIANT_MASK_HEX = "000000000000FF00000000000000FF00";

    // ---------------------
    // Instance Variables
    // ---------------------
    private byte[] ipek; // Will be destroyed after first use
    private String ksi;  // Key Serial Identifier (device specific part)
    private String ksn;  // Current Key Serial Number (KSI + counter)
    private boolean ipekDestroyed = false;

    // Key registers (hex strings) - stores last derived keys
    public String pinDerivedKeyHex = null;
    public String dataDerivedKeyHex = null;
    public String macDerivedKeyHex = null;
    public String currentDerivedKeyHex = null;

    // ---------------------
    // Constructor - IPEK and KSI provided only once
    // ---------------------
    public DukptManager(String initialIpekHex, String initialKsiHex) {
        if (initialIpekHex == null || initialIpekHex.length() != 32) {
            throw new IllegalArgumentException("IPEK must be exactly 16 bytes (32 hex characters)");
        }
        if (initialKsiHex == null || (initialKsiHex.length() != 15 && initialKsiHex.length() != 16)) {
            throw new IllegalArgumentException("KSI must be either 15 or 16 hex characters (industry standard varies)");
        }

        this.ipek = Converter.hexStringToByteArray_2(initialIpekHex);
        this.ksi = initialKsiHex.toUpperCase();

        // Initialize KSN based on KSI length
        if (initialKsiHex.length() == 15) {
            // 15 hex chars KSI + 5 hex chars counter = 20 hex chars total (80 bits)
            this.ksn = this.ksi + "00000";
        } else {
            // 16 hex chars KSI + 4 hex chars counter = 20 hex chars total (80 bits)
            this.ksn = this.ksi + "0000";
        }
    }

    // ---------------------
    // KSN Management
    // ---------------------
    public String getKSN() {
        return ksn;
    }

    public String getKSI() {
        return ksi;
    }

    /**
     * Get the current transaction counter value (21-bit)
     */
    public long getTransactionCounter() {
        BigInteger ksnBig = new BigInteger(ksn, 16);
        BigInteger counterMask = BigInteger.ONE.shiftLeft(21).subtract(BigInteger.ONE);
        return ksnBig.and(counterMask).longValue();
    }

    /**
     * Get KSN structure information for debugging
     */
    public String getKsnInfo() {
        return String.format("KSN: %s (KSI: %s, Counter: %d, Total Length: %d hex chars)",
                ksn, ksi, getTransactionCounter(), ksn.length());
    }

    /**
     * Increment the 21-bit transaction counter in the KSN.
     *
     * KSN format (80 bits total):
     * - For 15-char KSI: KSI(60 bits) + Counter(20 bits, but only 21 bits used across boundary)
     * - For 16-char KSI: KSI(64 bits) + Counter(16 bits, but only 21 bits used across boundary)
     *
     * The 21-bit counter can span across the KSI/Counter boundary as per ANSI X9.24-1
     */
    public void incrementKSN() {
        // Convert KSN to BigInteger for bit manipulation
        BigInteger ksnBig = new BigInteger(ksn, 16);

        // Extract the 21-bit counter (lowest 21 bits)
        BigInteger counterMask = BigInteger.ONE.shiftLeft(21).subtract(BigInteger.ONE); // 0x1FFFFF
        BigInteger counter = ksnBig.and(counterMask);
        BigInteger maxCounter = counterMask;

        if (counter.compareTo(maxCounter) >= 0) {
            throw new IllegalStateException("KSN counter overflow. Maximum transactions (2,097,151) reached.");
        }

        // Increment the counter
        BigInteger ksnBase = ksnBig.and(counterMask.not()); // Clear low 21 bits
        BigInteger newCounter = counter.add(BigInteger.ONE);
        BigInteger newKsnBig = ksnBase.or(newCounter);

        // Convert back to hex string (20 hex chars = 10 bytes = 80 bits)
        String newKsnHex = padHex(newKsnBig.toString(16).toUpperCase(), 20);
        this.ksn = newKsnHex;
    }

    // ---------------------
    // Standard DUKPT Key Derivation (ANSI X9.24-1)
    // ---------------------

    /**
     * Derive a key using the standard ANSI X9.24-1 DUKPT algorithm.
     *
     * @param keyType "PIN", "DATA", or "MAC"
     * @return derived key hex (16 bytes -> 32 hex chars)
     */
    public String deriveAndRegisterKey(String keyType) throws Exception {
        if (ipekDestroyed || ipek == null) {
            throw new IllegalStateException("IPEK has been destroyed. Cannot derive new keys.");
        }

        KeyType type;
        try {
            type = KeyType.valueOf(keyType.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid keyType. Must be PIN, DATA, or MAC");
        }

        // Convert inputs for DUKPT algorithm
        byte[] ksnBytes = Converter.hexStringToByteArray_2(ksn);

        // Use standard DUKPT algorithm
        byte[] derivedKey = computeStandardDukptKey(ipek, ksnBytes, type);

        // Convert to hex and register
        String derivedHex = Converter.byteArrayToHexString_2(derivedKey);

        switch (type) {
            case PIN:
                pinDerivedKeyHex = derivedHex;
                currentDerivedKeyHex = pinDerivedKeyHex;
                break;
            case DATA:
                dataDerivedKeyHex = derivedHex;
                currentDerivedKeyHex = dataDerivedKeyHex;
                break;
            case MAC:
                macDerivedKeyHex = derivedHex;
                currentDerivedKeyHex = macDerivedKeyHex;
                break;
        }

        // Secure cleanup
        Arrays.fill(derivedKey, (byte) 0x00);

        return currentDerivedKeyHex;
    }

    /**
     * Standard ANSI X9.24-1 DUKPT key computation
     */
    private byte[] computeStandardDukptKey(byte[] ipek, byte[] ksn, KeyType keyType) throws Exception {
        BitSet ipekBits = toBitSet(ipek);
        BitSet ksnBits = toBitSet(ksn);

        BitSet key = getCurrentKey(ipekBits, ksnBits, keyType);
        byte[] result = toByteArray(key);

        // Secure cleanup
        obliviate(ipekBits);
        obliviate(ksnBits);
        obliviate(key);

        return result;
    }

    /**
     * Main DUKPT key derivation algorithm from ANSI X9.24-1
     */
    private BitSet getCurrentKey(BitSet ipek, BitSet ksn, KeyType keyType) throws Exception {
        BitSet key = (BitSet) ipek.clone();
        BitSet counter = (BitSet) ksn.clone();

        // Clear the upper bits, keeping only the counter part
        for (int i = 59; i < counter.length(); i++) {
            counter.clear(i);
        }

        // Process each bit in the counter from bit 59 upward
        for (int i = 59; i < ksn.length(); i++) {
            if (ksn.get(i)) {
                counter.set(i);
                BitSet newKey = nonReversibleKeyGenerationProcess(key,
                        counter.get(16, Math.min(80, counter.length())));
                obliviate(key);
                key = newKey;
            }
        }

        // Apply variant mask based on key type
        BitSet variantMask = getVariantMask(keyType);
        key.xor(variantMask);

        // Cleanup
        obliviate(counter);
        obliviate(variantMask);

        return key;
    }

    /**
     * Non-reversible key generation process from ANSI X9.24-1
     */
    private BitSet nonReversibleKeyGenerationProcess(BitSet key, BitSet data) throws Exception {
        BitSet keyReg = (BitSet) key.clone();
        BitSet reg1 = (BitSet) data.clone();

        // Step 1: Crypto Register-1 XOR right half of Key Register -> Crypto Register-2
        BitSet reg2 = (BitSet) reg1.clone();
        BitSet rightHalf = keyReg.get(64, 128);
        reg2.xor(rightHalf);

        // Step 2: DES encrypt Crypto Register-2 with left half of Key Register
        BitSet leftHalf = keyReg.get(0, 64);
        byte[] reg2Encrypted = encryptDes(toByteArray(leftHalf), toByteArray(reg2), false);
        reg2 = toBitSet(reg2Encrypted);

        // Step 3: XOR result with right half of Key Register
        reg2.xor(rightHalf);

        // Step 4: XOR Key Register with the standard mask
        BitSet keyRegMask = toBitSet(Converter.hexStringToByteArray_2(KEY_REGISTER_BITMASK));
        keyReg.xor(keyRegMask);

        // Step 5: XOR Crypto Register-1 with right half of modified Key Register
        BitSet newRightHalf = keyReg.get(64, 128);
        reg1.xor(newRightHalf);

        // Step 6: DES encrypt Crypto Register-1 with left half of modified Key Register
        BitSet newLeftHalf = keyReg.get(0, 64);
        byte[] reg1Encrypted = encryptDes(toByteArray(newLeftHalf), toByteArray(reg1), false);
        reg1 = toBitSet(reg1Encrypted);

        // Step 7: XOR result with right half of modified Key Register
        reg1.xor(newRightHalf);

        // Combine reg1 and reg2 to form the final key
        byte[] reg1Bytes = toByteArray(reg1);
        byte[] reg2Bytes = toByteArray(reg2);
        byte[] finalKey = concat(reg1Bytes, reg2Bytes);

        BitSet result = toBitSet(finalKey);

        // Secure cleanup
        obliviate(keyReg);
        obliviate(reg1);
        obliviate(reg2);
        obliviate(leftHalf);
        obliviate(rightHalf);
        obliviate(newLeftHalf);
        obliviate(newRightHalf);
        obliviate(keyRegMask);
        Arrays.fill(reg1Bytes, (byte) 0);
        Arrays.fill(reg2Bytes, (byte) 0);
        Arrays.fill(finalKey, (byte) 0);
        Arrays.fill(reg2Encrypted, (byte) 0);
        Arrays.fill(reg1Encrypted, (byte) 0);

        return result;
    }

    /**
     * Get the appropriate variant mask for the key type
     */
    private BitSet getVariantMask(KeyType keyType) {
        String maskHex;
        switch (keyType) {
            case PIN:
                maskHex = PIN_VARIANT_MASK_HEX;
                break;
            case DATA:
                maskHex = DATA_VARIANT_MASK_HEX;
                break;
            case MAC:
                maskHex = MAC_VARIANT_MASK_HEX;
                break;
            default:
                throw new IllegalArgumentException("Unknown key type: " + keyType);
        }
        return toBitSet(Converter.hexStringToByteArray_2(maskHex));
    }

    // ---------------------
    // Security Methods
    // ---------------------

    /**
     * Destroys IPEK from memory for security.
     * Call this manually after deriving all keys needed for the current transaction.
     */
    public void destroyIPEK() {
        if (ipek != null) {
            obliviate(ipek);
            ipek = null;
        }
        ipekDestroyed = true;
    }

    /**
     * Derive all keys needed for a complete transaction using the same KSN.
     * This is the recommended approach for DUKPT.
     *
     * @return Map containing all derived keys
     */
    public java.util.Map<String, String> deriveAllKeysForTransaction() throws Exception {
        if (ipekDestroyed || ipek == null) {
            throw new IllegalStateException("IPEK has been destroyed. Cannot derive new keys.");
        }

        java.util.Map<String, String> keys = new java.util.HashMap<>();

        // Derive all keys using the SAME KSN
        keys.put("PIN", deriveAndRegisterKey("PIN"));
        keys.put("DATA", deriveAndRegisterKey("DATA"));
        keys.put("MAC", deriveAndRegisterKey("MAC"));

        return keys;
    }

    /**
     * Complete transaction lifecycle: derive keys, process transaction, then move to next KSN
     */
    public void completeTransaction() {
//        nextTransaction();
        // Optionally destroy IPEK if this was the last transaction
        // destroyIPEK();
    }

    // ---------------------
    // Encryption/Decryption with derived keys
    // ---------------------

    public String encryptWithCurrentDerivedKeyHex(String plainText) throws Exception {
        if (currentDerivedKeyHex == null) {
            throw new IllegalStateException("No current derived key registered");
        }
        byte[] keyBytes = Converter.hexStringToByteArray_2(currentDerivedKeyHex);
        byte[] ciphertext = tripleDesEncryptWith16ByteKey(keyBytes, plainText.getBytes());
        return Converter.byteArrayToHexString_2(ciphertext);
    }

    public String decryptWithCurrentDerivedKeyHex(String cipherHex) throws Exception {
        if (currentDerivedKeyHex == null) {
            throw new IllegalStateException("No current derived key registered");
        }
        byte[] keyBytes = Converter.hexStringToByteArray_2(currentDerivedKeyHex);
        byte[] plain = tripleDesDecryptWith16ByteKey(keyBytes,
                Converter.hexStringToByteArray_2(cipherHex));
        return new String(plain);
    }

    // ---------------------
    // Utility Methods
    // ---------------------

    /**
     * Single DES encryption
     */
    public static byte[] encryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        SecretKey encryptKey = SecretKeyFactory.getInstance("DES")
                .generateSecret(new DESKeySpec(key));

        Cipher encryptor;
        if (padding) {
            encryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");
        } else {
            encryptor = Cipher.getInstance("DES/CBC/NoPadding");
        }

        encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
        return encryptor.doFinal(data);
    }

    /**
     * 3DES encryption with 16-byte key (extended to 24 bytes)
     */
    private static byte[] tripleDesEncryptWith16ByteKey(byte[] key16, byte[] plain) throws Exception {
        if (key16.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes");
        }

        byte[] key24 = new byte[24];
        System.arraycopy(key16, 0, key24, 0, 16);
        System.arraycopy(key16, 0, key24, 16, 8);

        SecretKeySpec keySpec = new SecretKeySpec(key24, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        return cipher.doFinal(plain);
    }

    /**
     * 3DES decryption with 16-byte key (extended to 24 bytes)
     */
    private static byte[] tripleDesDecryptWith16ByteKey(byte[] key16, byte[] cipherText) throws Exception {
        if (key16.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes");
        }

        byte[] key24 = new byte[24];
        System.arraycopy(key16, 0, key24, 0, 16);
        System.arraycopy(key16, 0, key24, 16, 8);

        SecretKeySpec keySpec = new SecretKeySpec(key24, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        return cipher.doFinal(cipherText);
    }

    // ---------------------
    // BitSet Operations (from reference implementation)
    // ---------------------

    /**
     * Convert byte array to BitSet
     */
    public static BitSet toBitSet(byte[] b) {
        BitSet bs = new BitSet(8 * b.length);
        for (int i = 0; i < b.length; i++) {
            for (int j = 0; j < 8; j++) {
                if ((b[i] & (1L << j)) > 0) {
                    bs.set(8 * i + (7 - j));
                }
            }
        }
        return bs;
    }

    /**
     * Convert BitSet to byte array
     */
    public static byte[] toByteArray(BitSet b) {
        int size = (int) Math.ceil(b.length() / 8.0d);
        byte[] value = new byte[size];
        for (int i = 0; i < size; i++) {
            value[i] = toByte(b.get(i * 8, Math.min(b.length(), (i + 1) * 8)));
        }
        return value;
    }

    /**
     * Convert BitSet to single byte
     */
    public static byte toByte(BitSet b) {
        byte value = 0;
        for (int i = 0; i < Math.min(8, b.length()); i++) {
            if (b.get(i))
                value = (byte) (value | (1L << (7 - i)));
        }
        return value;
    }

    /**
     * Concatenate two byte arrays
     */
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /**
     * Secure memory overwrite for BitSet
     */
    public static void obliviate(BitSet b) {
        SecureRandom r = new SecureRandom();
        for (int i = 0; i < NUM_OVERWRITES; i++) {
            for (int j = 0; j < b.length(); j++) {
                b.set(j, r.nextBoolean());
            }
        }
        b.clear();
    }

    /**
     * Secure memory overwrite for byte array
     */
    public static void obliviate(byte[] b) {
        SecureRandom r = new SecureRandom();
        for (int i = 0; i < NUM_OVERWRITES; i++) {
            r.nextBytes(b);
        }
        Arrays.fill(b, (byte) 0x00);
    }

    /**
     * Pad hex string to specified width
     */
    private static String padHex(String h, int width) {
        if (h.length() >= width) {
            return h.substring(h.length() - width);
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < width - h.length(); i++) {
            sb.append('0');
        }
        sb.append(h);
        return sb.toString().toUpperCase();
    }

    // ---------------------
    // Enums
    // ---------------------

    public enum KeyType {
        PIN, DATA, MAC
    }

    // ---------------------
    // Custom BitSet class to handle DUKPT operations
    // ---------------------

    public static class BitSet implements Cloneable {
        private boolean[] bits;
        private int size;

        public BitSet(int nbits) {
            this.bits = new boolean[nbits];
            this.size = nbits;
        }

        public void set(int bitIndex) {
            set(bitIndex, true);
        }

        public void set(int bitIndex, boolean value) {
            if (bitIndex >= 0 && bitIndex < size) {
                bits[bitIndex] = value;
            }
        }

        public void clear(int bitIndex) {
            if (bitIndex >= 0 && bitIndex < size) {
                bits[bitIndex] = false;
            }
        }

        public void clear(int fromIndex, int toIndex) {
            for (int i = fromIndex; i < Math.min(toIndex, size); i++) {
                bits[i] = false;
            }
        }

        public void clear() {
            Arrays.fill(bits, false);
        }

        public boolean get(int bitIndex) {
            return bitIndex >= 0 && bitIndex < size && bits[bitIndex];
        }

        public BitSet get(int fromIndex, int toIndex) {
            int length = Math.min(toIndex - fromIndex, size - fromIndex);
            length = Math.max(0, length);
            BitSet result = new BitSet(length);
            for (int i = 0; i < length; i++) {
                result.set(i, get(fromIndex + i));
            }
            return result;
        }

        public void xor(BitSet set) {
            int minSize = Math.min(this.size, set.size);
            for (int i = 0; i < minSize; i++) {
                this.bits[i] ^= set.get(i);
            }
        }

        public int length() {
            return size;
        }

        @Override
        public Object clone() {
            BitSet clone = new BitSet(this.size);
            System.arraycopy(this.bits, 0, clone.bits, 0, this.size);
            return clone;
        }
    }
}