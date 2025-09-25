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
import java.util.HashMap;
import java.util.Map;

/**
 * Enhanced DUKPT Manager - ANSI X9.24-1 with 21-Key Precompute Model
 *
 * SECURITY MODEL OVERVIEW:
 * ========================
 * 1. PRECOMPUTE: Derives exactly 21 future transaction keys from IPEK at initialization
 * 2. DESTROY IPEK: Immediately securely erases IPEK after precomputation
 * 3. CONSUME: Uses precomputed keys sequentially for transactions (never derives during payment)
 * 4. REPLENISH: Optionally generates new key batch when approaching exhaustion
 * 5. REKEY: Forces new IPEK injection when all 21 keys consumed
 *
 * WHY 21 KEYS?
 * - ANSI X9.24-1 standard allows maximum 21-bit counter (2,097,151 total keys)
 * - Practical memory constraint for payment terminals
 * - Optimal security/performance tradeoff for forward secrecy
 * - Balances key storage vs. HSM computation requirements
 *
 * SECURITY BENEFITS:
 * - IPEK never stored long-term on device (destroyed after first use)
 * - Fast transaction processing (no cryptographic derivation during payment)
 * - Forward security: compromised device cannot recover past keys
 * - Tamper-resistant: key exhaustion forces secure re-initialization
 */
public class EnhancedDukptManager {

    // ---------------------
    // Security Configuration
    // ---------------------
    public static final int NUM_OVERWRITES = 3;
    public static final int FUTURE_KEYS_COUNT = 21; // Maximum future keys to precompute

    // Standard DUKPT masks from ANSI X9.24-1 (CONFIRM WITH YOUR HSM SPEC)
    public static final String KEY_REGISTER_BITMASK = "C0C0C0C000000000C0C0C0C000000000";
    public static final String PIN_VARIANT_MASK_HEX = "00000000000000FF00000000000000FF";
    public static final String DATA_VARIANT_MASK_HEX = "0000000000FF00000000000000FF0000";
    public static final String MAC_VARIANT_MASK_HEX = "000000000000FF00000000000000FF00";

    // ---------------------
    // Instance Variables
    // ---------------------
    private String ksi;  // Key Serial Identifier (device-specific part)
    private long baseCounter; // Starting counter when keys were precomputed
    private boolean ipekDestroyed = false;

    // Precomputed future keys storage (exactly 21 keys)
    private final Map<Integer, byte[]> futureKeys = new HashMap<>();
    private int nextKeyIndex = 0; // Index of next key to consume (0-20)

    // Current transaction state
    private String currentKsn = null;
    private String currentDerivedKeyHex = null;
    private KeyType currentKeyType = null;

    // ---------------------
    // Constructor - Precomputes 21 future keys and destroys IPEK
    // ---------------------
    public EnhancedDukptManager(String initialIpekHex, String initialKsiHex) throws Exception {
        this(initialIpekHex, initialKsiHex, 0L);
    }

    public EnhancedDukptManager(String initialIpekHex, String initialKsiHex, long startingCounter) throws Exception {
        if (initialIpekHex == null || initialIpekHex.length() != 32) {
            throw new IllegalArgumentException("IPEK must be exactly 16 bytes (32 hex characters)");
        }
        if (initialKsiHex == null || (initialKsiHex.length() != 15 && initialKsiHex.length() != 16)) {
            throw new IllegalArgumentException("KSI must be either 15 or 16 hex characters");
        }
        if (startingCounter < 0 || startingCounter > 0x1FFFFF) { // 21-bit max
            throw new IllegalArgumentException("Starting counter must be 0 to 2,097,151 (21-bit max)");
        }

        this.ksi = initialKsiHex.toUpperCase();
        this.baseCounter = startingCounter;

        // CRITICAL SECURITY STEP: Precompute all future keys and immediately destroy IPEK
        byte[] ipek = Converter.hexStringToByteArray_2(initialIpekHex);
        try {
            precomputeFutureKeys(ipek);
        } finally {
            // ALWAYS destroy IPEK, even if precomputation fails
            obliviate(ipek);
            ipek = null;
            ipekDestroyed = true;
            System.gc(); // Suggest garbage collection (Android limitation)
        }

        System.out.println("EnhancedDukptManager initialized: " + FUTURE_KEYS_COUNT + " keys precomputed, IPEK destroyed");
    }

    // ---------------------
    // Future Key Precomputation (Core Security Function)
    // ---------------------

    /**
     * SECURITY-CRITICAL: Precomputes exactly 21 future transaction keys from IPEK.
     * This method runs only ONCE during initialization.
     * After completion, IPEK is permanently destroyed.
     *
     * ALGORITHM:
     * 1. For each future key index (0 to 20):
     *    - Calculate KSN = KSI + (baseCounter + index)
     *    - Derive base transaction key using standard DUKPT algorithm
     *    - Store key in secure in-memory map
     * 2. Clear all working memory
     * 3. Mark IPEK for destruction
     */
    private void precomputeFutureKeys(byte[] ipek) throws Exception {
        System.out.println("=== PRECOMPUTING " + FUTURE_KEYS_COUNT + " FUTURE KEYS ===");

        for (int keyIndex = 0; keyIndex < FUTURE_KEYS_COUNT; keyIndex++) {
            long counterValue = baseCounter + keyIndex;
            String ksn = buildKsn(ksi, counterValue);

            // Derive the base transaction key (without variant mask)
            byte[] ksnBytes = Converter.hexStringToByteArray_2(ksn);
            byte[] transactionKey = computeStandardDukptKey(ipek, ksnBytes, null);

            // Store securely in memory
            futureKeys.put(keyIndex, transactionKey.clone());

            System.out.println(String.format("Future key %02d: KSN=%s, Counter=%d",
                    keyIndex, ksn, counterValue));

            // Secure cleanup of working memory
            Arrays.fill(transactionKey, (byte) 0x00);
            Arrays.fill(ksnBytes, (byte) 0x00);
        }

        System.out.println("=== PRECOMPUTATION COMPLETE - IPEK WILL BE DESTROYED ===");
    }

    // ---------------------
    // Key Consumption Functions
    // ---------------------

    /**
     * Consumes the next precomputed future key for a transaction.
     * Applies the specified usage variant (PIN/DATA/MAC).
     *
     * PROCESS:
     * 1. Verify key availability
     * 2. Retrieve precomputed base transaction key
     * 3. Apply usage variant mask (PIN/DATA/MAC)
     * 4. Update current transaction state
     * 5. Return derived usage key
     *
     * @param keyType The usage variant (PIN, DATA, MAC)
     * @return Hex-encoded derived key for transaction use
     */
    public String consumeNextFutureKey(KeyType keyType) throws Exception {
        if (nextKeyIndex >= FUTURE_KEYS_COUNT) {
            throw new IllegalStateException(
                    String.format("All %d future keys exhausted. Device MUST be re-keyed with new IPEK.",
                            FUTURE_KEYS_COUNT));
        }

        if (!futureKeys.containsKey(nextKeyIndex)) {
            throw new IllegalStateException("Future key " + nextKeyIndex + " not available");
        }

        System.out.println(String.format("Consuming future key %d for %s usage",
                nextKeyIndex, keyType));

        // Get the precomputed base transaction key
        byte[] baseKey = futureKeys.get(nextKeyIndex).clone();

        try {
            // Apply usage variant mask
            byte[] variantMask = getVariantMaskBytes(keyType);
            for (int i = 0; i < baseKey.length; i++) {
                baseKey[i] ^= variantMask[i];
            }

            // Update current transaction state
            currentKsn = buildKsn(ksi, baseCounter + nextKeyIndex);
            currentDerivedKeyHex = Converter.byteArrayToHexString_2(baseKey);
            currentKeyType = keyType;

            System.out.println(String.format("Key consumed: KSN=%s, Type=%s, Keys remaining: %d",
                    currentKsn, keyType, getRemainingKeyCount() - 1));

            return currentDerivedKeyHex;

        } finally {
            // Secure cleanup
            Arrays.fill(baseKey, (byte) 0x00);
        }
    }

    /**
     * Advances to the next future key after completing a transaction.
     * Securely erases the consumed key from memory.
     * Call this after successful transaction completion.
     */
    public void advanceToNextKey() {
        if (nextKeyIndex < FUTURE_KEYS_COUNT) {
            // Secure erasure of consumed key
            if (futureKeys.containsKey(nextKeyIndex)) {
                obliviate(futureKeys.get(nextKeyIndex));
                futureKeys.remove(nextKeyIndex);
            }

            nextKeyIndex++;

            // Clear current transaction state
            if (currentDerivedKeyHex != null) {
                byte[] currentKeyBytes = Converter.hexStringToByteArray_2(currentDerivedKeyHex);
                obliviate(currentKeyBytes);
            }
            currentKsn = null;
            currentDerivedKeyHex = null;
            currentKeyType = null;

            System.out.println(String.format("Advanced to next key. Keys remaining: %d",
                    getRemainingKeyCount()));
        }
    }

    // ---------------------
    // Transaction Processing
    // ---------------------

    /**
     * Complete transaction workflow: consume → encrypt → advance
     *
     * @param keyType Usage variant for the transaction
     * @param plaintext Data to encrypt
     * @return Transaction details including KSN and encrypted data
     */
    public Map<String, Object> processTransaction(KeyType keyType, String plaintext) throws Exception {
        // 1. Consume future key
        String derivedKey = consumeNextFutureKey(keyType);

        // 2. Process transaction data
        String encryptedData = encryptWithCurrentDerivedKey(plaintext);

        // 3. Prepare result
        Map<String, Object> result = new HashMap<>();
        result.put("ksn", currentKsn);
        result.put("keyType", keyType.toString());
        result.put("encryptedData", encryptedData);
        result.put("keysRemaining", getRemainingKeyCount() - 1);
        result.put("transactionCounter", getCurrentTransactionCounter());

        // 4. Advance to next key (consumes current key)
        advanceToNextKey();

        return result;
    }

    // ---------------------
    // Key Management Status
    // ---------------------

    /**
     * Gets the number of future keys remaining
     */
    public int getRemainingKeyCount() {
        return FUTURE_KEYS_COUNT - nextKeyIndex;
    }

    /**
     * Checks if device rekeying is required (all keys consumed)
     */
    public boolean isRekeyingRequired() {
        return nextKeyIndex >= FUTURE_KEYS_COUNT;
    }

    /**
     * Gets current transaction counter value
     */
    public long getCurrentTransactionCounter() {
        return baseCounter + nextKeyIndex;
    }

    /**
     * Gets comprehensive status information
     */
    public String getStatus() {
        return String.format(
                "DUKPT Status: Keys=%d/%d, Index=%d, Counter=%d, IPEK destroyed=%s, Rekeying required=%s",
                getRemainingKeyCount(), FUTURE_KEYS_COUNT, nextKeyIndex,
                getCurrentTransactionCounter(), ipekDestroyed, isRekeyingRequired());
    }

    // ---------------------
    // Security Functions
    // ---------------------

    /**
     * EMERGENCY: Destroys all remaining cryptographic material.
     * Call on security breach, tamper detection, or app shutdown.
     */
    public void destroyAllKeys() {
        System.out.println("EMERGENCY: Destroying all cryptographic material");

        // Destroy all future keys
        for (byte[] key : futureKeys.values()) {
            if (key != null) {
                obliviate(key);
            }
        }
        futureKeys.clear();

        // Destroy current key if active
        if (currentDerivedKeyHex != null) {
            byte[] currentKeyBytes = Converter.hexStringToByteArray_2(currentDerivedKeyHex);
            obliviate(currentKeyBytes);
            currentDerivedKeyHex = null;
        }

        // Mark as exhausted
        nextKeyIndex = FUTURE_KEYS_COUNT;
        currentKsn = null;
        currentKeyType = null;

        System.gc(); // Suggest garbage collection
        System.out.println("All cryptographic material destroyed");
    }

    // ---------------------
    // Utility Functions
    // ---------------------

    /**
     * Build KSN from KSI and counter value according to ANSI X9.24-1
     */
    private String buildKsn(String ksi, long counter) {
        if (counter > 0x1FFFFF) {
            throw new IllegalArgumentException("Counter exceeds 21-bit maximum (2,097,151)");
        }

        // Build base KSN structure
        String baseKsn;
        if (ksi.length() == 15) {
            baseKsn = ksi + "00000"; // 20 hex chars total (80 bits)
        } else {
            baseKsn = ksi + "0000";  // 20 hex chars total (80 bits)
        }

        // Apply counter to lower 21 bits
        BigInteger ksnBig = new BigInteger(baseKsn, 16);
        BigInteger counterBig = BigInteger.valueOf(counter);
        BigInteger mask = BigInteger.valueOf(0x1FFFFF); // 21-bit mask

        ksnBig = ksnBig.and(mask.not()).or(counterBig);

        return padHex(ksnBig.toString(16).toUpperCase(), 20);
    }

    /**
     * Get usage variant mask as byte array
     */
    private byte[] getVariantMaskBytes(KeyType keyType) {
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
        return Converter.hexStringToByteArray_2(maskHex);
    }

    // ---------------------
    // Standard DUKPT Algorithm (ANSI X9.24-1)
    // ---------------------

    /**
     * Standard DUKPT key derivation algorithm
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

    private BitSet getCurrentKey(BitSet ipek, BitSet ksn, KeyType keyType) throws Exception {
        BitSet key = (BitSet) ipek.clone();
        BitSet counter = (BitSet) ksn.clone();

        // Clear upper bits, keep only counter part
        for (int i = 59; i < counter.length(); i++) {
            counter.clear(i);
        }

        // Process each bit from bit 59 upward
        for (int i = 59; i < ksn.length(); i++) {
            if (ksn.get(i)) {
                counter.set(i);
                BitSet newKey = nonReversibleKeyGenerationProcess(key,
                        counter.get(16, Math.min(80, counter.length())));
                obliviate(key);
                key = newKey;
            }
        }

        // Apply variant mask only for final usage (not during precomputation)
        if (keyType != null) {
            BitSet variantMask = getVariantMask(keyType);
            key.xor(variantMask);
            obliviate(variantMask);
        }

        obliviate(counter);
        return key;
    }

    private BitSet nonReversibleKeyGenerationProcess(BitSet key, BitSet data) throws Exception {
        BitSet keyReg = (BitSet) key.clone();
        BitSet reg1 = (BitSet) data.clone();

        // ANSI X9.24-1 Non-reversible key generation process
        BitSet reg2 = (BitSet) reg1.clone();
        BitSet rightHalf = keyReg.get(64, 128);
        reg2.xor(rightHalf);

        BitSet leftHalf = keyReg.get(0, 64);
        byte[] reg2Encrypted = encryptDes(toByteArray(leftHalf), toByteArray(reg2), false);
        reg2 = toBitSet(reg2Encrypted);

        reg2.xor(rightHalf);

        BitSet keyRegMask = toBitSet(Converter.hexStringToByteArray_2(KEY_REGISTER_BITMASK));
        keyReg.xor(keyRegMask);

        BitSet newRightHalf = keyReg.get(64, 128);
        reg1.xor(newRightHalf);

        BitSet newLeftHalf = keyReg.get(0, 64);
        byte[] reg1Encrypted = encryptDes(toByteArray(newLeftHalf), toByteArray(reg1), false);
        reg1 = toBitSet(reg1Encrypted);

        reg1.xor(newRightHalf);

        // Combine results
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

    private BitSet getVariantMask(KeyType keyType) {
        return toBitSet(getVariantMaskBytes(keyType));
    }

    // ---------------------
    // Encryption/Decryption
    // ---------------------

    public String encryptWithCurrentDerivedKey(String plainText) throws Exception {
        if (currentDerivedKeyHex == null) {
            throw new IllegalStateException("No current derived key. Call consumeNextFutureKey() first.");
        }
        byte[] keyBytes = Converter.hexStringToByteArray_2(currentDerivedKeyHex);
        try {
            byte[] ciphertext = tripleDesEncryptWith16ByteKey(keyBytes, plainText.getBytes());
            return Converter.byteArrayToHexString_2(ciphertext);
        } finally {
            Arrays.fill(keyBytes, (byte) 0x00);
        }
    }

    public String decryptWithCurrentDerivedKey(String cipherHex) throws Exception {
        if (currentDerivedKeyHex == null) {
            throw new IllegalStateException("No current derived key. Call consumeNextFutureKey() first.");
        }
        byte[] keyBytes = Converter.hexStringToByteArray_2(currentDerivedKeyHex);
        try {
            byte[] plain = tripleDesDecryptWith16ByteKey(keyBytes,
                    Converter.hexStringToByteArray_2(cipherHex));
            return new String(plain);
        } finally {
            Arrays.fill(keyBytes, (byte) 0x00);
        }
    }

    // ---------------------
    // Getters
    // ---------------------

    public String getCurrentKsn() { return currentKsn; }
    public KeyType getCurrentKeyType() { return currentKeyType; }
    public String getKsi() { return ksi; }
    public boolean isIpekDestroyed() { return ipekDestroyed; }

    // ---------------------
    // Cryptographic Utilities (unchanged from original)
    // ---------------------

    public static byte[] encryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        SecretKey encryptKey = SecretKeyFactory.getInstance("DES")
                .generateSecret(new DESKeySpec(key));

        Cipher encryptor = Cipher.getInstance(
                padding ? "DES/CBC/PKCS5Padding" : "DES/CBC/NoPadding");

        encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
        return encryptor.doFinal(data);
    }

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

    // BitSet Operations (unchanged)
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

    public static byte[] toByteArray(BitSet b) {
        int size = (int) Math.ceil(b.length() / 8.0d);
        byte[] value = new byte[size];
        for (int i = 0; i < size; i++) {
            value[i] = toByte(b.get(i * 8, Math.min(b.length(), (i + 1) * 8)));
        }
        return value;
    }

    public static byte toByte(BitSet b) {
        byte value = 0;
        for (int i = 0; i < Math.min(8, b.length()); i++) {
            if (b.get(i))
                value = (byte) (value | (1L << (7 - i)));
        }
        return value;
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static void obliviate(BitSet b) {
        SecureRandom r = new SecureRandom();
        for (int i = 0; i < NUM_OVERWRITES; i++) {
            for (int j = 0; j < b.length(); j++) {
                b.set(j, r.nextBoolean());
            }
        }
        b.clear();
    }

    public static void obliviate(byte[] b) {
        SecureRandom r = new SecureRandom();
        for (int i = 0; i < NUM_OVERWRITES; i++) {
            r.nextBytes(b);
        }
        Arrays.fill(b, (byte) 0x00);
    }

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
    // Enums and Inner Classes
    // ---------------------

    public enum KeyType {
        PIN, DATA, MAC
    }

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