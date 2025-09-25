package org.example.utils.security.dukpt;

import org.example.utils.Converter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public final class Dukpt {
    public static final int NUM_OVERWRITES = 3;

    public static final String KEY_REGISTER_BITMASK = "C0C0C0C000000000C0C0C0C000000000";
    public static final BitSet DEFAULT_KEY_REGISTER_BITMASK = toBitSet(Converter.hexStringToByteArray_2(KEY_REGISTER_BITMASK));

    public static final String PIN_VARIANT_BITMASK  = "00000000000000FF00000000000000FF";
    public static final String DATA_VARIANT_BITMASK = "0000000000FF00000000000000FF0000";
    public static final String MAC_VARIANT_BITMASK  = "000000000000FF00000000000000FF00";

    public static final BitSet PIN_VARIANT_BITMASK_BIT = toBitSet(Converter.hexStringToByteArray_2(PIN_VARIANT_BITMASK));
    public static final BitSet DATA_VARIANT_BITMASK_BIT = toBitSet(Converter.hexStringToByteArray_2(DATA_VARIANT_BITMASK));
    public static final BitSet MAC_VARIANT_BITMASK_BIT = toBitSet(Converter.hexStringToByteArray_2(MAC_VARIANT_BITMASK));


    /**
     * <p>Computes a DUKPT (Derived Unique Key-Per-Transaction).
     *
     * <p>This is derived from the Base Derivation Key, which should
     * have been injected into the device and should remain secret,
     * and the Key Serial Number which is a concatenation of the
     * device's serial number and its encryption (or transaction)
     * counter.
     * @param _ipek Initial PIN encryption key
     * @param _ksn The Key Serial Number
     * @return A unique key for this set of data.
     * @throws Exception
     */
    public static byte[] computeKey(byte[] _ipek, byte[] _ksn , KeyType keyType) throws Exception {

        BitSet ipek = toBitSet(_ipek);
        BitSet ksn = toBitSet(_ksn);

        BitSet key;

        if(keyType == KeyType.PIN) {
            key = _getCurrentKey(ipek, ksn, DEFAULT_KEY_REGISTER_BITMASK, PIN_VARIANT_BITMASK_BIT);
        }else if(keyType == KeyType.DATA){
            key = _getCurrentKey(ipek, ksn, DEFAULT_KEY_REGISTER_BITMASK, DATA_VARIANT_BITMASK_BIT);
        }else if (keyType == KeyType.MAC){
            key = _getCurrentKey(ipek, ksn, DEFAULT_KEY_REGISTER_BITMASK, MAC_VARIANT_BITMASK_BIT);
        }else{
            key = _getCurrentKey(ipek, ksn, DEFAULT_KEY_REGISTER_BITMASK, PIN_VARIANT_BITMASK_BIT);
        }

        byte[] rkey = toByteArray(key);

        // secure memory
        obliviate(ksn);
        obliviate(ipek);
        obliviate(key);

        return rkey;
    }

    /**
     * <p>Computes a Dukpt (Derived Unique Key-Per-Transaction) given an IPEK
     * and Key Serial Number.
     *
     * <p>Here, a non-reversible operation is used to find one key from
     * another.  This is where the transaction counter comes in.  In order
     * to have the desired number of possible unique keys (over 1 million)
     * for a given device, a transaction counter size of 20 bits would
     * suffice.  However, by adding an extra bit and a constraint (that
     * keys must have AT MOST 9* bits set) the same number of values can be
     * achieved while allowing a user to calculate the key in at most 9
     * steps.
     *
     * <p>We have reason to believe that is actually 10 bits (as the
     * sum of the 21 choose i for i from 0 to 9 is only around 700,000 while
     * taking i from 0 to 10 yields exactly 2^20 (just over 1,000,000) values)
     * but regardless of the truth, our algorithm is not dependent upon this
     * figure and will work no matter how it is implemented in the encrypting
     * device or application.
     *
     * <p>This algorithm was found in Annex A, section 3 on pages 50-54
     * of the ANSI X9.24-1:2009 document.
     *
     * @param ipek Initial PIN encryption key
     * @param ksn The Key Serial Number.
     * @return The Dukpt that corresponds to this combination of values.
     * @throws Exception
     */
    private static BitSet _getCurrentKey(BitSet ipek, BitSet ksn, BitSet keyRegisterBitmask, BitSet dataVariantBitmask) throws Exception {
        BitSet key = ipek.get(0, ipek.bitSize());
        BitSet counter = ksn.get(0, ksn.bitSize());
        counter.clear(59, ksn.bitSize());

        for (int i = 59; i < ksn.bitSize(); i++) {
            if (ksn.get(i)) {
                counter.set(i);
                BitSet tmp = _nonReversibleKeyGenerationProcess(key, counter.get(16, 80), keyRegisterBitmask);
                // secure memory
                obliviate(key);
                key = tmp;
            }
        }
        key.xor(dataVariantBitmask); // data encryption variant (e.g. To PIN)

        // secure memory
        obliviate(counter);

        return key;
    }

    /**
     * <p>Creates a new key from a previous key and the right 64 bits of the
     * Key Serial Number for the desired transaction.
     *
     * <p>This algorithm was found in Annex A, section 2 on page 50
     * of the ANSI X9.24-1:2009 document.
     *
     * @param p_key The previous key to be used for derivation.
     * @param data The data to encrypt it with, usually the right 64 bits of the transaction counter.
     * @return A key that cannot be traced back to p_key.
     * @throws Exception
     */
    private static BitSet _nonReversibleKeyGenerationProcess(BitSet p_key, BitSet data, BitSet keyRegisterBitmask) throws Exception {
        BitSet keyreg = p_key.get(0, p_key.bitSize());
        BitSet reg1 = data.get(0, data.bitSize());
        // step 1: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-2.
        BitSet reg2 = reg1.get(0, 64); // reg2 is being used like a temp here
        reg2.xor(keyreg.get(64, 128));   // and here, too, kind of
        // step 2: Crypto Register-2 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-2
        reg2 = toBitSet(encryptDes(toByteArray(keyreg.get(0, 64)), toByteArray(reg2) , false));
        // step 3: Crypto Register-2 XORed with the right half of the Key Register goes to Crypto Register-2
        reg2.xor(keyreg.get(64, 128));
        // done messing with reg2

        // step 4: XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
        keyreg.xor(keyRegisterBitmask);
        // step 5: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
        reg1.xor(keyreg.get(64, 128));
        // step 6: Crypto Register-1 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-1
        reg1 = toBitSet(encryptDes(toByteArray(keyreg.get(0, 64)), toByteArray(reg1) , false));
        // step 7: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
        reg1.xor(keyreg.get(64, 128));
        // done

        byte[] reg1b = toByteArray(reg1), reg2b = toByteArray(reg2);
        byte[] key = concat(reg1b, reg2b);
        BitSet rkey = toBitSet(key);

        // secure memory
        obliviate(reg1);
        obliviate(reg2);
        obliviate(reg1b);
        obliviate(reg2b);
        obliviate(key);
        obliviate(keyreg);

        return rkey;
    }

    /**
     * <p>Performs Single DES Encryption.
     *
     * @param key The key for encryption.
     * @param data The data to encrypt.
     * @param padding When true, PKCS5 Padding will be used.  This is most likely not desirable.
     * @return The encrypted.
     * @throws Exception
     */
    public static byte[] encryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        SecretKey encryptKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(key));
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
     * <p>Converts a byte array to an extended BitSet.
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
     * <p>Converts an extended BitSet into a byte.
     *
     * <p>Requires that the BitSet be exactly 8 bits long.
     */
    public static byte toByte(BitSet b) {
        byte value = 0;
        for (int i = 0; i < b.bitSize(); i++) {
            if (b.get(i))
                value = (byte) (value | (1L << 7 - i));
        }
        return value;
    }

    /**
     * <p>Converts a BitSet into a byte array.
     *
     * <p>Pads to the left with zeroes.
     *
     * <p>Note: this is different from {@link BitSet#toByteArray()}.</p>
     */
    public static byte[] toByteArray(BitSet b) {
        int size = (int) Math.ceil(b.bitSize() / 8.0d);
        byte[] value = new byte[size];
        for (int i = 0; i < size; i++) {
            value[i] = toByte(b.get(i * 8, Math.min(b.bitSize(), (i + 1) * 8)));
        }
        return value;
    }


    /**
     * <p>Concatenates two byte arrays.
     *
     * @return The array a concatenated with b.  So if r is the returned array, r[0] = a[0] and r[a.length] = b[0].
     */
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        for (int i = 0; i < a.length; i++) {
            c[i] = a[i];
        }
        for (int i = 0; i < b.length; i++) {
            c[a.length + i] = b[i];
        }
        return c;
    }
    /**
     * <p>Overwrites the extended BitSet NUM_OVERWRITES times with random data for security purposes.
     */
    public static void obliviate(BitSet b) {
        obliviate(b, NUM_OVERWRITES);
    }

    /**
     * <p>Overwrites the byte array NUM_OVERWRITES times with random data for security purposes.
     */
    public static void obliviate(byte[] b) {
        obliviate(b, NUM_OVERWRITES);
    }

    /**
     * <p>Overwrites the extended BitSet with random data for security purposes.
     */
    public static void obliviate(BitSet b, int n) {
        java.security.SecureRandom r = new java.security.SecureRandom();
        for (int i=0; i<n; i++) {
            for (int j = 0; j<b.bitSize(); j++) {
                b.set(j, r.nextBoolean());
            }
        }
    }

    /**
     * <p>Overwrites the byte array with random data for security purposes.
     */
    public static void obliviate(byte[] b, int n) {
        for (int i=0; i<n; i++) {
            b[i] = 0x00;
            b[i] = 0x01;
        }

        java.security.SecureRandom r = new java.security.SecureRandom();
        for (int i=0; i<n; i++) {
            r.nextBytes(b);
        }
    }

    public enum KeyType {
        PIN, DATA, MAC
    }

}
