package org.example.utils.security;


import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.example.utils.Converter;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class KeyStoreUtil {

    public final String PKCS12 = "PKCS12";
    public final String ALGORITHM1 = "RSA/ECB/PKCS1Padding";
    public final String ALGORITHM2 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public final String ALGORITHM3 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";


    public final String RSA = "RSA";
    private String TAG = "KeyStoreUtil";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public String keyStoreFile = "mykeystore.p12";
    public String keyStorePassword = "changeit";
    public String keyAlias = "pos_rsa";


    public void generateRSAKeyForPKC() throws Exception {


        KeyStore keyStore = KeyStore.getInstance(PKCS12);

        if (keyStore.containsAlias(keyAlias)) {
            System.out.println("Key already exists in KeyStore");
            return;
        }

        // Generate RSA KeyPair
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(spec);
        KeyPair keyPair = generator.generateKeyPair();

        // Generate self-signed certificate (lifetime)
        X500Principal subject = new X500Principal("CN=" + keyAlias);
        long validFrom = System.currentTimeMillis();
        long validUntil = Long.MAX_VALUE; // practically lifetime
        X509Certificate cert = generateSelfSignedCertificateForPKC(keyPair, subject, validFrom, validUntil);

        // Store PrivateKey + certificate in KeyStore
        keyStore.setKeyEntry(keyAlias, keyPair.getPrivate(), keyStorePassword.toCharArray(), new Certificate[]{cert});

        // Save KeyStore to file
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            keyStore.store(fos, keyStorePassword.toCharArray());
        }

        System.out.println("RSA KeyPair generated and stored in KeyStore: " + keyStoreFile);
    }

    private static X509Certificate generateSelfSignedCertificateForPKC(KeyPair keyPair, X500Principal subject, long validFrom, long validUntil) throws Exception {
        // Build certificate using BouncyCastle
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                new Date(validFrom),
                new Date(validUntil),
                subject,
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }


    public void generateRSAKey(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        keyStore.load(null);

        if (keyStore.containsAlias(keyName)) {
            System.out.println("Key alias already exists.");
            return;
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)); //modulus(1024-bit) + expo(03)
        generator.initialize(spec);
        KeyPair keyPair = generator.generateKeyPair();

        long validFrom = System.currentTimeMillis();
        long validUntil = Long.MAX_VALUE;
        X500Principal subject = new X500Principal("CN=" + keyName);

        Certificate selfSignedCert = generateSelfSignedCertificate(keyPair, subject, validFrom, validUntil);

        keyStore.setKeyEntry(keyName, keyPair.getPrivate(), null, new Certificate[]{selfSignedCert});

        System.out.println("Keys successfully generated and stored in Android Keystore with alias: " + keyName);
    }

    private Certificate generateSelfSignedCertificate(KeyPair keyPair, X500Principal subject, long validFrom, long validUntil) throws Exception {
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                new Date(validFrom),
                new Date(validUntil),
                subject,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);
    }


    public String getPublicKey(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);

        try (FileInputStream fis = new FileInputStream("mykeystore.p12")) {
            keyStore.load(fis, "changeit".toCharArray());
        }


        PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();

        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

            BigInteger modulus = rsaPublicKey.getModulus();
            // Exponent
            BigInteger exponent = rsaPublicKey.getPublicExponent();

            // Convert to hex string for display
            String modulusHex = Converter.byteArrayToHexString_2(modulus.toByteArray());
            String exponentHex = Converter.byteArrayToHexString_2(exponent.toByteArray());
           System.out.println("Modulus: " + modulusHex + "\nExponent: " + exponentHex);

            // X.509 SubjectPublicKeyInfo + ASN1 encoded info + publicKey

            byte[] publicKeyWithX509Info = rsaPublicKey.getEncoded();


            // Here where i remove SubjectPublicKeyInfo in begin of (ASN1 +PublicKey)
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                    ASN1Sequence.getInstance(publicKeyWithX509Info));

            byte[] encodedPublicKey = subjectPublicKeyInfo.parsePublicKey().getEncoded();

            return Converter.byteArrayToHexString_2(encodedPublicKey);

        } else {
            System.out.println("Key is not an RSA public key.");
        }
        return "";
    }

    public String getPublicKey(String keyName, String keyStoreFile, String keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }

        Certificate cert = keyStore.getCertificate(keyName);
        if (cert == null) {
            throw new RuntimeException("No certificate found for alias: " + keyName);
        }

        PublicKey publicKey = cert.getPublicKey();
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new RuntimeException("Key is not an RSA public key");
        }

        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        String modulusHex = Converter.byteArrayToHexString_2(rsaPublicKey.getModulus().toByteArray());
        String exponentHex = Converter.byteArrayToHexString_2(rsaPublicKey.getPublicExponent().toByteArray());

        System.out.println("Modulus: " + modulusHex);
        System.out.println("Exponent: " + exponentHex);

        return modulusHex + ":" + exponentHex;
    }


    public String getSignature(String keyName, byte[] dataToSign) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        keyStore.load(null);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        signature.update(dataToSign);
        
        byte[] signatureBytes = signature.sign();

        return Converter.byteArrayToHexString_2(signatureBytes);
    }

    public byte[] encrypt(String keyName , byte[] encryptedData) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        keyStore.load(null);

        PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();

        Cipher cipher = Cipher.getInstance(ALGORITHM1);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedData);
    }

    public byte[] decrypt(String keyName , byte[] encryptedData) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        keyStore.load(null);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
        Cipher cipher = Cipher.getInstance(ALGORITHM1);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public byte[] globalEncrypt(String keyName , byte[] encryptedData) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        keyStore.load(null);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);

        Cipher cipher = Cipher.getInstance(ALGORITHM1);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public byte[] globalDecrypt(String keyName , byte[] encryptedData) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        keyStore.load(null);

        PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM1);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedData);
    }

    public Pair<String, String> getModulusAndExpo(String publicKeyHex) {
        byte[] publicKeyBytes = Converter.hexStringToByteArray_2(publicKeyHex);
        BigInteger modulus = null;
        BigInteger exponent = null;

        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(publicKeyBytes))) {
            ASN1Primitive obj = asn1InputStream.readObject();

            // Handle the SubjectPublicKeyInfo wrapper
            ASN1Sequence sequence = (ASN1Sequence) obj;
            ASN1BitString publicKeyBitString = (ASN1BitString) sequence.getObjectAt(1);
            byte[] rsaKeyBytes = publicKeyBitString.getOctets();

            try (ASN1InputStream rsaKeyInput = new ASN1InputStream(new ByteArrayInputStream(rsaKeyBytes))) {
                ASN1Sequence rsaSequence = (ASN1Sequence) rsaKeyInput.readObject();
                modulus = ((ASN1Integer) rsaSequence.getObjectAt(0)).getValue();
                exponent = ((ASN1Integer) rsaSequence.getObjectAt(1)).getValue();
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse public key", e);
        }

        String modulusHex = modulus.toString(16);
        String exponentHex = exponent.toString(16);

        return new ImmutablePair<>(modulusHex, exponentHex);
    }


    public Pair<String, String> getModulusAndExpo2(String publicKeyHex) {

        BigInteger modulus = null;
        BigInteger exponent = null;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] keyBytes = Converter.hexStringToByteArray_2(publicKeyHex);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            PublicKey fileGeneratedPublicKey = keyFactory.generatePublic(spec);
            RSAPublicKey rsaPub  = (RSAPublicKey)(fileGeneratedPublicKey);
            modulus = rsaPub.getModulus();
            exponent = rsaPub.getPublicExponent();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        String modulusHex = "";
        String exponentHex = "";
        if(modulus != null && exponent != null){
            modulusHex = modulus.toString(16);
            exponentHex = exponent.toString(16);
        }

        return new ImmutablePair<>(modulusHex, exponentHex);
    }

    public PublicKey hexToPublicKey(String senderPk) throws Exception {

        if(senderPk.length() == 276){
            senderPk = senderPk.substring(14, senderPk.length() - 6);
        }else if(senderPk.length() == 274){
            senderPk = senderPk.substring(12, senderPk.length() - 6);
        } else if(senderPk.length() == 534){
            senderPk = senderPk.substring(16, senderPk.length() - 6);
        } else{
            return null;
        }

        BigInteger modulus = new BigInteger(senderPk, 16);
        BigInteger exponent = new BigInteger("03", 16);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    private static class ASN1ParseResult {
        final BigInteger modulus;
        final BigInteger exponent;

        ASN1ParseResult(BigInteger modulus, BigInteger exponent) {
            this.modulus = modulus;
            this.exponent = exponent;
        }
    }


    public PublicKey hexToPk(String hexKey) throws Exception {
        if (hexKey == null || hexKey.length() < 10) {
            throw new IllegalArgumentException("Invalid hex key length");
        }

        // Convert hex to bytes for easier parsing
        byte[] keyBytes = Converter.hexStringToByteArray_2(hexKey);

        // Parse ASN.1 DER structure
        ASN1ParseResult result = parseASN1DER(keyBytes);

        if (result == null) {
            throw new IllegalArgumentException("Could not parse ASN.1 DER structure");
        }

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(result.modulus, result.exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    private ASN1ParseResult parseASN1DER(byte[] data) {
        try {
            int offset = 0;

            // Skip SEQUENCE tag (0x30)
            if (data[offset] != 0x30) {
                return null;
            }
            offset++;

            // Skip length
            offset += getLengthSize(data, offset);

            // Look for INTEGER tag (0x02) - this should be the modulus
            while (offset < data.length - 6) { // Leave space for exponent
                if (data[offset] == 0x02) {
                    // Found INTEGER tag, parse modulus
                    offset++; // Skip tag
                    int modulusLength = getLength(data, offset);
                    offset += getLengthSize(data, offset - 1); // Skip length bytes

                    // Skip leading zero if present (for positive numbers)
                    if (data[offset] == 0x00) {
                        offset++;
                        modulusLength--;
                    }

                    // Extract modulus
                    byte[] modulusBytes = new byte[modulusLength];
                    System.arraycopy(data, offset, modulusBytes, 0, modulusLength);
                    BigInteger modulus = new BigInteger(1, modulusBytes);

                    // Move to next field
                    offset += modulusLength;

                    // Look for exponent (next INTEGER)
                    if (offset < data.length && data[offset] == 0x02) {
                        offset++; // Skip tag
                        int exponentLength = getLength(data, offset);
                        offset += getLengthSize(data, offset - 1);

                        byte[] exponentBytes = new byte[exponentLength];
                        System.arraycopy(data, offset, exponentBytes, 0, exponentLength);
                        BigInteger exponent = new BigInteger(1, exponentBytes);

                        return new ASN1ParseResult(modulus, exponent);
                    } else {
                        // If no exponent found, assume it's 3 (common default)
                        return new ASN1ParseResult(modulus, new BigInteger("3"));
                    }
                }
                offset++;
            }

            return null;
        } catch (Exception e) {
            // Fallback to your original hardcoded approach
            return parseWithHardcodedOffsets(data);
        }
    }

    private int getLengthSize(byte[] data, int offset) {
        int length = data[offset] & 0xFF;
        if ((length & 0x80) == 0) {
            return 1;
        } else {
            return 1 + (length & 0x7F);
        }
    }

    private int getLength(byte[] data, int offset) {
        int length = data[offset] & 0xFF;
        if ((length & 0x80) == 0) {
            // Short form
            return length;
        } else {
            // Long form
            int numBytes = length & 0x7F;
            int result = 0;
            for (int i = 1; i <= numBytes; i++) {
                result = (result << 8) | (data[offset + i] & 0xFF);
            }
            return result;
        }
    }

    private ASN1ParseResult parseWithHardcodedOffsets(byte[] data) {
        String hexKey = Converter.byteArrayToHexString_2(data);
        String modulusHex = null;

        // Your original logic as fallback
        if (hexKey.length() == 276) {
            modulusHex = hexKey.substring(14, hexKey.length() - 6);
        } else if (hexKey.length() == 274) {
            modulusHex = hexKey.substring(12, hexKey.length() - 6);
        } else if (hexKey.length() == 534) {
            modulusHex = hexKey.substring(16, hexKey.length() - 6);
        }

        if (modulusHex != null) {
            BigInteger modulus = new BigInteger(modulusHex, 16);
            BigInteger exponent = new BigInteger("03", 16);
            return new ASN1ParseResult(modulus, exponent);
        }

        return null;
    }


    public String encryptBySenderPK(PublicKey senderPublicKey , byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM1);
        cipher.init(Cipher.ENCRYPT_MODE, senderPublicKey);
        String encryptedDataHex = Converter.byteArrayToHexString_2(cipher.doFinal(data));
        return Converter.hexToAscii(encryptedDataHex);
    }

    public String decryptBySenderPK(PublicKey senderPublicKey , String _signature) throws Exception {
        byte[] signature = Converter.hexStringToByteArray_2(_signature);
        Cipher cipher = Cipher.getInstance(ALGORITHM1);
        cipher.init(Cipher.DECRYPT_MODE, senderPublicKey);
        return Converter.byteArrayToHexString_2(cipher.doFinal(signature));
    }

    public String hash(String input , int hashAlgo , boolean isHex) {
        try {
            MessageDigest md;
            StringBuilder sb = new StringBuilder();

            if(hashAlgo == 512 ){
                md = MessageDigest.getInstance("SHA-512");
            }else{
                md = MessageDigest.getInstance("SHA-512");
            }

            if(isHex){

                byte[] digest = md.digest(Converter.hexStringToByteArray_2(input));
                for (byte b : digest) {
                    sb.append(String.format("%02x", b));
                }

            }else{

                byte[] digest = md.digest(input.getBytes());
                for (byte b : digest) {
                    sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
                }

            }

            return sb.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-512 algorithm not found", e);
        }
    }

    public String encrypt3DES(String DESKey , String input) throws Exception {

        byte[] key = Converter.getByteDESKey(DESKey);

        byte[] paddedBytes = Converter.hexStringToByteArray_2(input);

        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key , "DESede"));

        return Converter.byteArrayToHexString_2(cipher.doFinal(paddedBytes)).toUpperCase();
    }

    public String decrypt3DES(String DESKey , String input) throws Exception {

       System.out.println("KeyStoreUtil : " + DESKey);
        byte[] key = Converter.getByteDESKey(DESKey);

        byte[] inputBytes = Converter.hexStringToByteArray_2(input);

        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key , "DESede"));

        return Converter.byteArrayToHexString_2(cipher.doFinal(inputBytes)).toUpperCase();
    }

    public String encryptISO9797Alg3Mac(String DESKey , String input){


        byte[] key= Converter.getByteDESKey(DESKey);

        byte[] data = Converter.hexStringToByteArray_2(input);

        BlockCipher cipher = new DESEngine();

        ISO9797Alg3Mac mac = new ISO9797Alg3Mac(cipher, 64);

        KeyParameter keyP = new KeyParameter(key);

        mac.init(keyP);
        mac.update(data, 0, data.length);

        byte[] out = new byte[8];

        mac.doFinal(out, 0);

        return Converter.byteArrayToHexString_2(out);
    }

    public String padHexMessage(String hexMessage) {

        if (hexMessage == null || !hexMessage.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("Invalid hex message");
        }

        int messageLength = hexMessage.length();
        int remainder = messageLength % 16;

        int paddingLength;
        if (remainder <= 14) {
            paddingLength = 16 - remainder;
        } else {
            paddingLength = (16 - remainder) + 16;
        }

        StringBuilder paddedMessage = new StringBuilder(hexMessage);
        for (int i = 0; i < paddingLength - 2; i++) {
            paddedMessage.append('0');
        }
        paddedMessage.append(String.format("%02X", paddingLength));
       System.out.println("Added padding Hex Message : " + paddedMessage );
        //TODO : FOR DEBUG
        removeHexPadding(paddedMessage.toString());
        return paddedMessage.toString();
    }

    public String removeHexPadding(String paddedMessage) {

        if (paddedMessage == null || paddedMessage.length() < 2 || !paddedMessage.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("Invalid padded message");
        }
        String lengthHex = paddedMessage.substring(paddedMessage.length() - 2);
        int paddingLength = Integer.parseInt(lengthHex, 16);

        if (paddingLength < 2 || paddingLength > 32 || paddingLength > paddedMessage.length()) {
            throw new IllegalArgumentException("Invalid padding length");
        }

        String removedPaddedMsg =  paddedMessage.substring(0, paddedMessage.length() - paddingLength);
        // Remove padding including length byte
       System.out.println("Removed padding Hex Message: " + removedPaddedMsg);
        return removedPaddedMsg;
    }

    public static String addEncryptionTag(String data , String version){
        return "@@"+version+"@@"+data;
    }

    public static String removeEncryptionTag(String data) {
        String begin = "@@" + "V1"+ "@@";
        int tagLength = begin.length();
        if (data.startsWith(begin)) {
            data = data.substring(tagLength);
        }
        return data;
    }


}