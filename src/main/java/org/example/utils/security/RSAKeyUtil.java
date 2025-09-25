package org.example.utils.security;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.security.auth.x500.X500Principal;
import javax.crypto.Cipher;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.utils.Converter;

import java.security.spec.RSAPublicKeySpec;

public class RSAKeyUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final String keyStoreFile = "pos_keystore.p12";
    private final String keyStorePassword = "changeit";
    private final String keyAlias = "pos_rsa";
    private final String ALGORITHM = "RSA/ECB/PKCS1Padding";
    private final String PKCS12= "PKCS12";


    // Generate RSA Key Pair and store in PKCS12 KeyStore
    public void generateRSAKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        } catch (Exception e) {
            keyStore.load(null, null);
        }

        if (keyStore.containsAlias(keyAlias)) {
            System.out.println("Key already exists in KeyStore");
            return;
        }

        // RSA 2048-bit with exponent 3
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
        KeyPair keyPair = keyGen.generateKeyPair();

        // Optional self-signed certificate (100 years)
        X500Principal subject = new X500Principal("CN=" + keyAlias);
        long validFrom = System.currentTimeMillis();
        long validUntil = validFrom + (100L * 365 * 24 * 60 * 60 * 1000);
        X509Certificate cert = generateSelfSignedCertificate(keyPair, subject, validFrom, validUntil);

        keyStore.setKeyEntry(keyAlias, keyPair.getPrivate(), keyStorePassword.toCharArray(), new Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            keyStore.store(fos, keyStorePassword.toCharArray());
        }

        System.out.println("RSA KeyPair generated and stored in KeyStore.");
    }

    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair, X500Principal subject, long validFrom, long validUntil) throws Exception {
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                new java.util.Date(validFrom),
                new java.util.Date(validUntil),
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

    // Encrypt using public key
    public String encrypt(String plainText) throws Exception {
        PublicKey publicKey = getPublicKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Converter.byteArrayToHexString_2(encrypted);
    }

    // Decrypt using private key
    public String decrypt(String hexCipherText) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyStorePassword.toCharArray());
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Converter.hexStringToByteArray_2(hexCipherText));
        return new String(decrypted);
    }

    public String decryptBySenderPK(PublicKey senderPublicKey , String encryptedData) throws Exception {
        byte[] signature = Converter.hexStringToByteArray_2(encryptedData);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, senderPublicKey);
        return Converter.byteArrayToHexString_2(cipher.doFinal(signature));

    }

    public PublicKey hexToPublicKey(String senderPk) throws Exception {

        if(senderPk.length() == 276){
            senderPk = senderPk.substring(14, senderPk.length() - 6);
        }else if(senderPk.length() == 274){
            senderPk = senderPk.substring(12, senderPk.length() - 6);
        } else if(senderPk.length() == 534){
            senderPk = senderPk.substring(16, senderPk.length() - 6);
        } else if (senderPk.length() == 536){
            senderPk = senderPk.substring(18, senderPk.length() - 6);
        }else{
            return null;
        }

        BigInteger modulus = new BigInteger(senderPk, 16);
        BigInteger exponent = new BigInteger("03", 16);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }



    // Return public key in DER format (hex)
    public String getPublicKeyDERHex() throws Exception {
        PublicKey publicKey = getPublicKey();
        byte[] derBytes = publicKey.getEncoded(); // ASN.1 DER SubjectPublicKeyInfo
        return Converter.byteArrayToHexString_2(derBytes);
    }

    private PublicKey getPublicKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }
        Certificate cert = keyStore.getCertificate(keyAlias);
        if (cert == null) throw new RuntimeException("Certificate not found for alias: " + keyAlias);
        return cert.getPublicKey();
    }
}