package org.example;

import org.example.utils.security.RSAKeyUtil;
import org.example.utils.security.dukpt.DukptManager;

import java.security.PublicKey;


public class Main {
    static RSAKeyUtil util = new RSAKeyUtil();

    public static void main(String[] args) throws Exception {
        util.generateRSAKey();

        String message = "Test DUKPT IPEK";
        String encrypted = util.encrypt(message);
        System.out.println("Encrypted (hex): " + encrypted);

        String decrypted = util.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);

        String publicHex = util.getPublicKeyDERHex();
        System.out.println("Public Key Der  Hex: " + publicHex);

        test01();

        dukptTest();
    }

    public static void test01() throws Exception{
        String senderPublicKey = "3082010702820100BA0C9F5251B48A83D4E4A25B202F6C1D54123C8F1182E7E496CCEA7AA9C5C926DE10D8E0A456283F8A7F770DFFA29C7F7E2EEBB86302FE467BCB299962026D4CDC058559F81D0BCB9857BDA86D7DA05E793D6D24433A36302EF0829CC527D7AC0A9B67E6B1FF6B4320531CA42CF1B7759E05FB4B5BD71C9E3AAFCAC3EC87463A225D70868CCEC50DD4F50934E9D6F006C0418DDD0DAC06D00082BF51ACD51404F849692D203DF539FDDBD29B3340E6588BC520AA0EA5BFC4075306F6F1EC4F9E421F866798AC0DA15D1CE2A8114778931CA3918110F67CCBB852FD9A22D838BEC3FDBA0C25F610E2967980234DEBA006D19D9B5380AD8FA035A85BAFDCD61E81020103";
        String encryptedSignature  = "9e7f7b7f6d06012915a4bd46628367bc0c9fe564e8edac43534a661c279fb346846a33a298cae1cc89db3472596698d5ca489f201681b3d9d0e10095ba62624adee5264e9a14fc1c89f4066264db5692c424f7f258dd20423eaee1856be9cc4d8da7b02964fe039a20ac2dc621423ed8068693c88f233db164d1f62e8c50141539568474ac23d134f5d2b360e9e81e9658cbd7a74658bf47ea63757b801884a5a4d30b79d1ed1cdd2ff6caeac1ba35eaecab17f17048b1fbfeedb1eac743193ef67e3a78608afc546072e473521b73b307055e72826c366856dbed94e2f9503e6a2af95224e6b432a529ef147a3abe9743aa1fbf1fc492e2e6cd835e0802a996";
        PublicKey hexToPub = util.hexToPublicKey(senderPublicKey);


        String decryptedSignature = util.decryptBySenderPK(hexToPub, encryptedSignature);

        System.out.println("Decrypted Signature :" +   decryptedSignature);
    }

    public static void dukptTest() throws Exception {

        DukptManager dukpt = new DukptManager(
                "A7A39D60C7BB7BDBB78918823B1199A0",
                "FFFF3C54990041A"
        );
        System.out.println(dukpt.getKsnInfo());

        String pinDerivedKey = dukpt.deriveAndRegisterKey("pin");
        String dataDerivedKey = dukpt.deriveAndRegisterKey("data");
        String macDerivedKey = dukpt.deriveAndRegisterKey("mac");

        System.out.println("PIN DERIVED KEY : " + pinDerivedKey);
        System.out.println("DATA DERIVED KEY : " + dataDerivedKey);
        System.out.println("MAC DERIVED KEY : " + macDerivedKey);

        dukpt.incrementKSN();
        System.out.println(dukpt.getKsnInfo());

        System.out.println("-------------------------------------------------");

        String pinDerivedKey1 = dukpt.deriveAndRegisterKey("pin");
        String dataDerivedKey1 = dukpt.deriveAndRegisterKey("data");
        String macDerivedKey1 = dukpt.deriveAndRegisterKey("mac");

        System.out.println("PIN DERIVED KEY : " + pinDerivedKey1);
        System.out.println("DATA DERIVED KEY : " + dataDerivedKey1);
        System.out.println("MAC DERIVED KEY : " + macDerivedKey1);

        dukpt.incrementKSN();
        System.out.println(dukpt.getKsnInfo());

        System.out.println("-------------------------------------------------");

        String pinDerivedKey2 = dukpt.deriveAndRegisterKey("pin");
        String dataDerivedKey2 = dukpt.deriveAndRegisterKey("data");
        String macDerivedKey2 = dukpt.deriveAndRegisterKey("mac");

        System.out.println("PIN DERIVED KEY : " + pinDerivedKey2);
        System.out.println("DATA DERIVED KEY : " + dataDerivedKey2);
        System.out.println("MAC DERIVED KEY : " + macDerivedKey2);
    }
}