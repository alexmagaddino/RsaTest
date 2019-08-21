package it.alex;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtils {
    public static String signRSASHA256InBase64WithPrivateBase64Key(String privateKey, byte[] message) {
        try {
            PrivateKey aPrivate = getPrivate(Base64.getDecoder().decode(privateKey));
            return Base64.getEncoder().encodeToString(sign(aPrivate, message));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String signRSASHA256InBase64WithPrivateBase64Key(String privateKey, String message) {
        return signRSASHA256InBase64WithPrivateBase64Key(privateKey, message.getBytes(StandardCharsets.UTF_8));
    }

    public static String encryptInBase64WithPrivateBase64Key(String privateKey, String message) {
        try {
            PrivateKey aPrivate = getPrivate(Base64.getDecoder().decode(privateKey));
            return Base64.getEncoder().encodeToString(encrypt(aPrivate, message));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptInBase64WithPublicBase64Key(String publicKey, String message) {
        try {
            PublicKey aPublic = getPublic(Base64.getDecoder().decode(publicKey));
            return Base64.getEncoder().encodeToString(encrypt(aPublic, message));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptBase64WithPrivateKeyBase64(String privateKey, String message) throws Exception {
        try {
            PrivateKey aPublic = getPrivate(Base64.getDecoder().decode(privateKey));
            return new String(decrypt(aPublic, Base64.getDecoder().decode(message)));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptInBase64WithPrivateBase64Key(String privateKey, byte[] message) {
        try {
            PrivateKey aPrivate = getPrivate(Base64.getDecoder().decode(privateKey));
            return Base64.getEncoder().encodeToString(encrypt(aPrivate, message));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptBase64WithPublicKeyBase64(String publicKey, String message) throws Exception {
        try {
            PublicKey aPublic = getPublic(Base64.getDecoder().decode(publicKey));
            return new String(decrypt(aPublic, Base64.getDecoder().decode(message)));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encrypt(Key privateKey, String message) throws Exception {
        return encrypt(privateKey, message.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] encrypt(Key privateKey, byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(message);
    }

    public static byte[] sign(PrivateKey privateKey, byte[] message) throws Exception {
        Signature sha256withRSA = Signature.getInstance("SHA256withRSA");
        sha256withRSA.initSign(privateKey);
        sha256withRSA.update(message);
        return sha256withRSA.sign();
    }

    public static boolean verify(byte[] toVerify, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(toVerify);
        return publicSignature.verify(signatureBytes);
    }

    public static boolean verifySignatureBase64AndPublicKeyBase64(String message, String signature, String publicKey) {
        try {
            PublicKey aPublic = getPublic(Base64.getDecoder().decode(publicKey));
            byte[] decodeSignature = Base64.getDecoder().decode(signature);
            return verify(message.getBytes(StandardCharsets.UTF_8), decodeSignature, aPublic);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] decrypt(Key publicKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encrypted);
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public static PrivateKey getPrivate(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    public static PublicKey getPublic(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}