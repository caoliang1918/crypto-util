package com.bckefu.uccc.rsa;

import com.bckefu.uccc.CipherType;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by caoliang on 2017/8/7.
 * RSA是第一个能同时用于加密和数宇签名的算法
 */
public class RsaUtil {
    public final static int KEY_SIZE = 2048;


    public static Map<String , String> generateKeyPair(){
        Map<String , String> map = new HashMap<String , String>();
        //创建随机数源
        SecureRandom secureRandom = new SecureRandom();
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CipherType.RSA);
            keyPairGenerator.initialize(KEY_SIZE , secureRandom);

            //生成秘钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            //生成公私钥
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            //密钥转成字符串
            String publicKeyString = getKeyString(publicKey);
            String privateKeyString = getKeyString(privateKey);

            map.put("publicKey", publicKeyString);
            map.put("privateKey", privateKeyString);

            RSAPublicKey rsp = (RSAPublicKey) keyPair.getPublic();
            BigInteger bint = rsp.getModulus();
            byte[] b = bint.toByteArray();
            byte[] deBase64Value = Base64.encodeBase64(b);
            String retValue = new String(deBase64Value);
            map.put("modulus", retValue);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return map;
    }

    /**
     * 字符串转换成公钥
     * @param key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PublicKey getPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.decodeBase64(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(CipherType.RSA);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 字符串转换成私钥
     * @param key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PrivateKey getPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.decodeBase64(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(CipherType.RSA);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 密钥转成字符串
     * @param key
     * @return
     * @throws Exception
     */
    public static String getKeyString(Key key){
        byte[] keyBytes = key.getEncoded();
        return Base64.encodeBase64String(keyBytes);
    }

    /**
     * 公钥加密
     * @param data
     * @param publicKey
     * @return
     */
    public static String  encrypt(String data , String publicKey){
        return encrypt(data , publicKey , CipherType.RSA_ECB_PSCS1PADDING);
    }
    /**
     * 公钥加密
     * @param data
     * @param publicKey
     * @return
     */
    public static String encrypt(String data , String publicKey , String cipherType){
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherType);
            cipher.init(Cipher.ENCRYPT_MODE,getPublicKey(publicKey));
            byte[] enBytes = cipher.doFinal(data.getBytes());
            return Base64.encodeBase64String(enBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥解密
     * @param encryptCode
     * @param privateKey
     * @return
     */
    public static String decrypt(String encryptCode , String privateKey ){
        return decrypt(encryptCode , privateKey , CipherType.RSA_ECB_PSCS1PADDING);
    }

    /**
     * 私钥解密
     * @param encryptCode
     * @param privateKey
     * @return
     */
    public static String decrypt(String encryptCode , String privateKey , String cipherType){
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(CipherType.RSA_ECB_PSCS1PADDING);
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
            byte[] deBytes = cipher.doFinal(Base64.decodeBase64(encryptCode));
            return new String(deBytes);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 签名
     * @param plainText
     * @param privateKeyString
     * @return
     */
    public static String sign(String plainText, String privateKeyString) {
        PrivateKey privateKey = null;
        try {
            privateKey = getPrivateKey(privateKeyString);
            Signature signature = Signature.getInstance(privateKey.getAlgorithm()); //推荐SHA256withRSA
            signature.initSign(privateKey);
            signature.update(plainText.getBytes());
            return new String(Base64.encodeBase64(signature.sign()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 验证签名
     * @param encryptString
     * @param signatureString
     * @param publicKeyString
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyData(String encryptString, String signatureString, String publicKeyString) {
        PublicKey publicKey = null;
        try {
            publicKey = getPublicKey(publicKeyString);
            byte[] signatureBytes = Base64.decodeBase64(signatureString);
            Signature signature = Signature.getInstance(publicKey.getAlgorithm());//SHA256withRSA
            signature.initVerify(publicKey);
            signature.update(encryptString.getBytes("UTF-8"));
            return signature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }


}
