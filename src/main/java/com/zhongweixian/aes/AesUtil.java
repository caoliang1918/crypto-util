package com.zhongweixian.aes;


import com.zhongweixian.CipherType;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @Author caoliang1918@aliyun.com
 *
 * Date 2017/8/5 23:18
 *
 * 工作模式[CBC，CFB，ECB，OFB，PCBC]
 * 填充方式[NoPadding/zero，PKCS5Padding , PKCS7Padding ，ISO10126Padding]
 *
 */
public class AesUtil {

    public static final String IV = "Pdt2WQ6vCU5MBY3n";
    public static final String KEY = "a9VmT4PcXi7gFDkL";


    /**
     * 加密
     * @param data
     * @param password
     * @param iv
     * @return
     */
    public static String encryptAES(String data, String password , String iv , String cipherType) {
        if(StringUtils.isBlank(data)){
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(cipherType);
            SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(), CipherType.AES_ALGORITHM);
            if(!cipherType.contains("CBC")){
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
                cipher.init(Cipher.ENCRYPT_MODE , secretKeySpec, ivParameterSpec);
            }else {
                cipher.init(Cipher.ENCRYPT_MODE , secretKeySpec);
            }
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.encodeBase64String(encrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     * @param decryptCode
     * @param password
     * @param iv
     * @return
     */
    public static String decryptAES(String decryptCode, String password , String iv , String cipherType) {
        if(StringUtils.isBlank(decryptCode)){
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(cipherType);
            SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(), CipherType.AES_ALGORITHM);
            if(!cipherType.contains("CBC")){
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
                cipher.init(Cipher.DECRYPT_MODE , secretKeySpec, ivParameterSpec);
            }else {
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            }
            byte[] encryptByte = Base64.decodeBase64(decryptCode);
            byte[] original = cipher.doFinal(encryptByte);
            return new String(original);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 加密
     * @param data
     * @param password
     * @param iv
     * @return
     */
    public static String encryptAES(String data, String password , String iv){
        return encryptAES(data ,password , iv  , CipherType.AES_CBC_PKC5PADDING);
    }

    /**
     * 解密
     * @param decryptCode
     * @param password
     * @param iv
     * @return
     */
    public static String decryptAES(String decryptCode, String password , String iv) {
        return decryptAES(decryptCode , password , iv , CipherType.AES_CBC_PKC5PADDING);
    }

    public static String encryptAES(String data, String password){
        return encryptAES(data ,password , null  , CipherType.AES_ECB_PKC5PADDING);
    }

    public static String decryptAES(String decryptCode, String password) {
        return decryptAES(decryptCode , password , null , CipherType.AES_ECB_PKC5PADDING);
    }
}
