package com.zhongweixian;

/**
 * Created by caoliang on 2017/8/4.
 */
public class CipherType {
    //MD5
    public final static String MD5 = "MD5";

    //sha
    public final static String SHA_1 = "SHA-1";
    public final static String SHA_256 = "SHA-256";

    //HMAC
    public final static String HMAC_SHA_1 = "HmacSHA1";
    public final static String HMAC_SHA_256 = "HmacSHA256";

    //AES
    public final static String AES_ALGORITHM = "AES";
    public final static String AES_CBC_PKC5PADDING = "AES/CBC/PKCS5Padding";
    public final static String AES_CBC_NODDING = "AES/CBC/NoPadding"; //NoPadding非填充，明文必须是16的整数倍

    public final static String AES_ECB_PKC5PADDING = "AES/ECB/PKCS5Padding"; //ECB模式，IV不要填
    public final static String AES_ECB_NODDING = "AES/ECB/NoPadding";

    //RSA
    public final static String RSA = "RSA";

    //加密算法
    public final static String RSA_ECB_PSCS1PADDING = "RSA/ECB/PKCS1Padding";
    public final static String RSA_CBC_PSCS1PADDING = "RSA/CBC/PKCS1Padding";

    //签名算法
    public final static String SHA256_RSA = "SHA256withRSA";


}
