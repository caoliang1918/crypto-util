package com.zhongweixian.sha;

import com.zhongweixian.CipherType;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by caoliang on 2017/8/4.
 */
public class ShaUtil {

    static char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String shaByApache(String data){
        return shaByApache(data , CipherType.SHA_256);
    }
    public static String shaByJDK(String data){
        return shaByApache(data , CipherType.SHA_256);
    }

    /**
     * Apache官方提供的散列算法
     * @param data
     * @param algorithm
     * @return
     */
    public static String shaByApache(String data , String algorithm){
        MessageDigest messageDigest;
        String encdeStr = "";
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
            byte[] hash = messageDigest.digest(data.getBytes("UTF-8"));
            encdeStr = Hex.encodeHexString(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return encdeStr;
    }

    /**
     * java原生散列算法
     * @param data
     * @param algorithm
     * @return
     */
    public static String shaByJDK(String data , String algorithm){
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
            byte[] hash = messageDigest.digest(data.getBytes("UTF-8"));
            int j = hash.length;
            char[] buf = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = hash[i];
                buf[k++] = hexDigits[byte0 >>> 4 & 0xf];
                buf[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(buf);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return encodeStr;
    }


}
