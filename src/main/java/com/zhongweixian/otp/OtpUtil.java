package com.zhongweixian.otp;

import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;

import java.security.SecureRandom;

/**
 * @author : caoliang
 * @date : 2018/1/19  下午4:48
 */
public class OtpUtil {

    private final static Integer SECRET_LENGTH = 32;

    private static String generateSecret(int length) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[length / 2];
        random.nextBytes(salt);
        return Base32.encode(salt);
    }

    public static String generateSecret64() {
        return generateSecret(64);
    }

    /**
     *
     * @return
     */
    public static String generateSecret() {
        return generateSecret(SECRET_LENGTH);
    }

    /**
     * 取当前的otp Code
     * @param secret
     * @return
     */
    public static String generateOtpCode(String secret) {
        return new Totp(secret).now();
    }


    /**
     * 校验
     *
     * @param secret
     * @param otp
     * @return
     */
    public static boolean verify(String secret, String otp) {
        return new Totp(secret).verify(otp);
    }

    /**
     *
     * @param domain
     * @param user
     * @param secret
     * @return
     */
    public static String generateQrCode(String domain, String user, String secret) {
        return "otpauth://totp/" + domain + "(" + user + ")?secret=" + secret;
    }
}
