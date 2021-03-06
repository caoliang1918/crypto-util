package com.zhongweixian.bcrypt;

import com.zhongweixian.sha.ShaUtil;
import org.springframework.security.crypto.bcrypt.BCrypt;

/**
 * @Author caoliang1918@aliyun.com
 *
 * Date 2017/8/4 22:09
 */
public class BcryptUtil {

    final static int ROUNDS = 4;

    /**
     *
     * @param data
     * @return
     */
    public static String encrypt(String data){
        return BCrypt.hashpw(ShaUtil.shaByApache(data), BCrypt.gensalt(ROUNDS));
    }

    /**
     * 验签
     * @param decryptCode
     * @param hashed
     * @return
     */
    public static boolean checkPwd(String decryptCode, String hashed){
        return BCrypt.checkpw(ShaUtil.shaByApache(decryptCode) , hashed);
    }
}
