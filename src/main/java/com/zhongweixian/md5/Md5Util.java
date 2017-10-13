package com.zhongweixian.md5;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.Md5Crypt;

/**
 * @Author caoliang1918@aliyun.com
 * Date 2017/8/5:23:03
 */
public class Md5Util {

    /**
     * 使用Apache提供的md5算法
     * @param content
     * @return
     */
    public static String encrypt(String content){
        return DigestUtils.md5Hex(content.getBytes());
    }
    public static String encrypt16(String content){
        String str = DigestUtils.md5Hex(content.getBytes());
        return str.substring(8,24);
    }

}
