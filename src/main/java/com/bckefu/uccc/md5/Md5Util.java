package com.bckefu.uccc.md5;

import org.springframework.util.DigestUtils;

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
        return DigestUtils.md5DigestAsHex(content.getBytes());
    }
}
