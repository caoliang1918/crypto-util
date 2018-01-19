package com.zhongweixian;

import com.zhongweixian.otp.OtpUtil;
import org.junit.Test;

/**
 * @author : caoliang1918@aliyun.com
 * @date : 2017/11/28  下午4:43
 */
public class OtpTest {

    private static String secret = null;

    @Test
    public void genSecretTest() {
        // 生成密钥
        secret = OtpUtil.generateSecret();

        System.out.println("secret:" + secret);

        //用于二维码
        String auth = OtpUtil.generateQrCode("zhongweixian.org", "caoliang", secret);

        System.out.println("auth:" + auth);

        //验证
        boolean result = OtpUtil.verify(secret, "183273");

        System.out.println("result = " + result);

    }


}
