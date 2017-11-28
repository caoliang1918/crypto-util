package com.zhongweixian;

import com.zhongweixian.otp.GoogleAuth;
import org.junit.Test;

/**
 * @author : caoliang1918@aliyun.com
 *
 * @date : 2017/11/28  下午4:43
 */
public class AuthTest {

    //当测试authTest时候，把genSecretTest生成的secret值赋值给它
    private static String secret="43TEBIKHQNSHER3N";

    @Test
    public void genSecretTest() {// 生成密钥
        secret = GoogleAuth.generateSecretKey();
        // 把这个qrcode生成二维码，用google身份验证器扫描二维码就能添加成功
        String qrcode = GoogleAuth.getQRBarcode("caoliang1918@gmail.com", secret);
        System.out.println("qrcode:" + qrcode + ",key:" + secret);
    }
    /**
     * 验证optCode
     */
    @Test
    public void verifyTest() {
        String code = "141799";
        long t = System.currentTimeMillis();
        GoogleAuth googleAuth = new GoogleAuth();
        boolean r = googleAuth.checkCode(secret, 697881, t);
        System.out.println("检查code是否正确？" + r);
    }

}
