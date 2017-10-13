package com.zhongweixian;

import com.zhongweixian.aes.AesUtil;
import com.zhongweixian.hmac.HmacUtil;
import com.zhongweixian.md5.Md5Util;
import com.zhongweixian.rsa.RsaUtil;
import com.zhongweixian.sha.ShaUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.UnsupportedEncodingException;
import java.security.SignatureException;


public class BckefuCryptoApplicationTests {
	Logger logger = LoggerFactory.getLogger(BckefuCryptoApplicationTests.class);
	String data = "caoliang";

	@Test
	public void hMacTest() throws SignatureException {
		String encrypt = HmacUtil.hmacSha256Hex(data , "key");
		System.out.println(encrypt);
	}
	@Test
	public void shaTest() throws UnsupportedEncodingException {

		String encrypt2 = ShaUtil.shaByApache(data);
		String encrypt3 = ShaUtil.shaByJDK(data);
		logger.info("sha256加密 :{}",encrypt2);
		logger.info("sha256加密 :{}",encrypt3);
	}
	@Test
	public void md5Test(){
		String encrypt2 = Md5Util.encrypt16(data);
		System.out.println(encrypt2);
	}

	@Test
	public void aesTest(){
		String content = "18612983191";
		logger.info("加密前：{}" , content);
		String encryptResult = AesUtil.encryptAES(content, AesUtil.KEY , AesUtil.IV);
		logger.info("加密后 : {}" , encryptResult);
		String decryptResult = AesUtil.decryptAES(encryptResult, AesUtil.KEY , AesUtil.IV);
		logger.info("解密后：{}" , decryptResult);
	}
	@Test
	public void rsaTest(){


		String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviSuCu4Yg/WAyjp06qiaE/ioI2M/ACT9UTUVxWtM7IZlXMQZPjLn0H1x0zmJ/VLIhnBliyb06QLvtrrBFRt4jnOJR5LjoTg/g8XYdVXN6a+XFjqFvOUPgzZ7OdywOoXxiO+M7WrvT0XgqyBqCnDADpY1eucDqfIDYYOBHKbtMkh0N4ZVBcfULb1Sm+Q7ed+jUa8eXPQPhMrWvhQkIeZJh+hCIrNjXUxyfZPh1tSvqoJYArbyHZs8LnbUtjIQCx9OlR9+xJTx3L9h89I4D+hqA4CZqxUzfibsu5XgYKnoSri2OCR2FefSfYlCd8Fysp0wET/r1L141qnhoMQtrUs8jwIDAQAB";
		String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+JK4K7hiD9YDKOnTqqJoT+KgjYz8AJP1RNRXFa0zshmVcxBk+MufQfXHTOYn9UsiGcGWLJvTpAu+2usEVG3iOc4lHkuOhOD+Dxdh1Vc3pr5cWOoW85Q+DNns53LA6hfGI74ztau9PReCrIGoKcMAOljV65wOp8gNhg4Ecpu0ySHQ3hlUFx9QtvVKb5Dt536NRrx5c9A+Eyta+FCQh5kmH6EIis2NdTHJ9k+HW1K+qglgCtvIdmzwudtS2MhALH06VH37ElPHcv2Hz0jgP6GoDgJmrFTN+Juy7leBgqehKuLY4JHYV59J9iUJ3wXKynTARP+vUvXjWqeGgxC2tSzyPAgMBAAECggEAMhFkhtpFOFIoFJgp+zRkRgf+9jqG91nGHmEVF4P2oH2PKUs1vmwXII43r8AB9uOai9QC2Q5sBQNR7dLlTtKJ/zCrIF6sc+JkzyUEp3jtnLAw35iPaLsER6/L6OOUwARPIpi5ijbTRxOGYmlJovAnkm+5K2CzVUe13jKLh+joool/ReZk0Rsr4tVLSLmvzDA/sRwYun0x0+jl5EZSQfwsVyN9bD5rY/In/EuvH9yj5R4lPe+mimF4Os6IgTsP5LzqDTAiFx5NNioFRJ2SkcTmM0CZQeMIBuvvF2HCtJlDEfCytD7wYup3GBvar2ccOe9T3YhJdsj5bfAJHVJtamxQwQKBgQDnYReMMzqAh2HOFL8QymzOjImsrOz6NCZatq38TU1hSe9PK+C0sFGhkd788y4AuURS1Btu4i7F+hOYcj1z3L+NSPGE3yLHVjakMrrNbA9rwG/t7oU0cG7d0WWM9bcTQiCSNcUyt69BGH3dZdqee1tITzqghE7+gh9RYiVcI6/8LwKBgQDSYEuWFLMUsR/s7unSHCucuEXjwbYrvknv8Y81sjvrWktNXrJoYlbGy/7HYA6lxzchtSxhPuUSjopwQ5scgMhqf8Gxz7jsDN9ak2dErF7cWRFYfh6aKhkbEw9oG01jIX15MK0TbMafoJslDhPQF1cP9i0+ZGg+gPbASdeUVRTNoQKBgQCOjwDOLgYeiMtXCOtL8hymCmsNDCKaaiUzgRijuhEyHzamJhe13Gj/TnwAh+hRI9UX333jjNJawqDuLXz1dQ5Eg6vjPQQVo2XZNzRnOuwpbJDKHUrPK3Lzkn+qIP6ii/y7eQu+GvSM/AUYsxfGy6RLYh1yJvLw1sVrBDiWk5prmwKBgFvgrmI3XBa3XKgPl5KptupVGEDmAveLvaLLLq5WzxB0eNqrduNbv2ZHBVhxvTPtk0hnZaB65XR7SD7LZ9zE6cKJVUCg5bRB0vIt2jYFydAWHhs1yYuuwxQt+NaQxfV7VN8uwQfww7ZHYDqIsWJ6Lw3Lh+rt0xEpJZrJJRulJNbBAoGBAK1OEnfBpSB99N8gdhp+ZGLsDfwFCQ2Cd4Jpsd4hxdwbXevNuA1OiE20sHPuKqEqfOKocgTMobCwbSfnymatRydVoeUumkEc4Ja+XDgH+P1eXQLdIuRCwh0AXl+vkuOCBDMw367Zp/j6vwPlNKh9ZmOBPwhV0Syv2Z8uGkTZ6g+f";


		logger.info("公钥加密——私钥解密");
		String source = "caoliangcaoliangcaoliang";
		logger.info("加密前文字：{}" , source);
		String aData = RsaUtil.encrypt(source , publicKey );
		logger.info("加密后文字：{}" ,  aData);
		String dData = RsaUtil.decrypt(aData , privateKey );
		logger.info("解密后文字: {}" , dData);

		logger.info("{}" ,RsaUtil.generateKeyPair().toString());

	}



}
