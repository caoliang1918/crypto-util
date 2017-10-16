package com.zhongweixian;

import com.zhongweixian.aes.AesUtil;
import com.zhongweixian.hmac.HmacUtil;
import com.zhongweixian.md5.Md5Util;
import com.zhongweixian.rsa.RsaUtil;
import com.zhongweixian.sha.ShaUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;


public class BckefuCryptoApplicationTests {
	Logger logger = LoggerFactory.getLogger(BckefuCryptoApplicationTests.class);
	String data = "caoliang";

	@Test
	public void hMacTest() throws SignatureException {
		String encrypt = HmacUtil.hmacSha256Hex(data , "key");
		System.out.println(encrypt);
	}
	@Test
	public void shaTest(){

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
		logger.debug("加密前：{}" , content);
		String encryptResult = AesUtil.encryptAES(content, AesUtil.KEY , AesUtil.IV);
		logger.debug("加密后 : {}" , encryptResult);
		String decryptResult = AesUtil.decryptAES(encryptResult, AesUtil.KEY , AesUtil.IV);
		logger.info("解密后：{}" , decryptResult);
	}
	@Test
	public void rsaTest() throws InvalidKeySpecException, NoSuchAlgorithmException {
		logger.info("{}" ,RsaUtil.generateKeyPair().toString());


		String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdnu22ITZvmuc5kdhO5oh650tz\n" +
				"taBxNvVVfYvVIBkAfjvItSmQxcYBgS8kln25pauTpOAfKxG5rkorfkdNX9PA5Ctq\n" +
				"0C8itYEyob8DV16kn2r5IOkn/eA4z4MnbJnhkMyAsaX5Weu/cuGx3FCFSiUct3j7\n" +
				"ym5JqrUY0akpIGOxTwIDAQAB";
		String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJ2e7bYhNm+a5zmR\n" +
				"2E7miHrnS3O1oHE29VV9i9UgGQB+O8i1KZDFxgGBLySWfbmlq5Ok4B8rEbmuSit+\n" +
				"R01f08DkK2rQLyK1gTKhvwNXXqSfavkg6Sf94DjPgydsmeGQzICxpflZ679y4bHc\n" +
				"UIVKJRy3ePvKbkmqtRjRqSkgY7FPAgMBAAECgYAvgxeuneZV0ADBJshoSC99tLjW\n" +
				"wToCxok/Yt/Ct7Exp9uHjaxg2mzsSS+XvNFbI6hLkhiI7KekK/hpkeAWX7tpYR5r\n" +
				"6V7ZM5z4llO9k0hWBuLZa8Bzz6kxIEKO1yWlMQClILS4mVmF0v4x0niwVkBV/QD4\n" +
				"0Du9WCATHaaaTk+M0QJBANnIYnAhA7ptVJw4Ckl0FFEqbPohpaG4rrQmtwRsn68X\n" +
				"Z/q6SqcKU7XGfrn8fM7GnD/W5DxJycpot2g1Rd62/ykCQQC5R9hJuvhliA2C81/A\n" +
				"im6E893ZPGB4rTYxcmch3oqi+esy6W/FKew7HekXl3+0AMtGFFazVwf4fKYSJzzA\n" +
				"MVO3AkBYwxJT7zDMz/i3PyP6MiSBvE/0VrhiRJp39HuNgxRGUbzgdQMuN8hMgx1t\n" +
				"gloAEPToFBar98sWAz4Va/kRP/aZAkEApBu+t4+j9EpNrW9joGb8/UYDeibATCMf\n" +
				"nSx3rMgwg6pZaP7awQgg9TvI+dx2gDkz0x6wrKippq7BadLXPGR0gQJAMmKPgTug\n" +
				"h1KhvmAyb5NODYUj6ef4euAoZe7tAoz9e0uBra15hrfIcYK13rS0aM4UGGzXDVra\n" +
				"1SjNGiIXfrZcow==";


		PrivateKey privateKey1 = RsaUtil.getPrivateKey(privateKey);

		logger.info("{}",privateKey1.getAlgorithm());
		logger.info("{}",privateKey1.getFormat());
		logger.info("{}",privateKey1.getEncoded());

		logger.info("公钥加密——私钥解密");
		String source = "caoliangcaoliangcaoliang";
		logger.info("加密前文字：{}" , source);
		String aData = RsaUtil.encrypt(source , publicKey );
		logger.info("加密后文字：{}" ,  aData);
		String dData = RsaUtil.decrypt(aData , privateKey );
		logger.debug("解密后文字: {}" , dData);


	}



}
