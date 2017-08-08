package com.bckefu.uccc.hmac;

import com.bckefu.uccc.CipherType;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SignatureException;

/**
 * Created by caoliang on 2017/8/4.
 */
public class HmacUtil {

    /**
     *
     * @param data
     * @param key
     * @return
     * @throws java.security.SignatureException
     */
    public static String hmacSha256Hex(String data, String key , String algorithm) {
        try {
            // get an hmac_sha1 key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(),algorithm);

            // get an hmac_sha1 Mac instance and initialize with the signing key
            Mac mac = Mac.getInstance(algorithm);
            mac.init(signingKey);

            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(data.getBytes());

            // base64-encode the hmac
            byte[] hexB = (new Hex()).encode(rawHmac);
            return new String(hexB);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param message
     * @param key
     * @return
     * @throws SignatureException
     */
    public static String hmacSha256Hex(String message , String key) throws SignatureException {
        return hmacSha256Hex(message , key , CipherType.HMAC_SHA_256);
    }
}
