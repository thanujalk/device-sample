package com.wso2.device.sample;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Map;

public class DeviceSigner {

    public static final String SIGNING_ALGORITHM = "SHA256withRSA";

    public static String getSignature(Map<String, String> formData, PrivateKey privateKey)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        byte[] message = ("sub=" + formData.get("sub") + "&iat=" + formData.get("iat") + "&exp=" + formData.get("exp"))
                .getBytes(StandardCharsets.UTF_8);
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message);
        byte[] digitalSignature = signature.sign();
        return Base64.getEncoder().encodeToString(digitalSignature);
    }
}
