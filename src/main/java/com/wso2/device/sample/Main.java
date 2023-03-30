package com.wso2.device.sample;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.wso2.device.sample.DeviceSigner.SIGNING_ALGORITHM;

public class Main {

    public static void main(String[] args) throws UnrecoverableKeyException, CertificateException, KeyStoreException,
            IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, InterruptedException {

        TokenServer tokenServer = new TokenServer("https://localhost:9443/oauth2/token",
                "PLKxdsOBoWaolLiXAj2gjsngyqEa", "OfDaBHfg1zLtiNcPYCh5flllmhga");

        Device device101 = new Device.DeviceBuilder()
                .deviceId("device101")
                .deviceKeyStore("device101.jks")
                .deviceKeyStorePassword("changeit".toCharArray())
                .privateKeyAlias("device101")
                .privateKeyPassword("changeit".toCharArray())
                .build();

        HttpResponse<String> response = getAccessToken(device101, tokenServer);
        // Print token response
        System.out.println("\n\nRequest Data:");
        System.out.println(response.body());
    }

    public static HttpResponse<String> getAccessToken(Device device, TokenServer tokenServer)
            throws IOException, InterruptedException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, CertificateEncodingException {

        // Build request parameters
        Map<String, String> formData = buildRequestParams(device);
        // Print request parameters
        printFormData(formData);

        // Build custom token grant request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenServer.getServerUrl()))
                .POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(formData)))
                .setHeader("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + Base64.getEncoder()
                        .encodeToString((tokenServer.getClientId() + ":" + tokenServer.getClientSecret())
                                .getBytes())).build();

        HttpClient httpClient = HttpClient.newHttpClient();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, String> buildRequestParams(Device device) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException {

        Map<String, String> formData = new HashMap<>();
        formData.put("grant_type", "custom-device-grant");
        formData.put("sub", device.getDeviceId());
        Instant now = Instant.now();
        formData.put("iat", String.valueOf(Date.from(now).getTime()));
        formData.put("exp", String.valueOf(Date.from(now.plus(5, ChronoUnit.MINUTES)).getTime()));
        formData.put("sig", DeviceSigner.getSignature(formData, device.getPrivateKey()));
        formData.put("pub", Base64.getEncoder().encodeToString(device.getCertificate().getEncoded()));
        formData.put("scope", "openid");
        formData.put("alg", SIGNING_ALGORITHM);
        return formData;
    }

    private static String getFormDataAsString(Map<String, String> formData) {

        StringBuilder formBodyBuilder = new StringBuilder();
        for (Map.Entry<String, String> singleEntry : formData.entrySet()) {
            if (formBodyBuilder.length() > 0) {
                formBodyBuilder.append("&");
            }
            formBodyBuilder.append(URLEncoder.encode(singleEntry.getKey(), StandardCharsets.UTF_8));
            formBodyBuilder.append("=");
            formBodyBuilder.append(URLEncoder.encode(singleEntry.getValue(), StandardCharsets.UTF_8));
        }
        return formBodyBuilder.toString();
    }

    private static void printFormData(Map<String, String> formData) {

        System.out.println("Request Data:");
        for (Map.Entry<String, String> singleEntry : formData.entrySet()) {
            System.out.println(singleEntry.getKey() + " : " + singleEntry.getValue());
        }
    }
}