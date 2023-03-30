package com.wso2.device.sample;

public class TokenServer {

    private final String serverUrl;

    private final String clientId;

    private final String clientSecret;

    public TokenServer(String serverUrl, String clientId, String clientSecret) {

        this.serverUrl = serverUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getServerUrl() {

        return serverUrl;
    }

    public String getClientId() {

        return clientId;
    }

    public String getClientSecret() {

        return clientSecret;
    }
}
