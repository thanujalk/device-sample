package com.wso2.device.sample;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Device {

    private final String deviceId;

    private final String deviceKeyStore;

    private final char[] deviceKeyStorePassword;

    private final String privateKeyAlias;

    private final char[] privateKeyPassword;

    private PrivateKey privateKey;

    private PublicKey publicKey;

    private Certificate certificate;

    private Device(DeviceBuilder deviceBuilder) throws KeyStoreException, CertificateException,
            IOException, NoSuchAlgorithmException, UnrecoverableKeyException {

        this.deviceId = deviceBuilder.deviceId;
        this.deviceKeyStore = deviceBuilder.deviceKeyStore;
        this.deviceKeyStorePassword = deviceBuilder.deviceKeyStorePassword;
        this.privateKeyAlias = deviceBuilder.privateKeyAlias;
        this.privateKeyPassword = deviceBuilder.privateKeyPassword;
        init();
    }

    private void init() throws KeyStoreException, CertificateException, IOException,
            NoSuchAlgorithmException, UnrecoverableKeyException {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        InputStream is = classloader.getResourceAsStream(deviceKeyStore);
        keyStore.load(is, deviceKeyStorePassword);
        this.privateKey = (PrivateKey) keyStore.getKey(this.privateKeyAlias, privateKeyPassword);

        Certificate certificate = keyStore.getCertificate(this.privateKeyAlias);
        this.certificate = certificate;
        this.publicKey = certificate.getPublicKey();
    }

    public String getDeviceId() {

        return deviceId;
    }

    public String getDeviceKeyStore() {

        return deviceKeyStore;
    }

    public char[] getDeviceKeyStorePassword() {

        return deviceKeyStorePassword;
    }

    public String getPrivateKeyAlias() {

        return privateKeyAlias;
    }

    public char[] getPrivateKeyPassword() {

        return privateKeyPassword;
    }

    public PrivateKey getPrivateKey() {

        return privateKey;
    }

    public PublicKey getPublicKey() {

        return publicKey;
    }

    public Certificate getCertificate() {

        return certificate;
    }

    public static class DeviceBuilder {

        private String deviceId;

        private String deviceKeyStore;

        private char[] deviceKeyStorePassword;

        private String privateKeyAlias;

        private char[] privateKeyPassword;

        public DeviceBuilder deviceId(String deviceId) {
            this.deviceId = deviceId;
            return this;
        }

        public DeviceBuilder deviceKeyStore(String deviceKeyStore) {
            this.deviceKeyStore = deviceKeyStore;
            return this;
        }

        public DeviceBuilder deviceKeyStorePassword(char[] deviceKeyStorePassword) {
            this.deviceKeyStorePassword = deviceKeyStorePassword;
            return this;
        }

        public DeviceBuilder privateKeyAlias(String privateKeyAlias) {
            this.privateKeyAlias = privateKeyAlias;
            return this;
        }

        public DeviceBuilder privateKeyPassword(char[] privateKeyPassword) {
            this.privateKeyPassword = privateKeyPassword;
            return this;
        }

        public Device build() throws KeyStoreException, CertificateException, IOException,
                NoSuchAlgorithmException, UnrecoverableKeyException {

            return new Device(this);
        }
    }
}
