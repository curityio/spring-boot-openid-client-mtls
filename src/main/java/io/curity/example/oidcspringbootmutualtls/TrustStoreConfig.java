package io.curity.example.oidcspringbootmutualtls;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Configuration
public class TrustStoreConfig {
    @Value("${custom.client.ssl.trust-store:}")
    private String trustStorePath;

    @Value("${custom.client.ssl.trust-store-password:}")
    private String trustStorePassword;

    @Value("${custom.client.ssl.trust-store-type:jks}")
    private String trustStoreType;

    @Value("${custom.client.ssl.key-store}")
    private String keyStorePath;

    @Value("${custom.client.ssl.key-store-password}")
    private String keyStorePassword;

    @Value("${custom.client.ssl.key-store-type:jks}")
    private String keyStoreType;

    @Bean
    TrustManagerFactory trustManagerFactory() throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore trustStore = KeyStore.getInstance(trustStoreType);
        TrustManagerFactory trustManagerFactory = null;

        if (!trustStorePath.isBlank()) {
            trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            try (InputStream ksFileInputStream = new ClassPathResource(trustStorePath).getInputStream()) {
                trustStore.load(ksFileInputStream, trustStorePassword.toCharArray());
                trustManagerFactory.init(trustStore);
            }
        }

        return trustManagerFactory;
    }

    @Bean
    public KeyManagerFactory keyManagerFactory() throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException {

        KeyStore clientKeyStore = KeyStore.getInstance(keyStoreType);
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        try (InputStream ksFileInputStream = new ClassPathResource(keyStorePath).getInputStream()) {
            clientKeyStore.load(ksFileInputStream, keyStorePassword.toCharArray());
            keyManagerFactory.init(clientKeyStore, keyStorePassword.toCharArray());
        }
        return keyManagerFactory;
    }

}
