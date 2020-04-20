package io.curity.example.oidcspringbootmutualtls;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
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

    private SslContextBuilder mutualTLSContextBuilder;
    private SslContextBuilder trustedTLSContextBuilder;

    private boolean isTrustStoreConfigured;

    public TrustStoreConfig(
            @Value("${custom.client.ssl.trust-store-type:jks}") String trustStoreType,
            @Value("${custom.client.ssl.trust-store:}") String trustStorePath,
            @Value("${custom.client.ssl.trust-store-password:}") String trustStorePassword,
            @Value("${custom.client.ssl.key-store}") String keyStorePath,
            @Value("${custom.client.ssl.key-store-password}") String keyStorePassword,
            @Value("${custom.client.ssl.key-store-type:jks}") String keyStoreType)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException {

        isTrustStoreConfigured = (trustStorePath != null && !trustStorePath.isEmpty());

        TrustManagerFactory trustManagerFactory = trustManagerFactory(trustStoreType, trustStorePath, trustStorePassword);

        trustedTLSContextBuilder = SslContextBuilder
                .forClient();

        if (trustManagerFactory != null) {
            trustedTLSContextBuilder.trustManager(trustManagerFactory);
        }

        mutualTLSContextBuilder = SslContextBuilder
                .forClient()
                .keyManager(keyManagerFactory(keyStoreType, keyStorePath, keyStorePassword));

        if (trustManagerFactory != null) {
            mutualTLSContextBuilder.trustManager(trustManagerFactory);
        }
    }

    private TrustManagerFactory trustManagerFactory(String trustStoreType, String trustStorePath, String trustStorePassword) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore trustStore = KeyStore.getInstance(trustStoreType);
        TrustManagerFactory trustManagerFactory = null;

        if (isTrustStoreConfigured()) {
            trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            try (InputStream ksFileInputStream = new ClassPathResource(trustStorePath).getInputStream()) {
                trustStore.load(ksFileInputStream, trustStorePassword.toCharArray());
                trustManagerFactory.init(trustStore);
            }
        }

        return trustManagerFactory;
    }

    private KeyManagerFactory keyManagerFactory(String keyStoreType, String keyStorePath, String keyStorePassword) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException {

        KeyStore clientKeyStore = KeyStore.getInstance(keyStoreType);
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        try (InputStream ksFileInputStream = new ClassPathResource(keyStorePath).getInputStream()) {
            clientKeyStore.load(ksFileInputStream, keyStorePassword.toCharArray());
            keyManagerFactory.init(clientKeyStore, keyStorePassword.toCharArray());
        }
        return keyManagerFactory;
    }

    /**
     * Creates the prerequisites for mutual TLS. <br/>
     * This method adds the client certificate and key as well as a custom trust store to the context.<br/>
     * If no custom trust store was configured JVM default settings are used.
     *
     * @return Sslcontext with the configured client certificate and trust store
     * @throws SSLException
     */
    public SslContext createMutualTlsContext() throws SSLException {
        return mutualTLSContextBuilder.build();
    }

    /**
     * Creates the prerequisites for TLS with a custom trust store. <br/>
     * This method adds a custom trust store to the context.<br/>
     * If no custom trust store was configured JVM default settings are used.
     *
     * @return Sslcontext with the configured trust store
     * @throws SSLException
     */
    public SslContext createTrustedTlsContext() throws SSLException {
        return trustedTLSContextBuilder.build();
    }

    public boolean isTrustStoreConfigured() {
        return isTrustStoreConfigured;
    }

}
