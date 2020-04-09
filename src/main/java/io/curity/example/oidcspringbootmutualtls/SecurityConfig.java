package io.curity.example.oidcspringbootmutualtls;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.concurrent.TimeUnit;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(exchanges ->
                        exchanges
                                .anyExchange().authenticated()
                )
                .oauth2Login(withDefaults());
        return http.build();
    }

    @Bean
    public SslContextBuilder sslContextBuilder(@Value("${http.client.ssl.key-store}") String keyStorePath,
                                               @Value("${http.client.ssl.key-store-password}") String keyStorePassword)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        try (InputStream ksFileInputStream = new ClassPathResource(keyStorePath).getInputStream()) {
            keyStore.load(ksFileInputStream, keyStorePassword.toCharArray());
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
            trustManagerFactory.init(keyStore);
        }

        return SslContextBuilder
                .forClient()
                .keyManager(keyManagerFactory)
                .trustManager(trustManagerFactory);
    }

    WebClient createWebClient(SslContext sslContext) {
        HttpClient nettyClient = HttpClient
                .create(ConnectionProvider.create("small-test-pool", 3))
                .wiretap(true)
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext)
                        .handshakeTimeout(Duration.of(2, ChronoUnit.SECONDS)));

        ClientHttpConnector clientConnector = new ReactorClientHttpConnector(nettyClient);

        return WebClient
                .builder()
                .clientConnector(clientConnector)
                .build();
    }

    @Bean
    ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> reactiveOAuth2AccessTokenResponseClientWithMtls(
            SslContextBuilder sslContextBuilder) throws SSLException {

        WebClientReactiveAuthorizationCodeTokenResponseClient mtlsClient = new
                WebClientReactiveAuthorizationCodeTokenResponseClient();

        WebClient mtlsWebClient = createWebClient(sslContextBuilder.build());
        mtlsClient.setWebClient(mtlsWebClient);

        return mtlsClient;
    }

}
