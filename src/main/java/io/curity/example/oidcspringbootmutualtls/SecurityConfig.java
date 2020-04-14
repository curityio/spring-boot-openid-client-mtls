package io.curity.example.oidcspringbootmutualtls;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withJwkSetUri;

@Configuration
@Import(TrustStoreConfig.class)
public class SecurityConfig {

    private final TrustStoreConfig trustStoreConfig;

    public SecurityConfig(TrustStoreConfig trustStoreConfig) {
        this.trustStoreConfig = trustStoreConfig;
    }

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

    /**
     * Creates a jwt/id token decoder factory that uses the given trust for retrieving the JWKS.
     * If no trust was configured use default implementation instead.
     * @return
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    @Bean
    ReactiveJwtDecoderFactory<ClientRegistration> jwtDecoderFactory() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = trustStoreConfig.trustManagerFactory();
        if (trustManagerFactory != null) {
            SslContext sslContext = SslContextBuilder
                    .forClient()
                    .trustManager(trustManagerFactory)
                    .build();

            return new UpdatedReactiveJwtDecoderFactory(sslContext);
        } else {
            return new ReactiveOidcIdTokenDecoderFactory();
        }
    }

    /**
     * Creates an access token response client that handles the authorization code flow.
     * This client supports mutual TLS and therefore requires a client certificate and key provided by the key manager factory.
     * It also must trust the server certificate which is provided through the trust manager factory. If not trust was configured default is used.
     *
     * @return
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    @Bean
    ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> reactiveOAuth2AccessTokenResponseClientWithMtls() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        TrustManagerFactory trustManagerFactory = trustStoreConfig.trustManagerFactory();

        SslContextBuilder sslContextBuilder = SslContextBuilder
                .forClient()
                .keyManager(trustStoreConfig.keyManagerFactory());

        if (trustManagerFactory != null) {
            sslContextBuilder.trustManager(trustManagerFactory);
        }

        SslContext sslContext = sslContextBuilder.build();

        WebClientReactiveAuthorizationCodeTokenResponseClient mtlsClient = new
                WebClientReactiveAuthorizationCodeTokenResponseClient();

        WebClient mtlsWebClient = createWebClient(sslContext);
        mtlsClient.setWebClient(mtlsWebClient);

        return mtlsClient;
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

    /**
     * Based on {@link ReactiveOidcIdTokenDecoderFactory}
     * Returns a jwtDecoder with an updated webClient
     */
    private class UpdatedReactiveJwtDecoderFactory implements ReactiveJwtDecoderFactory<ClientRegistration> {

        SslContext sslContext;

        UpdatedReactiveJwtDecoderFactory(SslContext sslContext) {
            this.sslContext = sslContext;
        }

        @Override
        public ReactiveJwtDecoder createDecoder(ClientRegistration clientRegistration) {
            String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
            NimbusReactiveJwtDecoder jwtDecoder = withJwkSetUri(jwkSetUri).webClient(createWebClient(sslContext)).build();
            jwtDecoder.setClaimSetConverter(new ClaimTypeConverter(ReactiveOidcIdTokenDecoderFactory.createDefaultClaimTypeConverters()));
            jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(), new OidcIdTokenValidator(clientRegistration)));

            return jwtDecoder;
        }
    }
}
