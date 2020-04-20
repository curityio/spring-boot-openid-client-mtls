package io.curity.example.oidcspringbootmutualtls;

import io.netty.handler.ssl.SslContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveRefreshTokenTokenResponseClient;
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

import javax.net.ssl.SSLException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;

/**
 * This class configures the security setting for the application.<br/>
 * There are several web clients involved in an OAuth 2.0 flow.<br/>
 * Every web client must trust the OAuth 2.0 server certificate.
 * Every web client making a request to the OAuth 2.0 server that requires authentication must be setup for mutual TLS.<br/>
 * <p/>
 * <b>NOTE:</b> This configuration will only work for OAuth 2.0 clients that use the authorization code flow and refresh tokens.<br/>
 * <p/>
 * Take into account that this example will significantly change when the following issue gets solved:<br/>
 * - https://github.com/spring-projects/spring-security/issues/4498
 */
@Configuration
@Import(TrustStoreConfig.class)
public class SecurityConfig {

    /**
     * Configuration of a custom trust store.
     */
    private final TrustStoreConfig customTrustStoreConfig;

    /**
     * Load the configuration of the custom key and trust store.
     * @param trustStoreConfig
     */
    public SecurityConfig(final TrustStoreConfig trustStoreConfig) {
        this.customTrustStoreConfig = trustStoreConfig;
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(exchanges ->
                        exchanges
                                .anyExchange().authenticated()
                )
                .oauth2Login(Customizer.withDefaults());
        return http.build();
    }


    /**
     * Creates a jwt/id token decoder factory that uses the configured trust for retrieving the JWKS.<br/>
     * If no trust was configured use default implementation instead.
     *
     * @return
     * @throws SSLException
     */
    @Bean
    ReactiveJwtDecoderFactory<ClientRegistration> jwtDecoderFactory() throws SSLException {
        if (customTrustStoreConfig.isTrustStoreConfigured()) {
            SslContext sslContext = customTrustStoreConfig.createTrustedTlsContext();

            return new UpdatedReactiveJwtDecoderFactory(sslContext);
        } else {
            return new ReactiveOidcIdTokenDecoderFactory();
        }
    }

    /**
     * Creates an access token response client that handles the authorization code flow.<br/>
     * This client supports mutual TLS and therefore requires a client certificate and key.
     *
     * @return
     * @throws SSLException
     */
    @Bean
    ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> reactiveOAuth2AccessTokenResponseClientWithMtls() throws SSLException {
        SslContext sslContext = customTrustStoreConfig.createMutualTlsContext();

        WebClientReactiveAuthorizationCodeTokenResponseClient mtlsClient = new
                WebClientReactiveAuthorizationCodeTokenResponseClient();

        WebClient mtlsWebClient = createWebClient(sslContext);
        mtlsClient.setWebClient(mtlsWebClient);

        return mtlsClient;
    }

    /**
     * Create an access token response client that handles the refresh token flow.<br/>
     * This client supports mutual TLS and therefore requires a client certificate and key.
     *
     * @return
     * @throws SSLException
     */
    @Bean
    ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> reactiveOAuth2AccessTokenResponseClientWithMtlsAndRefreshToken() throws SSLException {
        SslContext sslContext = customTrustStoreConfig.createMutualTlsContext();

        WebClientReactiveRefreshTokenTokenResponseClient mtlsClient = new
                WebClientReactiveRefreshTokenTokenResponseClient();

        WebClient mtlsWebClient = createWebClient(sslContext);
        mtlsClient.setWebClient(mtlsWebClient);

        return mtlsClient;
    }

    /**
     * Create a web client with the given ssl context.<br/>
     * That way you can add custom trust or client certificate to the web client.
     *
     * @param sslContext
     * @return
     */
    private WebClient createWebClient(SslContext sslContext) {

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
     * Based on {@link ReactiveOidcIdTokenDecoderFactory}<br/>
     * This is a workaround because of this issue: <br/>
     * - https://github.com/spring-projects/spring-security/issues/8365 <br/>
     * Returns a jwtDecoder with an updated webClient. <br/>
     * Works only when jwkSetUri is available and no MAC based algorithm was used.
     */
    private class UpdatedReactiveJwtDecoderFactory implements ReactiveJwtDecoderFactory<ClientRegistration> {

        SslContext sslContext;

        UpdatedReactiveJwtDecoderFactory(SslContext sslContext) {
            this.sslContext = sslContext;
        }

        @Override
        public ReactiveJwtDecoder createDecoder(ClientRegistration clientRegistration) {
            String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
            NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder
                    .withJwkSetUri(jwkSetUri)
                    .webClient(createWebClient(sslContext))
                    .build();
            jwtDecoder.setClaimSetConverter(
                    new ClaimTypeConverter(
                            ReactiveOidcIdTokenDecoderFactory.createDefaultClaimTypeConverters()
                    ));
            jwtDecoder.setJwtValidator(
                    new DelegatingOAuth2TokenValidator<>(
                            new JwtTimestampValidator(),
                            new OidcIdTokenValidator(clientRegistration)
                    ));

            return jwtDecoder;
        }
    }
}
