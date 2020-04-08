# OAuth 2.0 Client with Spring Boot and mutual TLS Client Authentication
This repository contains an example implementation that demonstrate how to use Spring Boot and Spring Security to create an OAuth 2.0 Client that authenticates to the Curity Identity Server using mutual TLS.

There are only two things to consider when configuring the client in the Curity Identity Server:

* choose the authentication method `mutual tls` and make sure it uses the self-signed certificate created below. 
* register the following redirect uri for your client: `http://localhost:8080/login/oauth2/code/idsvr`. 

The redirect uri is the path of the application where the Curity Identity Server will redirect to after the user was authenticated. In this case we assume that this example will be hosted on `localhost`. 

## Create a Self-Signed Certificate
For mutual TLS client authentication to work you need a client certificate. Create a Java keystore with the self-signed certificate.

```bash
keytool -genkey -alias demo-client -keyalg RSA -keysize 4096 -keystore demo-client.keystore -storepass Secr3t -validity 10 -dname "CN=demo-client, OU=Example, O=Curity AB, C=SE"
```

Export the certificate and use it to configure the client at the Curity Identity Server.

```bash
keytool -export -alias demo-client -keystore demo-client.keystore -storepass Secr3t -file demo-client.cer 
```

## Configure application.yml
Update the client registration and provider to fit your setup.

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          idsvr:
            client-name: Demo
            client-id: demo-client
            client-authentication-method: none
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope: openid
        provider:
          idsvr:
            authorizationUri: https://idsvr.example.com/oauth/authorize
            tokenUri: https://idsvr.example.com/oauth/token
            jwkSetUri: https://idsvr.example.com/oauth/anonymous/jwks
```

Place the keystore created above in the `resources` folder and configure the SSL/TLS settings for the client.

```yaml
client:
  ssl:
    key-store: demo-client.keystore
    key-store-password: Secr3t
```

## Run the Application
To start the application run 

```bash
./gradlew bootRun
```

Open `http://localhost:8080` in your browser. It will automatically start a login flow.

## More Information
More information about OAuth 2.0, OpenID Connect and the Curity Identity Server can be found here:

* [The Curity Identity Server](https://curity.io)
* [OAuth 2.0](https://curity.io/resources/oauth/)
* [OpenID Connect](https://curity.io/resources/openid-connect/)

Check out the related tutorial of this repository:
* [OIDC Client with Mutual TLS Client Authentication](https://curity.io/resources/tutorials/howtos/writing-clients/oidc-spring-boot-mtls-auth/)

Read up on [OAuth 2.0 Mutual TLS Client Authentication](https://curity.io/resources/architect/oauth/oauth-client-authentication-mutual-tls/)

## Licensing

This software is copyright (C) 2020 Curity AB. It is open source software that is licensed under the [Apache 2 license](LICENSE).