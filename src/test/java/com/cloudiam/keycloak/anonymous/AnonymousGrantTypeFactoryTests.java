package com.cloudiam.keycloak.anonymous;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.provider.ProviderFactory;
import org.mockito.junit.jupiter.MockitoExtension;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wiremock.integrations.testcontainers.WireMockContainer;

@Testcontainers
@ExtendWith(MockitoExtension.class)
public class AnonymousGrantTypeFactoryTests {
    
    private static WireMockContainer wiremockServer;
    private KeycloakSession keycloakSession;

    @BeforeAll
    public static void startWireMockServer() {
        wiremockServer = new WireMockContainer("wiremock/wiremock").withExposedPorts(8080);
        wiremockServer.start();
    }

    @AfterAll
    public static void stopWireMockServer() {
        wiremockServer.stop();
    }

    @BeforeEach
    public void setup() {
        keycloakSession = mock(KeycloakSession.class);

    }

    @AfterEach
    public void tearDown() {
        // Clean up session
        if (keycloakSession != null) {
            keycloakSession.close();
        }
    }


    @Test
    public void testDefaultProviderIsOverridden() {
        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        AnonymousGrantTypeFactory factory = new AnonymousGrantTypeFactory();
        
        when(sessionFactory.getProviderFactory(OAuth2GrantType.class, "anonymous"))
            .thenReturn(factory);
        
        ProviderFactory<OAuth2GrantType> providerFactory = 
            sessionFactory.getProviderFactory(OAuth2GrantType.class, "anonymous");
        
        assertNotNull(providerFactory, "Provider factory should not be null");
        assertEquals("anonymous", providerFactory.getId());
        assertInstanceOf(AnonymousGrantTypeFactory.class, providerFactory);
    }
}
