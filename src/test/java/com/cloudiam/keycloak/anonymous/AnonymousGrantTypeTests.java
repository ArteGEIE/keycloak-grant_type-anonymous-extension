package com.cloudiam.keycloak.anonymous;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.response.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Testcontainers
public class AnonymousGrantTypeTests {
    private static final String GRANT_TYPE = "anonymous";
    private static final Network SHARED_NETWORK = Network.newNetwork();
    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASSWORD = "admin";
    private static final int KEYCLOAK_PORT = 8080;
    private static final String CLIENT_NAME = "test-client";
    private static final String PRIVATE_CLIENT_NAME = "private-client";
    private static final String DISABLED_CLIENT_NAME = "disabled-client";
    private static final String REALM_NAME = "master";

    private static String keycloakUrl;
    private Keycloak adminClient;

    @Container
    private static final KeycloakContainer keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:25.0.6")
            .withNetwork(SHARED_NETWORK)
            .withNetworkAliases("keycloak")
            .withExposedPorts(KEYCLOAK_PORT)
            .withLogConsumer(outputFrame -> System.out.println(outputFrame.getUtf8String().trim()))
            .withEnv("KEYCLOAK_ADMIN", ADMIN_USER)
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .withEnv("KC_HTTP_ENABLED", "true")
            .withEnv("KC_HOSTNAME_STRICT", "false")
            .withEnv("KC_HOSTNAME_STRICT_HTTPS", "false")
            .withEnv("KC_HTTP_PORT", String.valueOf(KEYCLOAK_PORT))
            .withCopyFileToContainer(
                    MountableFile.forHostPath("target/grant_type-anonymous-1.0.0-SNAPSHOT.jar"),
                    "/opt/keycloak/providers/grant_type-anonymous-1.0.0-SNAPSHOT.jar"
            )
            .waitingFor(
                Wait.forHttp("/realms/" + REALM_NAME)
                    .forPort(KEYCLOAK_PORT)
                    .forStatusCode(200)
            );

    

    @Test
    public void testProcess_WithValidClient_ShouldSuccess() {
            String tokenUrl = keycloakUrl + "/realms/" + REALM_NAME + "/protocol/openid-connect/token";

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", GRANT_TYPE);
            params.put("client_id", CLIENT_NAME);

            Response response = given()
                .formParams(params)
                .post(tokenUrl);

            assertEquals(200, response.getStatusCode(), "Should return 200 OK");
    }

    @Test
    public void testProcess_WithValidClient_ShouldReturnValidPayload() {
            String tokenUrl = keycloakUrl + "/realms/" + REALM_NAME + "/protocol/openid-connect/token";

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", GRANT_TYPE);
            params.put("client_id", CLIENT_NAME);

            Response response = given()
                .formParams(params)
                .post(tokenUrl);

            // Verify the response payload
            assertEquals("bearer", response.jsonPath().getString("token_type").toLowerCase(),
                "Token type should be bearer");
            assertNotNull(response.jsonPath().getString("access_token"), "Access token should not be null");
            assertEquals("300", response.jsonPath().getString("expires_in"), "Expires in should be 300");
            assertEquals("openid", response.jsonPath().getString("scope"), "Scope should be openid");
    }

    @Test
    public void testProcess_WithInvalidGrantType_ShouldFail() {
        String tokenUrl = keycloakUrl + "/realms/" + REALM_NAME + "/protocol/openid-connect/token";

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "anonymousss");
        params.put("client_id", CLIENT_NAME);

        Response response = given()
                .formParams(params)
                .post(tokenUrl);


        assertEquals(400, response.getStatusCode(), "Should return 400");
    }


    @Test
    public void testProcess_WithPrivateClient_ShouldFail() {
        String tokenUrl = keycloakUrl + "/realms/" + REALM_NAME + "/protocol/openid-connect/token";

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "anonymousss");
        params.put("client_id", PRIVATE_CLIENT_NAME);

        Response response = given()
                .formParams(params)
                .post(tokenUrl);


        assertEquals(400, response.getStatusCode(), "Should return 400");
    }

    @Test
    public void testProcess_WithDisabledClient_ShouldFail() {
        String tokenUrl = keycloakUrl + "/realms/" + REALM_NAME + "/protocol/openid-connect/token";

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "anonymousss");
        params.put("client_id", PRIVATE_CLIENT_NAME);

        Response response = given()
                .formParams(params)
                .post(tokenUrl);


        assertEquals(400, response.getStatusCode(), "Should return 400");
    }
            
    @Test
    public void testProcess_WithInvalidClient_ShouldReturnError() {
            String tokenUrl = keycloakUrl + "/realms/" + REALM_NAME + "/protocol/openid-connect/token";

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", GRANT_TYPE);
            params.put("client_id", "invalidClientId");

            Response response = given()
                .formParams(params)
                .post(tokenUrl);

            assertEquals(401, response.getStatusCode(), "Should return 401 Unauthorized");
            String error = response.jsonPath().getString("error");
            assertEquals("invalid_client", error, "Should return invalid_client error");
    }

    @BeforeEach
    void setup() {
        keycloak.start();

        String host = keycloak.getHost();
        Integer port = keycloak.getMappedPort(KEYCLOAK_PORT);
        keycloakUrl = String.format("http://%s:%d", host, port);
        
        if (adminClient != null) {
            adminClient.close();
        }

        adminClient = KeycloakBuilder.builder()
            .serverUrl(keycloakUrl)
            .realm(REALM_NAME)
            .clientId("admin-cli")
            .username(ADMIN_USER)
            .password(ADMIN_PASSWORD)
            .build();
            
        // Add valid test client to master realm for testing
        ClientRepresentation testClient = createClient();
        adminClient.realm(REALM_NAME).clients().create(testClient);

        // Add private and disabled client to master realm for testing
        ClientRepresentation privateClient = createPrivateClient();
        adminClient.realm(REALM_NAME).clients().create(privateClient);

        ClientRepresentation disabledClient = createDisabledClient();
        adminClient.realm(REALM_NAME).clients().create(disabledClient);
    }

    private ClientRepresentation createClient() {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(CLIENT_NAME);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(true);
        client.setPublicClient(true);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setProtocol("openid-connect");
        client.setDefaultClientScopes(Collections.singletonList("openid"));
        client.setEnabled(true);

        return client;
    }


    private ClientRepresentation createPrivateClient() {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(CLIENT_NAME);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(true);
        // Set to false to simulate an invalid client
        client.setPublicClient(false);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setProtocol("openid-connect");
        client.setDefaultClientScopes(Collections.singletonList("openid"));
        client.setEnabled(true);

        return client;
    }


    private ClientRepresentation createDisabledClient() {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(DISABLED_CLIENT_NAME);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(true);
        client.setPublicClient(true);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setProtocol("openid-connect");
        client.setDefaultClientScopes(Collections.singletonList("openid"));
        client.setEnabled(false);

        return client;
    }

    
}
