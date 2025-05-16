package com.cloudiam.keycloak.anonymous;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.response.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.Collections;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

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
    private static final String TOKEN_URL = "/realms/" + REALM_NAME + "/protocol/openid-connect/token";

    private static String keycloakUrl;
    private static Keycloak adminClient;

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
            .withDefaultProviderClasses()
            // Container not initializing without waiting for port availability
            .waitingFor(
                Wait.forHttp("/realms/" + REALM_NAME)
                    .forPort(KEYCLOAK_PORT)
                    .forStatusCode(200)
            );

    

    private Response makeTokenRequest(String grantType, String clientId) {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", grantType);
        params.put("client_id", clientId);

        return given()
                .formParams(params)
                .post(keycloakUrl + TOKEN_URL);
    }

    @ParameterizedTest
    @MethodSource("validClientTestCases")
    public void testProcess_WithValidClient_ShouldSuccess(String clientId) {
        Response response = makeTokenRequest(GRANT_TYPE, clientId);
        assertEquals(200, response.getStatusCode(), "Should return 200 OK");
    }

    @ParameterizedTest
    @MethodSource("validClientTestCases")
    public void testProcess_WithValidClient_ShouldReturnValidPayload(String clientId) {
        Response response = makeTokenRequest(GRANT_TYPE, clientId);
        
        // Verify the response payload
        assertEquals("bearer", response.jsonPath().getString("token_type").toLowerCase(),
            "Token type should be bearer");
        assertNotNull(response.jsonPath().getString("access_token"), "Access token should not be null");
        assertEquals("300", response.jsonPath().getString("expires_in"), "Expires in should be 300");
        assertEquals("openid", response.jsonPath().getString("scope"), "Scope should be openid");
    }

    @ParameterizedTest
    @MethodSource("invalidGrantTypeTestCases")
    public void testProcess_WithInvalidGrantType_ShouldFail(String clientId, String grantType) {
        Response response = makeTokenRequest(grantType, clientId);
        assertEquals(400, response.getStatusCode(), "Should return 400");
    }

    @ParameterizedTest
    @MethodSource("privateClientTestCases")
    public void testProcess_WithPrivateClient_ShouldFail(String clientId) {
        Response response = makeTokenRequest(GRANT_TYPE, clientId);
        assertEquals(401, response.getStatusCode(), "Should return 401");
    }

    @ParameterizedTest
    @MethodSource("disabledClientTestCases")
    public void testProcess_WithDisabledClient_ShouldFail(String clientId, String grantType) {
        Response response = makeTokenRequest(grantType, clientId);
        assertEquals(401, response.getStatusCode(), "Should return 401");
    }

    @ParameterizedTest
    @MethodSource("invalidClientTestCases")
    public void testProcess_WithInvalidClient_ShouldReturnError(String clientId) {
        Response response = makeTokenRequest(GRANT_TYPE, clientId);

        assertEquals(401, response.getStatusCode(), "Should return 401 Unauthorized");
        String error = response.jsonPath().getString("error");
        assertEquals("invalid_client", error, "Should return invalid_client error");
    }

    private static Stream<String> validClientTestCases() {
        return Stream.of(CLIENT_NAME);
    }

    private static Stream<Arguments> invalidGrantTypeTestCases() {
        return Stream.of(
            Arguments.of(CLIENT_NAME, "anonymousss"),
            Arguments.of(CLIENT_NAME, "invalid_grant_type")
        );
    }

    private static Stream<String> privateClientTestCases() {
        return Stream.of(PRIVATE_CLIENT_NAME);
    }

    private static Stream<Arguments> disabledClientTestCases() {
        return Stream.of(
            Arguments.of(DISABLED_CLIENT_NAME, "anonymous"));
    }

    private static Stream<String> invalidClientTestCases() {
        return Stream.of("invalidClientId", "nonexistent-client", "invalid_client");
    }

    @BeforeAll
    static void setup() {
        keycloak.start();

        String host = keycloak.getHost();
        Integer port = keycloak.getMappedPort(KEYCLOAK_PORT);
        keycloakUrl = String.format("http://%s:%d", host, port);
        
        if (adminClient != null) {
            adminClient.close();
        }

        adminClient = keycloak.getKeycloakAdminClient();
            
        // Add valid test client to master realm for testing
        ClientRepresentation testClient = createClient();
        adminClient.realm(REALM_NAME).clients().create(testClient);

        // Add private and disabled client to master realm for testing
        ClientRepresentation privateClient = createPrivateClient();
        adminClient.realm(REALM_NAME).clients().create(privateClient);

        ClientRepresentation disabledClient = createDisabledClient();
        adminClient.realm(REALM_NAME).clients().create(disabledClient);
    }

    private static ClientRepresentation createClient() {
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


    private static ClientRepresentation createPrivateClient() {
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


    private static ClientRepresentation createDisabledClient() {
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
