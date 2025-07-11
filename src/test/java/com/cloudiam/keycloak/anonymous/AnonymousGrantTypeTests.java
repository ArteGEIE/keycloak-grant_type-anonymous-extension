package com.cloudiam.keycloak.anonymous;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.HashMap;
import java.util.Map;

import static com.cloudiam.keycloak.anonymous.AnonymousGrantType.ANONYMOUS;
import static com.cloudiam.keycloak.anonymous.Utils.*;
import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.slf4j.LoggerFactory.getLogger;

@Testcontainers
public class AnonymousGrantTypeTests {
    private static final Logger LOGGER = getLogger(AnonymousGrantTypeTests.class);
    private static final String GRANT_TYPE = ANONYMOUS;
    private static final Network SHARED_NETWORK = Network.newNetwork();
    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASSWORD = "admin";
    private static final String REALM_NAME = "master";
    private static final String TOKEN_URL = "/realms/" + REALM_NAME + "/protocol/openid-connect/token";
    private static String KEYCLOAK_URL;

    @BeforeAll
    static void setup() {
        var keycloak = createKeycloakContainer();
        keycloak.start();

        KEYCLOAK_URL = keycloak.getAuthServerUrl();

        var keycloakAdminClient = keycloak.getKeycloakAdminClient();

        keycloakAdminClient.realm(REALM_NAME).clientScopes().create(createAnonymousClientScope());

        // Add valid test client to master realm for testing
        keycloakAdminClient.realm(REALM_NAME).clients().create(createClient());

        // Add valid test-with-mapper client to master realm for testing
        try (var response = keycloakAdminClient.realm(REALM_NAME).clients().create(createClientWithMapper())) {
            var createdId = CreatedResponseUtil.getCreatedId(response);
            var clientResource = keycloakAdminClient.realm(REALM_NAME).clients().get(createdId);
            clientResource.getProtocolMappers().createMapper(createProtocolMapper());
        }

        // Add confidential client to master realm for testing
        keycloakAdminClient.realm(REALM_NAME).clients().create(createConfidentialClient());
        // Add disabled client to master realm for testing
        keycloakAdminClient.realm(REALM_NAME).clients().create(createDisabledClient());
    }


    @Test
    @DisplayName("Standard test case should return an access token with scope anonymous")
    void should_create_anonymous_authentication() throws VerificationException {
        String accessToken = makeTokenRequest(GRANT_TYPE, CLIENT_NAME)
                .then()
                .log().body()
                .assertThat()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("access_token", notNullValue())
                .body("token_type", equalToIgnoringCase("bearer"))
                .body("expires_in", equalTo(60))
                .body("scope", equalTo(ANONYMOUS))
                .extract().path("access_token");

        TokenVerifier<AccessToken> verifier = TokenVerifier.create(accessToken, AccessToken.class);
        AccessToken token = verifier.parse().getToken();
        Object anonymousClaim = token.getOtherClaims().get(ANONYMOUS);

        assertThat(anonymousClaim).isNotNull().isEqualTo("true");
    }

    @Test
    @DisplayName("Invalid grant type should be rejected")
    void should_reject_invalid_grant_type() {
        makeTokenRequest("unknown_grant_type", CLIENT_NAME)
                .then()
                .log().body()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("unsupported_grant_type"))
                .body("error_description", equalTo("Unsupported grant_type"));
    }

    @Test
    @DisplayName("A client with mapper should return an access token with scope anonymous")
    void should_create_anonymous_authentication_with_mapper_enabled() {
        makeTokenRequest(GRANT_TYPE, CLIENT_WITH_MAPPER_NAME)
                .then()
                .log().body()
                .assertThat()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("access_token", notNullValue())
                .body("token_type", equalToIgnoringCase("bearer"))
                .body("expires_in", equalTo(60))
                .body("scope", equalTo(ANONYMOUS));
    }

    @Test
    @DisplayName("Confidential client should require a client secret")
    public void should_require_a_client_secret() {
        makeTokenRequest(GRANT_TYPE, CONFIDENTIAL_CLIENT_NAME)
                .then()
                .log().body()
                .assertThat()
                .statusCode(401)
                .body("error", equalTo("unauthorized_client"))
                .body("error_description", equalTo("Invalid client or Invalid client credentials"));
    }

    @Test
    @DisplayName("Confidential client with client_secret should success")
    public void should_create_anonymous_authentication_with_confidential_client() {
        makeTokenRequest(GRANT_TYPE, CONFIDENTIAL_CLIENT_NAME, CONFIDENTIAL_CLIENT_SECRET)
                .then()
                .log().body()
                .assertThat()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("access_token", notNullValue())
                .body("token_type", equalToIgnoringCase("bearer"))
                .body("expires_in", equalTo(60))
                .body("scope", equalTo(ANONYMOUS));
    }

    @Test
    @DisplayName("Disabled clients should not authenticate")
    public void should_reject_disabled_client() {
        makeTokenRequest(GRANT_TYPE, DISABLED_CLIENT_NAME)
                .then()
                .log().body()
                .assertThat()
                .statusCode(401)
                .body("error", equalTo("invalid_client"))
                .body("error_description", equalTo("Invalid client or Invalid client credentials"));
    }

    @Test
    @DisplayName("Unknown client should not authenticate")
    public void should_reject_unknown_client() {
        makeTokenRequest(GRANT_TYPE, "unknown_client")
                .then()
                .log().body()
                .assertThat()
                .statusCode(401)
                .body("error", equalTo("invalid_client"))
                .body("error_description", equalTo("Invalid client or Invalid client credentials"));
    }

    private static KeycloakContainer createKeycloakContainer() {
        var keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:25.0.6")
                .withNetwork(SHARED_NETWORK)
                .withNetworkAliases("keycloak")
                .withLogConsumer(new Slf4jLogConsumer(LOGGER))
                .withEnv("KEYCLOAK_ADMIN", ADMIN_USER)
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", ADMIN_PASSWORD)
                .withDefaultProviderClasses()
                // Container not initializing without waiting for port availability
                .waitingFor(Wait.forHttp("/realms/master"));
        LOGGER.info("Keycloak container created");
        return keycloak;
    }

    private Response makeTokenRequest(String grantType, String clientId) {
        return makeTokenRequest(grantType, clientId, null);
    }

    private Response makeTokenRequest(String grantType, String clientId, String clientSecret) {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", grantType);
        params.put("client_id", clientId);

        if (clientSecret != null) {
            params.put("client_secret", clientSecret);
        }

        return given()
                .formParams(params)
                .post(KEYCLOAK_URL + TOKEN_URL);
    }

}
