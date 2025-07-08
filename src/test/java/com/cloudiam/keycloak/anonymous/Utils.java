package com.cloudiam.keycloak.anonymous;

import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;

import java.util.Collections;
import java.util.HashMap;

import static com.cloudiam.keycloak.anonymous.AnonymousGrantType.ANONYMOUS;

public class Utils {
    static final String CLIENT_NAME = "test-client";
    static final String CLIENT_WITH_MAPPER_NAME = "test-client-with-mapper";
    static final String CONFIDENTIAL_CLIENT_NAME = "confidential-client";
    static final String DISABLED_CLIENT_NAME = "disabled-client";
    static final String CONFIDENTIAL_CLIENT_SECRET = "secret";

    static ClientScopeRepresentation createAnonymousClientScope() {
        var clientScope = new ClientScopeRepresentation();
        clientScope.setName(ANONYMOUS);
        clientScope.setProtocol("openid-connect");
        return clientScope;
    }

    static ClientRepresentation createClient() {
        var client = new ClientRepresentation();
        client.setClientId(CLIENT_NAME);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(true);
        client.setPublicClient(true);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setProtocol("openid-connect");
        client.setDefaultClientScopes(Collections.singletonList("basic"));
        client.setOptionalClientScopes(Collections.singletonList(ANONYMOUS));
        client.setEnabled(true);

        return client;
    }

    static ClientRepresentation createClientWithMapper() {
        var client = new ClientRepresentation();
        client.setClientId(CLIENT_WITH_MAPPER_NAME);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(true);
        client.setPublicClient(true);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setProtocol("openid-connect");
        client.setDefaultClientScopes(Collections.singletonList("basic"));
        client.setOptionalClientScopes(Collections.singletonList(ANONYMOUS));
        client.setEnabled(true);

        return client;
    }

    static ProtocolMapperRepresentation createProtocolMapper() {
        // Créer le protocol mapper
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("user-attr-my-custom-email");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-usermodel-attribute-mapper");

        mapper.setConfig(new HashMap<>() {{
            put("user.attribute", "my_custom_email");
            put("claim.name", "email");
            put("jsonType.label", "String");
            put("id.token.claim", "true");
            put("access.token.claim", "true");
            put("userinfo.token.claim", "true");
        }});

        return mapper;
    }


    static ClientRepresentation createConfidentialClient() {
        var client = new ClientRepresentation();
        client.setClientId(CONFIDENTIAL_CLIENT_NAME);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(true);
        // Set to false to simulate an invalid client
        client.setPublicClient(false);
        client.setSecret(CONFIDENTIAL_CLIENT_SECRET);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setProtocol("openid-connect");
        client.setDefaultClientScopes(Collections.singletonList("basic"));
        client.setOptionalClientScopes(Collections.singletonList(ANONYMOUS));
        client.setEnabled(true);

        return client;
    }


    static ClientRepresentation createDisabledClient() {
        var client = new ClientRepresentation();
        client.setClientId(DISABLED_CLIENT_NAME);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(true);
        client.setPublicClient(true);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setProtocol("openid-connect");
        client.setDefaultClientScopes(Collections.singletonList("basic"));
        client.setOptionalClientScopes(Collections.singletonList(ANONYMOUS));
        client.setEnabled(false);

        return client;
    }

}
