package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager.AccessTokenResponseBuilder;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.util.UUID;

public class AnonymousGrantType implements OAuth2GrantType {

    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantType.class);
    private final KeycloakSession session;
    private static final Integer ACCESS_TOKEN_LIFESPAN = Integer.parseInt(System.getenv("ACCESS_TOKEN_LIFESPAN") != null ? System.getenv("ACCESS_TOKEN_LIFESPAN") : "300");

    public AnonymousGrantType(KeycloakSession session) {
        this.session = session;
        LOGGER.info("******** ANONYMOUS GRANT TYPE PROVIDER INITIALIZED ********");
    }


    @Override
    public void close() {
        LOGGER.info("******** CLOSING ANONYMOUS GRANT TYPE PROVIDER ********");
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    @Override
    public Response process(Context context) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = session.getContext().getClient();

        // Verify client exists
        validateClient(client, realm);

        UserModel transientUser = createTransientUser(realm);
        EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
        event.event(EventType.LOGIN);

        UserSessionProvider userSessionProvider = session.getProvider(UserSessionProvider.class);
        UserSessionModel userSession = userSessionProvider.createUserSession(
            UUID.randomUUID().toString(),
            realm,
            transientUser,
            transientUser.getUsername(),
            session.getContext().getConnection().getRemoteAddr(),
            "anonymous",
            false,
            null,
            null,
            UserSessionModel.SessionPersistenceState.TRANSIENT
        );

        AuthenticatedClientSessionModel clientSession = session.sessions()
        .createClientSession(realm, client, userSession);

        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(
            clientSession, null, session
        );

        LOGGER.info("******* ANONYMOUS GRANT TYPE START TOKEN GENERATION *******");

        TokenManager tokenManager = new TokenManager();
        // Create token response builder
        AccessTokenResponseBuilder tokenResponseBuilder = tokenManager
                .responseBuilder(realm, client, event, session, userSession, clientSessionCtx).generateAccessToken();

        AccessTokenResponse tokenResponse = tokenResponseBuilder.build();

        tokenResponse.setExpiresIn(ACCESS_TOKEN_LIFESPAN);
        tokenResponse.setScope("openid");
        tokenResponse.setTokenType("Bearer");
        tokenResponse.setSessionState(null);

        LOGGER.info("******* ANONYMOUS GRANT TYPE TOKEN GENERATED SUCCESSFULLY *******");
        Response response = Response.ok(tokenResponse).build();

        // Delete the user after token creation
        deleteTransientUser(realm, userSession.getUser());

        return response;
    }

    private UserModel createTransientUser(RealmModel realm) {
        String anonUsername = "anon-" + UUID.randomUUID();
        UserModel user = session.users().addUser(realm, anonUsername);
        user.setEnabled(true);
        user.setSingleAttribute("anonymous", "true");

        return user;
    }

    private void deleteTransientUser(RealmModel realm, UserModel user) {
        try {
            session.users().removeUser(realm, user);
        } catch (Exception e) {
            LOGGER.error("Failed to delete user", e);
        }
    }

    private void validateClient(ClientModel client, RealmModel realm) {
        if (client == null || realm == null) {
            LOGGER.warn("Client or realm is null");
            throw new RuntimeException("Client or realm not found");
        }

        if(realm.getClientById(client.getId()) == null) {
            LOGGER.warnf("Client %s not found", client.getId());
            throw new RuntimeException("Client not found");
        }

        if (!client.isEnabled()) {
            LOGGER.warnf("Client %s is not available", client.getId());
            throw new RuntimeException("Client is disabled");
        }
    }
}
