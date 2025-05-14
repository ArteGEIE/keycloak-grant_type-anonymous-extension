package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.util.UUID;

public class AnonymousGrantType implements OAuth2GrantType {

    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantType.class);
    private final KeycloakSession session;
    private static final Integer ACCESS_TOKEN_LIFESPAN = 300;

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

        // Verify client ID
        if (client != null && !client.getId().isEmpty()) {
            LOGGER.info("Client ID exists: " + client.getId());
        } else {
            LOGGER.warn("Client ID does not exist or is invalid.");
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid client ID").build();
        }

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
        AccessToken accessToken = new AccessToken();
        long currentTimeInSeconds = System.currentTimeMillis() / 1000;
        accessToken.exp(currentTimeInSeconds + ACCESS_TOKEN_LIFESPAN);

        AccessTokenResponse tokenResponse = new TokenManager().responseBuilder(
                realm,
                client,
                event,
                session,
                userSession,
                clientSessionCtx
        )
        .accessToken(accessToken)
        .generateAccessToken()
        .build();

        tokenResponse = formatAccessTokenResponse(tokenResponse);
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

    private AccessTokenResponse formatAccessTokenResponse(AccessTokenResponse tokenResponse) {
        AccessTokenResponse customTokenResponse = new AccessTokenResponse();
        customTokenResponse.setTokenType("Bearer");
        customTokenResponse.setToken(tokenResponse.getToken());
        customTokenResponse.setExpiresIn(ACCESS_TOKEN_LIFESPAN);
        customTokenResponse.setScope("openid");

        return customTokenResponse;
    }
}
