package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.ErrorResponseException;

import java.util.UUID;

public class AnonymousGrantType implements OAuth2GrantType {

    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantType.class);
    private final KeycloakSession session;
    //private static final String ACCESS_TOKEN_LIFESPAN = 300;

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

        if (client == null || !client.isEnabled()) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_CLIENT,
                    "Invalid client credentials", Response.Status.UNAUTHORIZED);
        }

        UserModel transientUser = createTransientUser(realm);
        EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
        event.event(EventType.LOGIN);

        //ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionScopeParameter();
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

        // Build and return the token response
        AccessTokenResponse tokenResponse = new TokenManager().responseBuilder(
                        realm,
                        client,
                        event,
                        session,
                        userSession,
                        null
                )
                .generateAccessToken()
                .generateRefreshToken()
                .generateIDToken()
                .build();
LOGGER.info("TOKEN TOTO" + tokenResponse.toString());
        return Response.ok(tokenResponse).build();
    }

    private UserModel createTransientUser(RealmModel realm) {
        String anonUsername = "anon-" + UUID.randomUUID();
        UserModel user = session.users().addUser(realm, anonUsername);
        user.setEnabled(true);
        user.setSingleAttribute("anonymous", "true");

        return user;
    }
}
