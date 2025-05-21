package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.light.LightweightUserAdapter;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.TokenManager.AccessTokenResponseBuilder;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.storage.adapter.InMemoryUserAdapter;
import org.keycloak.util.TokenUtil;

import java.util.UUID;

import static org.keycloak.models.light.LightweightUserAdapter.isLightweightUser;
import static org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER;

public class AnonymousGrantType extends OAuth2GrantTypeBase {

    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantType.class);
    private final KeycloakSession session;

    public AnonymousGrantType(KeycloakSession session) {
        this.session = session;
        LOGGER.debug("******** ANONYMOUS GRANT TYPE PROVIDER INITIALIZED ********");
    }


    @Override
    public void close() {
        LOGGER.debug("******** CLOSING ANONYMOUS GRANT TYPE PROVIDER ********");
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    @Override
    public Response process(Context context) {
        setContext(context);
        event.detail(Details.AUTH_METHOD, "anonymous");

        UserModel transientUser = createTransientUser();
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

        AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client, userSession);

        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(
            clientSession, null, session
        );

        LOGGER.info("******* ANONYMOUS GRANT TYPE START TOKEN GENERATION *******");

        TokenManager tokenManager = new TokenManager();
        // Create token response builder
        AccessTokenResponseBuilder tokenResponseBuilder = tokenManager
                .responseBuilder(realm, client, event, session, userSession, clientSessionCtx)
                .generateAccessToken();

        AccessTokenResponse tokenResponse = build(tokenResponseBuilder, userSession, clientSessionCtx);
        tokenResponse.setScope("anonymous");

        event.detail(Details.TOKEN_ID, tokenResponseBuilder.getAccessToken().getId());
        event.success();

        LOGGER.trace("******* ANONYMOUS GRANT TYPE TOKEN GENERATED SUCCESSFULLY *******");
        return cors.add(Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE));
    }

    public AccessTokenResponse build(AccessTokenResponseBuilder tokenResponseBuilder, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        AccessTokenResponse res = new AccessTokenResponse();
        AccessToken accessToken = tokenResponseBuilder.getAccessToken();
        if (accessToken != null) {
            event.detail(Details.TOKEN_ID, accessToken.getId());
        }

        if (accessToken != null) {
            String encodedToken = session.tokens().encode(accessToken);
            res.setToken(encodedToken);
            res.setTokenType(formatTokenType(client));
            res.setSessionState(accessToken.getSessionState());
            if (accessToken.getExp() != 0) {
                res.setExpiresIn(accessToken.getExp() - Time.currentTime());
            }
        }

        int notBefore = realm.getNotBefore();
        if (client.getNotBefore() > notBefore) {
            notBefore = client.getNotBefore();
        }
        res.setNotBeforePolicy(notBefore);

        res = tokenManager.transformAccessTokenResponse(session, res, userSession, clientSessionCtx);

        // OIDC Financial API Read Only Profile : scope MUST be returned in the response from Token Endpoint
        String responseScope = clientSessionCtx.getScopeString();
        res.setScope(responseScope);
        event.detail(Details.SCOPE, responseScope);

        return res;
    }

    private String formatTokenType(ClientModel client) {
        if (OIDCAdvancedConfigWrapper.fromClientModel(client).isUseLowerCaseInTokenResponse()) {
            return TokenUtil.TOKEN_TYPE_BEARER.toLowerCase();
        }
        return TokenUtil.TOKEN_TYPE_BEARER;
    }

    private UserModel createTransientUser() {
        String id = UUID.randomUUID().toString();
        UserModel user = new LightweightUserAdapter(session, id);
        user.setUsername("anon-" + id);
        user.setEnabled(true);
        user.setSingleAttribute("anonymous", "true");

        return user;
    }

}
