# keycloak-grant_type-anonymous-extension

## Overview

This Keycloak extension introduces support for the custom OAuth2 grant type `anonymous`. It allows clients to request an access token without providing user credentials, enabling anonymous or guest access to protected resources. This can be useful for scenarios where limited, non-authenticated access is required (e.g., for demo, onboarding, or public API features).

### How it works

- The extension registers a new grant type named `anonymous` with Keycloak's OAuth2 protocol.
- When a client sends a token request with `grant_type=anonymous`, Keycloak processes the request using this extension.
- No user credentials are required; only the `client_id` must be provided.
- The extension issues an access token with a subject representing an anonymous user. The token may contain limited or custom claims, depending on your configuration and implementation.
- You can configure Keycloak policies and roles to restrict what anonymous users can access.

**Example token request:**
```bash
curl --request POST \
  --url http://localhost:8080/auth/realms/demo/protocol/openid-connect/token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data 'grant_type=anonymous' \
  --data 'client_id=demo'
```

**Security note:**
Anonymous tokens should be used with caution. They grant access without authentication, so always ensure that resources accessible to anonymous users are properly restricted and monitored.

### Response format

When a client requests a token using the `anonymous` grant type, the response is a JSON object similar to a standard OAuth2 token response. Here is an example:

```json
{
  "access_token": "<access_token>",
  "expires_in": 300,
  "refresh_expires_in": 0,
  "token_type": "Bearer",
  "not-before-policy": 0,
  "scope": ""
}
```

- `access_token`: The JWT access token issued for the anonymous session.
- `expires_in`: Lifetime in seconds of the access token (default: 300 seconds).
- `refresh_expires_in`: Lifetime of the refresh token (usually 0, as refresh tokens are not issued for anonymous grants).
- `token_type`: Always `Bearer`.
- `not-before-policy`: Keycloak policy timestamp (usually 0).
- `scope`: The granted scopes 

The actual claims inside the `access_token` can be customized in the extension code or via Keycloak configuration, but by default, the subject (`sub`) will represent an anonymous user and the token will have limited privileges.

By default, the anonymous user created for this grant type is a **transient user** in Keycloak. This means the user is not persisted in the Keycloak database and only exists for the duration of the token request. This ensures that no permanent user account is created for anonymous or guest sessions.


## Installation

1. **Clone the repository**
   ```bash
   git clone https://gitlab.liksi.io/liksi/cloud-iam/arte-web/keycloak-grant_type-anonymous-extension.git
   cd keycloak-grant_type-anonymous-extension
   ```

2. **Build the project**
   Ensure you have Maven installed on your system.
   ```bash
   mvn install
   mvn clean package
   ```

3. **Run Keycloak with Docker**
   Make sure Docker is installed and running on your system.
   ```bash
   docker-compose up
   ```

## Credits

This extension was developed by Liksi on behalf of the Arte GEIE team from Strasbourg, France. We are open to external contributions and suggestions, so feel free to create an issue or a pull request.

## License

This extension, just like Keycloak, is licensed under the Apache License, Version 2.0. You can find the full license text in the LICENSE file.
