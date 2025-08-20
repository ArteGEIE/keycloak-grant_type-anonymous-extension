# keycloak-grant_type-anonymous-extension

## Getting Started

This project is a Keycloak extension that adds anonymous grant type support. 

Follow the instructions below to set up and run the project.

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://gitlab.liksi.io/liksi/cloud-iam/arte-web/keycloak-grant_type-anonymous-extension.git
   cd keycloak-grant_type-anonymous-extension
   ```

2. **Build the Project**
   Ensure you have Maven installed on your system.
   ```bash
   mvn install
   ```

   ```bash
   mvn clean package
   ```

3. **Run Keycloak with Docker**
   Make sure Docker is installed and running on your system.
   ```bash
   docker-compose up
   ```

5. Usage

**Local Development:**
```bash
curl --request POST \
  --url http://localhost:8080/auth/realms/demo/protocol/openid-connect/token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data 'grant_type=anonymous' \
  --data 'client_id=demo'
```



6. **Access token format**

   ```json
   {
      "token_type": "Bearer",
      "access_token": "<access_token>",
      "expires_in": 300,
      "scope": "openid",
      // Default tokenResponseKeys
      "refresh_expires_in": 0,
      "not-before-policy": 0
   }    
   ```
   

## Credits

This extension was developed by Liksi on behalf of the Arte GEIE team from Strasbourg, France. We are open to external contributions and suggestions so feel free to create an issue or a pull request.

## License

This extension, just like Keycloak, is licensed under the Apache License, Version 2.0. You can find the full license text in the LICENSE file.
