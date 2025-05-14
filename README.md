# keycloak-grant_type-anonymous-extension

## Getting Started

This project is a Keycloak extension that adds anonymous grant type support. Follow the instructions below to set up and run the project.

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