# Setting Up API Gateway with OAuth2

## Prerequisites

- **Docker** installed on your machine.
- **Java 17** installed on your computer.

## Steps

1. **Start the Keycloak OAuth2 Provider**

   Use Docker Compose to build and start the Keycloak OAuth2 provider. Run the following command in your terminal:

   ```bash
   docker-compose -f keycloak-docker-compose.yml up --build
