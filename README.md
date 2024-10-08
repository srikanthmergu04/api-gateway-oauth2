# Setting Up API Gateway with OAuth2

## Project Overview

This project involves setting up an API Gateway with OAuth2 Authentication and Authorization support using Keycloak as the OAuth2 provider.

## Prerequisites

- **Docker**: Ensure Docker is installed on your machine.
- **Java 17**: Make sure Java 17 is installed on your computer.

## Steps

### 1. Start the Keycloak OAuth2 Provider

Use Docker Compose to build and start the Keycloak OAuth2 provider. Run the following command in your terminal:

```bash
docker-compose -f keycloak-docker-compose.yml up --build
```

### 2. Generate an OAuth2 Token

To generate an OAuth2 token using Keycloak, use the following `curl` command. Replace the placeholders with your actual Keycloak server details, client credentials, and user information.

### `curl` Command

```bash
curl --location 'http://localhost:8080/realms/{yourRealmName}/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id={client_id}' \
--data-urlencode 'client_secret={client_secret}' \
--data-urlencode 'username={username}' \
--data-urlencode 'password={password}' \
--data-urlencode 'grant_type=password'
