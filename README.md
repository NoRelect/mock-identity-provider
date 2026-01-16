# mock-identity-provider

A lightweight **Mock Identity Provider (IdP)** for **OpenID Connect (OIDC)** and **OAuth 2.0**, built on **OpenIddict**.  
Designed for **local development**, **integration testing**, **automation**, and **security testing** where a real IdP would be overkill.

---

## Features

- OIDC-compliant authorization server
- Supports multiple OAuth2 flows
  - Authorization Code
  - Hybrid
  - Implicit
  - Password (Resource Owner Password Credentials)
  - Refresh Token
  - None
- In-memory users defined via configuration
- Per-user roles and **custom claims**
- `/authorize`, `/token`, `/user-info`, `/logout`, `/revoke`
- No persistence, no database
- No client registration required
- Suitable for CI pipelines and local testing

---

## Configuration

All configuration is done via `appsettings.json`.

### Example `appsettings.json`

```json
{
  "Issuer": "http://localhost:6123",

  "AllowAuthorizationCodeFlow": true,
  "AllowHybridFlow": true,
  "AllowImplicitFlow": true,
  "AllowRefreshTokenFlow": true,
  "AllowPasswordFlow": true,
  "AllowNoneFlow": true,

  "Users": [
    {
      "id": "user",
      "name": "User",
      "email": "user@mock.idp",
      "roles": ["user"]
    },
    {
      "id": "admin",
      "name": "Admin",
      "email": "admin@mock.idp",
      "roles": ["admin"],
      "claims": {
        "tenant_id": "t-001",
        "department": "engineering"
      }
    }
  ]
}
````

---

## Endpoints

| Endpoint     | Description                                         |
| ------------ | --------------------------------------------------- |
| `/authorize` | Authorization endpoint (interactive user selection) |
| `/token`     | Token endpoint                                      |
| `/user-info` | UserInfo endpoint                                   |
| `/logout`    | End session                                         |
| `/revoke`    | Token revocation                                    |

---

## Requesting Tokens (Automation)

### Password Grant (CI / automation)

```sh
curl -X POST http://localhost:6123/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=admin&password=ignore"
```

* `password` is ignored
* `username` must match a configured user ID
* No client authentication required

---

### Example Token Response

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "profile email role"
}
```

---

## Authorization Code Flow (Browser)

1. Open in browser:

```text
http://localhost:6123/authorize?response_type=code&client_id=test&scope=profile email role
```

2. Select a user from the UI
3. Receive authorization code
4. Exchange code at `/token`

---

## Custom Claims

Custom claims are defined per user:

```json
"claims": {
  "tenant_id": "t-001",
  "department": "engineering"
}
```

They are:

* Included in **access tokens**
* Included in **ID tokens**
* Returned via `/user-info`

---

## Security Notes

* No HTTPS enforced (by design)
* No client validation
* No token encryption
* No persistence
* **Do not use in production**

This project is intended **only** for:

* Local development
* Automated tests
* CI/CD pipelines
* Security tooling

---

## Typical Use Cases

* Frontend development without a real IdP
* Backend integration tests
* OAuth/OIDC client testing
* Security testing and demos
* Mocking Entra ID / Keycloak / Auth0 behavior

---

## License

MIT

