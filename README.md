# Mock Identity Provider

This repository contains a simplified implementation of an [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) identity provider designed for use in development and testing environments where an application implements OpenID Connect Core for authenticating users.

> Note: This is NOT intended to be used in production environments!

## Quick Start

### Docker

To run the docker container with the [default configuration](config.json):

```sh
docker pull ghcr.io/norelect/mock-identity-provider:latest
docker run --rm -it -p 8000:8000 ghcr.io/norelect/mock-identity-provider:latest
```

To use a custom configuration, create a `config.json` file:

```sh
cat > config.json <<'EOF'
{
  "issuer": "http://localhost:8000",
  "key_size": 4096,
  "users": [
    {
      "sub": "user",
      "claims": {
        "name": "User",
        "email": "normal.user@example.com"
      }
    }
  ]
}
EOF
```

Then, mount it into the container:

```sh
docker run --rm -it -p 8000:8000 -v "$(pwd)/config.json:/config.json:ro" ghcr.io/norelect/mock-identity-provider:latest
```

### Kubernetes

Install the helm chart from this repository using a custom `values.yaml` file:

```sh
cat > values.yaml <<'EOF'
config:
  issuer: "https://idp.example.com"
  key_size: 4096
  users:
    - sub: user
      claims:
        name: User
        email: normal.user@example.com

ingress:
  enabled: true
  hosts:
    - host: idp.example.com
      paths:
        - path: /
          pathType: ImplementationSpecific
EOF

helm install mock-identity-provider oci://ghcr.io/norelect/charts/mock-identity-provider -f values.yaml
```

## Issue tokens

To issue tokens from within CI/CD pipelines in tests or from the command line non-interactively, a request to the `/token` endpoint can be created using the `password` grant:

```sh
curl -X POST $ISSUER/token -d "grant_type=password&client_id=demo&username=user"
```

The endpoint intentionally doesn't require a password and directly issues the tokens if the user exists within the configuration.
