# Mock Identity Provider

This repository contains a simplified implementation of an [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) identity provider designed for use in development and testing environments where an application implements OpenID Connect Core for authenticating users.

> Note: This is NOT intended to be used in production environments!

## Quick Start

### Docker

Pull and run the docker container (this will deploy the default configuration, as specified in [config.json](config.json)):

```sh
docker pull ghcr.io/norelect/mock-identity-provider:latest
docker run --rm -it -p 8000:8000 ghcr.io/norelect/mock-identity-provider:latest
```

### Kubernetes

Install the helm chart from this repository (this will deploy the default configuration, as specified in [values.yaml](charts/mock-identity-provider/values.yaml)):

```sh
helm install mock-identity-provider oci://ghcr.io/norelect/charts/mock-identity-provider \
    --set issuer=idp.example.com \
    --set ingress.enabled=true \
    --set ingress.hosts[0].host=idp.example.com
```

## Issue tokens

To issue tokens from within CI/CD pipelines in tests or from the command line non-interactively, a request to the `/token` endpoint can be created using the `password` grant:

```sh
curl -X POST $ISSUER/token \
    -d "grant_type=password&client_id=demo&username=user"
```

The endpoint intentionally doesn't require a password and directly issues the tokens if the user exists within the configuration.
