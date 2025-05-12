# mock-identity-provider

Mock Identity Provider that supports OIDC

## Requesting tokens for automation

```sh
curl -X POST --data 'username=admin&password=ignore&grant_type=password' 'http://localhost:6123/token'
```
