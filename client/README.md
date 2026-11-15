# OAuth Client

An OAuth Client. Mainly implemented for testing and learning. Not for use in production.

## Run

1. Set required environment variables:

- `AUTH_SERVER_BASE`
- `CLIENT_ID`
- `CLIENT_SECRET` if using a confidential client.

1. Optionally set:

- `CLIENT_AUTH_METHOD` to `client_secret_post` for form-body client credentials or `none` for a public client. Defaults to `client_secret_basic` for confidential clients.
- `DEFAULT_RESOURCE` to prefill the API resource field
- `DEFAULT_AUDIENCE` to prefill the API audience field
- `DEFAULT_SCOPES` to select known scope checkboxes and prefill additional scopes

1. Start the development server:

- `npm run dev`

## Local authorization server clients

Use one of these presets when testing against the authorization server in this repository:

### Opaque access token with Basic authentication

```env
CLIENT_ID=client-id-opaque
CLIENT_SECRET=test-client-secret
CLIENT_AUTH_METHOD=client_secret_basic
```

### JWT access token with Basic authentication

```env
CLIENT_ID=client-id-jwt
CLIENT_SECRET=other-test-client-secret
CLIENT_AUTH_METHOD=client_secret_basic
```

### JWT access token with POST authentication

```env
CLIENT_ID=client-id-jwt-post-auth
CLIENT_SECRET=jwt-post-auth-client-secret
CLIENT_AUTH_METHOD=client_secret_post
```

### Public JWT client

```env
CLIENT_ID=client-id-public
CLIENT_AUTH_METHOD=none
```

### OpenID Conformance clients

```env
CLIENT_ID=conformance-client-1
CLIENT_SECRET=conformance-secret-1
CLIENT_AUTH_METHOD=client_secret_basic
```

```env
CLIENT_ID=conformance-client-2
CLIENT_SECRET=conformance-secret-2
CLIENT_AUTH_METHOD=client_secret_basic
```

```env
CLIENT_ID=conformance-client-post-auth
CLIENT_SECRET=conformance-secret-3
CLIENT_AUTH_METHOD=client_secret_post
```
