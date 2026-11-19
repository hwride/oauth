# Local OpenID conformance testing

## Prerequisites

Install Docker and `mkcert` before starting the conformance suite.

On macOS:

```shell
brew install mkcert
```

On Windows, install it with Chocolatey or Scoop:

```powershell
choco install mkcert
```

The first `npm run conformance:up` runs `mkcert -install`, creates a locally trusted certificate for the development hostnames, and mounts it into both nginx HTTPS proxies. Generated certificates are stored locally and ignored by Git.

## Start

1. Start Docker Desktop. From the repository root, run these in two terminals:
1. Boot the conformance suite and our auth server HTTPS proxy: `npm run conformance:up`.
1. Boot the server with `npm run dev:conformance`. This loads the HTTPS issuer and listen address from `conformance.env`.
1. The conformance suite should then be available at <https://localhost.emobix.co.uk:8443>.

> [!NOTE]  
> Note conformance suite run state is data is persisted in  `./mongo/data`, delete that if you want a fresh site.

## Create a test plan
1. Go to <https://localhost.emobix.co.uk:8443>
1. Click "Create a new test"
1. Select a test plan.
1. Configure the test plan. See the sections below.
1. Click "Run Test".

### Users
Login with `jane`/`password` if you don't want MFA.

### Configuring test plans
#### OpenID Connect Core > Config
1. `server.discoveryUrl`: `https://host.docker.internal:4443/.well-known/openid-configuration`.
   The proxy uses a locally trusted `mkcert` certificate. The same certificate is used by the conformance suite at `https://localhost.emobix.co.uk:8443`.

#### OpenID Connect Core > Basic

1. Test information
   1. `alias`: `oauth-local`. The alias keeps the callback URI consistent across runs at `https://localhost.emobix.co.uk:8443/test/a/oauth-local/callback`.
1. Server
   1. `discoveryUrl`: <https://host.docker.internal:4443/.well-known/openid-configuration>
1. Client
   1. `client.client_id`: `conformance-client-1`
   1. `client.client_secret`: `conformance-secret-1`
1. Second client
   1. `client.client_id`: `conformance-client-2`
   1. `client.client_secret`: `conformance-secret-2`

Both clients use `client_secret_basic`.

See the [official OpenID Provider testing instructions](https://openid.net/certification/connect_op_testing/) for the full client setup information.

## Shutdown
1. Run `npm run conformance:down`

## Other notes
### Conformance suite URL
You might wonder why the local Docker Compose setup uses
<https://localhost.emobix.co.uk:8443> even though the hostname belongs to the
public `emobix.co.uk` domain.

The hostname has a public DNS record, but its IPv4 address intentionally points
to the local loopback address `127.0.0.1`:

```shell
dig localhost.emobix.co.uk

...
;; ANSWER SECTION:
localhost.emobix.co.uk. 3133    IN      A       127.0.0.1
```

## Sources

- Running the suite locally using a pre-built version with Docker: <https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run#quick-start-running-a-prebuilt-version-with-docker>
- Direct link the Docker composer file: <https://gitlab.com/openid/conformance-suite/-/blob/master/docker-compose-prebuilt.yml>
- Official suite main repo: <https://gitlab.com/openid/conformance-suite>
- OpenID Provider official testing instructions: <https://openid.net/certification/connect_op_testing/>
