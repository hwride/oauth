# Local OpenID conformance testing

## Start

1. Start Docker Desktop. From the repository root, run these in two terminals:
1. Boot the conformance suite and our auth server HTTPS proxy: `npm run conformance:up`.
1. Boot the server with the HTTPS issuer used by the proxy:
   ```shell
   export ISSUER="https://host.docker.internal:4443"
   export AUTH_SERVER_HOST="0.0.0.0" # This is not always necessary.
   npm run dev:conformance
   ```
1. The conformance suite should then be available at <https://localhost.emobix.co.uk:8443>.

> [!NOTE]  
> Note conformance suite run state is data is persisted in  `./mongo/data`, delete that if you want a fresh site.

## Create a test plan
1. Go to <https://localhost.emobix.co.uk:8443>
2. Click "Create a new test"
3. Click OpenID Connect Core > Config
4. For discovery URL put `https://host.docker.internal:4443/.well-known/openid-configuration`.
   The proxy uses a local self-signed certificate, so accept the certificate warning when opening the URL in a browser.
5. Click "Run Test".

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
