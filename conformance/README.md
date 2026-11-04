# Local OpenID conformance testing

## Start

1. Start Docker Desktop. From the repository root, run these in two terminals:
2. Boot the server `npm run dev`
3. Boot the conformance suite: `npm run conformance:up`

## Create a test plan
1. Go to https://localhost.emobix.co.uk:8443/
2. Click "Create a new test"
3. Click OpenID Connect Core > Config
4. For discovery URL put `http://host.docker.internal:4000/.well-known/openid-configuration`. This will allow the conformance suite to call basically call `localhost:4000`.
5. Click "Run Test".

## Shutdown
1. Run `npm run conformance:down`

## Sources

- Running the suite using docker: https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run#running-the-conformance-suite-locally-using-docker
- Official suite: <https://gitlab.com/openid/conformance-suite>
- Prebuilt Compose reference: <https://gitlab.com/openid/conformance-suite/-/blob/master/docker-compose-prebuilt.yml>
- OP testing instructions: <https://openid.net/certification/connect_op_testing/>
