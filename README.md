# xirugias-mcp-core

The MCP endpoint shared by the Xirugias apps (tenant, Nómina, …): OAuth 2.1
on the Xirugias login, bearer auth with per-call re-checks, stateless
Streamable HTTP transport, rate limits, result truncation and an audit log.
Each app supplies only what differs: its tools, its scoping rules, its
stores and the wording of the login page.

Read-only by design: the core never writes app data; the only writes are
its own OAuth records and audit rows.

## Install

No registry. Pin a tag from GitHub in the app's `package.json`:

```json
"xirugias-mcp-core": "github:jlvas-cloud/xirugias-mcp-core#v0.1.2"
```

The lockfile records the dependency as `git+ssh://git@github.com/...`, which a
Heroku/Railway build cannot clone unless the repo is **public** (npm then
falls back to the GitHub tarball). For a private repo, give the build a
read-only GitHub token (`GITHUB_TOKEN` config var) and rewrite the URL
before `npm ci` with a `heroku-prebuild` script in the app's root
`package.json`:

```json
"heroku-prebuild": "git config --global url.\"https://${GITHUB_TOKEN}@github.com/\".insteadOf \"ssh://git@github.com/\""
```

(`${VAR}` expands in a shell script, not in a package.json dependency
spec — never put the token in the spec itself.)

Peer dependencies: the app's `express` (>=4.16) and `mongoose` (>=7).

## Use

```js
const { createMcpCore, ToolError, schemas } = require('xirugias-mcp-core');

const core = createMcpCore({
    issuerUrl: () => process.env.MCP_ISSUER_URL || 'https://www.example.com',
    resourceName: 'Xirugias',
    scopes: ['xirugias:read'],
    accessPermission: 'can_use_agentes',      // only named in the 403 message
    stores: {                                 // mongoose models built from `schemas`
        clients: () => getMcpOAuthClientsModel(),
        authCodes: () => getMcpAuthCodesModel(),
        connections: () => getMcpConnectionsModel(),
        auditLog: companyId => getMcpAuditLogModel(companyId)
    },
    authenticate: async (email, password) => ({ principal }) /* or { error: 'message for the login page' } */,
    loadPrincipal: async (userId, companyId) => principal /* or null */,
    checkConnection: false,                   // true for apps without a user tokenVersion
    loginPage: { title, heading, prompt, scopeText, emailLabel, footer },
    server: { name: 'xirugias', version: '0.1.0', instructions, resources, rowCountKeys: ['cotizaciones'] },
    tools: { definitions: TOOL_DEFINITIONS, execute: (name, input, principal) => … }
});

app.use(core.oauthRouter());           // at the root: /.well-known, /authorize, /token, /register, /revoke, /oauth/login
app.use('/mcp', core.mcpRouter());     // before the SPA catch-all
```

A principal is whatever `loadPrincipal` returns. The core reads `userId`,
`companyId`, `email`, `name`, `deactivated`, `tokenVersion` (0 when the app
has none) and `canUseAgentes`; everything else is passed through to
`tools.execute` for scoping.

`authenticate` owns the whole login decision (password, account state, the
app's access permission) and returns the message the login page shows.

Throw `ToolError` from a tool for a message the agent may see; any other
error is logged and replaced by a generic one.

Environment read at mount time: `MCP_RATE_LIMIT_PER_MIN` (default 240 per
user), `MCP_AUTH_RATE_LIMIT_PER_15MIN` (default 60 per IP on login, register
and token). `JWT_SECRET` is read on every sign/verify unless `jwtSecret` is
given.

## Smoke-testing against a running server

Access tokens carry `iss` = the server's issuer URL. A token minted locally
(an app's `signAccessToken`, e.g. the tenant's `scripts/mcpSmokeTest.js --email`)
is accepted only if the minting process uses the same issuer: set
`MCP_ISSUER_URL` to the target server's public URL when minting.

## Tests

`npm test` runs the package suite against in-memory stores (no Mongo).
Each app keeps its own suite for scoping and tools.

## Releasing

Bump `version` in `package.json`, commit, `git tag vX.Y.Z && git push --tags`,
then update the pin in each app and `npm install`.
