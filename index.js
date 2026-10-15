/**
 * xirugias-mcp-core — the shared MCP endpoint for the Xirugias apps.
 *
 *   const core = createMcpCore({ ...options });
 *   app.use(core.oauthRouter());        // at the root (discovery documents)
 *   app.use('/mcp', core.mcpRouter());  // before the SPA catch-alls
 *
 * What the app supplies: how to check a password and the access permission
 * (`authenticate`), how to re-read a user (`loadPrincipal`), where the
 * OAuth clients/codes/connections and the audit log live (`stores`), and
 * its tools, resources and instructions. Everything else — OAuth 2.1 with
 * dynamic registration and PKCE, bearer auth, stateless Streamable HTTP,
 * rate limits, result truncation, audit — is the same in every app.
 *
 * A principal is the plain object `loadPrincipal` returns. The core reads
 * these fields: userId, companyId, email, name, deactivated, tokenVersion
 * (0 when the app has none), canUseAgentes. Anything else is the app's
 * scoping data and is passed through to `tools.execute`.
 */
const schemas = require('./lib/schemas');
const { createOAuth, escapeHtml, DEFAULT_LOGIN_PAGE } = require('./lib/oauth');
const { createBearerAuth } = require('./lib/auth');
const { createMcpServerFactory, ToolError, READ_ONLY_ANNOTATIONS } = require('./lib/server');
const { createOAuthRouter, createMcpRouter, clientIp } = require('./lib/routers');

const REQUIRED = ['issuerUrl', 'stores', 'authenticate', 'loadPrincipal', 'tools'];

function envNumber(name, fallback) {
    const n = Number(process.env[name]);
    return Number.isFinite(n) && n > 0 ? n : fallback;
}

/**
 * @param {object} o
 * @param {() => string} o.issuerUrl        public base URL (no trailing slash)
 * @param {() => string} [o.jwtSecret]      default: process.env.JWT_SECRET
 * @param {string} [o.resourceName]         shown in the OAuth metadata
 * @param {string[]} [o.scopes]             default ['<app>:read']
 * @param {string} [o.realm]                WWW-Authenticate realm
 * @param {string} o.accessPermission       name of the app permission that opens the MCP
 * @param {object} o.stores                 { clients(), authCodes(), connections(), auditLog(companyId) } → Promise<Model>
 * @param {Function} o.authenticate         (email, password) → {principal} | {error}
 * @param {Function} o.loadPrincipal        (userId, companyId) → principal | null
 * @param {boolean} [o.checkConnection]     re-read the connection on every call (apps without tokenVersion)
 * @param {object} [o.loginPage]            copy for the login page
 * @param {object} o.server                 { name, version, instructions, resources?, maxResultChars?, rowCountKeys?, toolVisible? }
 * @param {object} o.tools                  { definitions, execute(name, input, principal) }
 * @param {object} [o.rateLimit]            { perMinute, authPer15Min } (env MCP_RATE_LIMIT_PER_MIN / MCP_AUTH_RATE_LIMIT_PER_15MIN win)
 */
function createMcpCore(o) {
    for (const key of REQUIRED) {
        if (!o || o[key] == null) throw new Error(`createMcpCore: option "${key}" is required`);
    }
    const appKey = (o.server && o.server.name) || 'app';
    const jwtSecret = o.jwtSecret || (() => {
        if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not configured');
        return process.env.JWT_SECRET;
    });
    const scopes = o.scopes || [`${appKey}:read`];
    const accessPermission = o.accessPermission || 'can_use_agentes';

    const oauth = createOAuth({
        jwtSecret,
        issuerUrl: o.issuerUrl,
        scopes,
        stores: o.stores,
        authenticate: o.authenticate,
        loadPrincipal: o.loadPrincipal,
        loginPage: o.loginPage,
        accessTokenTtlSec: o.accessTokenTtlSec,
        authCodeTtlMs: o.authCodeTtlMs,
        connectionTtlDays: o.connectionTtlDays
    });

    const bearer = createBearerAuth({
        jwtSecret,
        issuerUrl: o.issuerUrl,
        realm: o.realm || `${appKey}-mcp`,
        accessPermission,
        inactiveMessage: o.inactiveMessage,
        loadPrincipal: o.loadPrincipal,
        checkConnection: !!o.checkConnection,
        stores: o.stores
    });

    const server = createMcpServerFactory({
        name: o.server.name,
        version: o.server.version || '0.1.0',
        instructions: o.server.instructions || '',
        tools: o.tools,
        resources: o.server.resources,
        auditLog: o.stores.auditLog,
        maxResultChars: o.server.maxResultChars,
        rowCountKeys: o.server.rowCountKeys,
        isToolError: o.server.isToolError,
        toolVisible: o.server.toolVisible
    });

    const rl = o.rateLimit || {};

    return {
        // OAuth
        provider: oauth.provider,
        handleLogin: oauth.handleLogin,
        signAccessToken: oauth.signAccessToken,
        issuerUrl: o.issuerUrl,
        SCOPES: scopes,
        ACCESS_TOKEN_TTL_SEC: oauth.ACCESS_TOKEN_TTL_SEC,
        // Bearer
        requireMcpUser: bearer.requireMcpUser,
        // Server
        createMcpServer: server.createMcpServer,
        runTool: server.runTool,
        INSTRUCTIONS: o.server.instructions || '',
        SERVER_NAME: o.server.name,
        SERVER_VERSION: o.server.version || '0.1.0',
        // Routers (rate limits are read when the router is built, so tests can
        // set the env before mounting)
        oauthRouter: () => createOAuthRouter({
            provider: oauth.provider,
            handleLogin: oauth.handleLogin,
            issuerUrl: o.issuerUrl,
            scopes,
            resourceName: o.resourceName || appKey,
            authRateLimitPer15Min: envNumber('MCP_AUTH_RATE_LIMIT_PER_15MIN', rl.authPer15Min || 60)
        }),
        mcpRouter: () => createMcpRouter({
            requireMcpUser: bearer.requireMcpUser,
            createMcpServer: server.createMcpServer,
            rateLimitPerMin: envNumber('MCP_RATE_LIMIT_PER_MIN', rl.perMinute || 240)
        })
    };
}

module.exports = { createMcpCore, ToolError, schemas, escapeHtml, clientIp, READ_ONLY_ANNOTATIONS, DEFAULT_LOGIN_PAGE };
