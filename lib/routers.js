/**
 * Express routers.
 *
 * oauthRouter — mounted at the app ROOT because the discovery documents must
 * live at /.well-known/…: the SDK router serves
 *   /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource/mcp,
 *   /authorize, /token, /register, /revoke
 * and POST /oauth/login receives the credentials from the page /authorize renders.
 * The SDK handlers set their own CORS headers (register/token/revoke/
 * metadata are called cross-origin by claude.ai); /authorize and /oauth/login
 * are plain browser navigations. Nothing here applies CORS router-wide:
 * mounted at the root, that would leak it onto every route after it.
 *
 * mcpRouter — mounted at /mcp. Stateless Streamable HTTP: a fresh transport
 * + server per request, bound to the authenticated user. Rate-limited per
 * user after auth (behind Heroku's router without `trust proxy`, an IP key
 * would put everyone in one bucket); unauthenticated calls only ever pay
 * for the cheap 401.
 */
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { mcpAuthRouter } = require('@modelcontextprotocol/sdk/server/auth/router.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');

// The app sits behind Heroku's router; req.ip is the router and the client
// address is the last X-Forwarded-For entry.
function clientIp(req) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
    return xff.length ? xff[xff.length - 1] : req.ip;
}

function createOAuthRouter({ provider, handleLogin, issuerUrl, scopes, resourceName, authRateLimitPer15Min }) {
    const router = express.Router();
    const issuer = new URL(issuerUrl());
    // Login page + token endpoints are the brute-force surface; keep it slow.
    const authLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: authRateLimitPer15Min,
        keyGenerator: clientIp,
        validate: false,
        standardHeaders: 'draft-7',
        legacyHeaders: false,
        message: { error: 'too_many_requests' }
    });
    router.use(['/oauth/login', '/register', '/token'], authLimiter);
    router.use(mcpAuthRouter({
        provider,
        issuerUrl: issuer,
        resourceServerUrl: new URL('/mcp', issuer),
        resourceName,
        scopesSupported: scopes
    }));
    // Some clients look for the metadata at the root path; the SDK serves it
    // path-suffixed (/.well-known/oauth-protected-resource/mcp) per RFC 9728
    router.get('/.well-known/oauth-protected-resource', (req, res, next) => {
        req.url = '/.well-known/oauth-protected-resource/mcp';
        router.handle(req, res, next);
    });
    router.post('/oauth/login', express.urlencoded({ extended: false }), (req, res, next) => handleLogin(req, res).catch(next));
    return router;
}

function createMcpRouter({ requireMcpUser, createMcpServer, rateLimitPerMin }) {
    const router = express.Router();
    const limiter = rateLimit({
        windowMs: 60 * 1000,
        limit: rateLimitPerMin,
        keyGenerator: req => req.mcpUser.userId,
        validate: false,
        standardHeaders: 'draft-7',
        legacyHeaders: false,
        message: { jsonrpc: '2.0', error: { code: -32000, message: 'Too many requests' }, id: null }
    });

    async function handle(req, res) {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
        const server = createMcpServer(req.mcpUser);
        res.on('close', () => {
            transport.close().catch(() => {});
            server.close().catch(() => {});
        });
        try {
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
        } catch (err) {
            console.error('MCP request failed:', err);
            if (!res.headersSent) {
                res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
            }
        }
    }

    router.use(cors());
    router.post('/', requireMcpUser, limiter, handle);
    // Stateless server: no standalone SSE stream and no sessions to delete.
    // 405 tells MCP clients "no notification stream offered" (they handle it).
    router.all('/', (req, res) => res.set('Allow', 'POST').sendStatus(405));
    return router;
}

module.exports = { createOAuthRouter, createMcpRouter, clientIp };
