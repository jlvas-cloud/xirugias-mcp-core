/**
 * Bearer auth for POST /mcp. Accepts only the OAuth access tokens the app
 * issues (aud=mcp), so a normal app session token can never reach the MCP
 * endpoint and an MCP token can never open the app.
 *
 * The principal is re-read on every call: deactivated, tokenVersion bumped
 * or the access permission removed → the agent is cut off immediately.
 * With `checkConnection`, the connection the token came from is also
 * re-read, so revoking it from the app takes effect at once even in apps
 * that have no tokenVersion.
 */
const jwt = require('jsonwebtoken');
const { getOAuthProtectedResourceMetadataUrl } = require('@modelcontextprotocol/sdk/server/auth/router.js');

/**
 * @param {object} o
 * @param {() => string} o.jwtSecret
 * @param {() => string} o.issuerUrl
 * @param {string} o.realm
 * @param {string} o.accessPermission  name shown in the 403 when missing
 * @param {string} [o.inactiveMessage]
 * @param {(userId, companyId) => Promise<principal|null>} o.loadPrincipal
 * @param {boolean} [o.checkConnection=false]
 * @param {object} [o.stores]  needs connections() when checkConnection
 */
function createBearerAuth(o) {
    function unauthorized(res, error) {
        const meta = getOAuthProtectedResourceMetadataUrl(new URL('/mcp', o.issuerUrl()));
        res.set('WWW-Authenticate', `Bearer realm="${o.realm}", resource_metadata="${meta}"${error ? `, error="${error}"` : ''}`);
        return res.status(401).json({ error: error === 'invalid_token' ? 'Invalid, expired or non-MCP token' : 'Missing bearer token' });
    }

    async function requireMcpUser(req, res, next) {
        const header = req.headers.authorization || '';
        const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
        if (!token) return unauthorized(res);

        let payload;
        try {
            payload = jwt.verify(token, o.jwtSecret(), { algorithms: ['HS256'], audience: 'mcp' });
        } catch (_) {
            return unauthorized(res, 'invalid_token');
        }

        try {
            const principal = await o.loadPrincipal(payload.sub, payload.co);
            if (!principal) return res.status(403).json({ error: 'User unknown' });
            if (principal.deactivated) return res.status(403).json({ error: o.inactiveMessage || 'Account inactive' });
            if ((principal.tokenVersion || 0) !== (payload.tv || 0)) return unauthorized(res, 'invalid_token');
            if (!principal.canUseAgentes) return res.status(403).json({ error: `Permission ${o.accessPermission} missing` });
            if (o.checkConnection && payload.cn) {
                const Connections = await o.stores.connections();
                const conn = await Connections.findById(payload.cn).select('revokedAt expiresAt').lean();
                if (!conn || conn.revokedAt || conn.expiresAt < new Date()) return unauthorized(res, 'invalid_token');
            }

            req.mcpUser = {
                ...principal,
                clientId: payload.cid,
                connectionId: payload.cn,
                client: req.headers['user-agent'] || ''
            };
            return next();
        } catch (err) {
            return next(err);
        }
    }

    return { requireMcpUser };
}

module.exports = { createBearerAuth };
