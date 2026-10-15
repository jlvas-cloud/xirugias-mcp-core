/**
 * OAuth 2.1 provider for the MCP endpoint, driven by the SDK's mcpAuthRouter.
 *
 * Identity and authorization are the host app's: it supplies
 * `authenticate(email, password)` (password check + its own access permission)
 * and `loadPrincipal(userId, companyId)` (re-read on every token issue).
 * Access tokens are short JWTs with aud=mcp; refresh tokens are random,
 * stored hashed on a connection document that can be listed and revoked
 * per agent.
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const randomToken = () => crypto.randomBytes(32).toString('base64url');

function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function isAllowedRedirectUri(uri) {
    try {
        const u = new URL(uri);
        if (u.protocol === 'https:') return true;
        return u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
    } catch (_) {
        return false;
    }
}

function toClientInfo(doc) {
    if (!doc) return undefined;
    return {
        ...(doc.metadata || {}),
        client_id: doc.clientId,
        ...(doc.clientSecret ? { client_secret: doc.clientSecret } : {}),
        ...(doc.clientSecretExpiresAt ? { client_secret_expires_at: doc.clientSecretExpiresAt } : {}),
        client_name: doc.clientName,
        redirect_uris: doc.redirectUris
    };
}

const DEFAULT_LOGIN_PAGE = {
    lang: 'es',
    title: 'Acceso de agentes',
    heading: 'Acceso de agentes',
    prompt: clientName => `<strong>${escapeHtml(clientName)}</strong> quiere consultar la aplicación en tu nombre.`,
    scopeText: 'Solo lectura. El agente verá lo mismo que tú ves en la aplicación; no puede crear ni modificar nada.',
    emailLabel: 'Correo (cuenta Xirugias)',
    passwordLabel: 'Contraseña',
    button: 'Autorizar',
    footer: 'Puedes revocar este acceso en cualquier momento desde la aplicación.'
};

function renderLoginPage(copy, { clientName, params, error }) {
    const hidden = Object.entries(params)
        .filter(([, v]) => v !== undefined && v !== null && v !== '')
        .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
        .join('\n');
    return `<!doctype html>
<html lang="${escapeHtml(copy.lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(copy.title)}</title>
<style>
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f7;color:#1f2937;display:flex;min-height:100vh;align-items:center;justify-content:center}
  .card{background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08);padding:32px;width:100%;max-width:400px;box-sizing:border-box}
  h1{font-size:18px;margin:0 0 4px}p{margin:0 0 20px;color:#6b7280;font-size:14px;line-height:1.4}
  label{display:block;font-size:13px;font-weight:600;margin:12px 0 6px}
  input[type=email],input[type=password]{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:15px;box-sizing:border-box}
  button{width:100%;margin-top:20px;padding:11px;border:0;border-radius:8px;background:#1d4ed8;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
  .err{background:#fef2f2;color:#991b1b;border:1px solid #fecaca;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:8px}
  .scope{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:10px 12px;font-size:13px;color:#1e3a8a;line-height:1.4}
  .foot{margin-top:18px;font-size:12px;color:#9ca3af;text-align:center}
</style></head><body>
<form class="card" method="post" action="/oauth/login">
  <h1>${escapeHtml(copy.heading)}</h1>
  <p>${copy.prompt(clientName)}</p>
  <div class="scope">${escapeHtml(copy.scopeText)}</div>
  ${error ? `<div class="err" style="margin-top:12px">${escapeHtml(error)}</div>` : ''}
  <label for="email">${escapeHtml(copy.emailLabel)}</label>
  <input id="email" name="email" type="email" autocomplete="username" required autofocus>
  <label for="password">${escapeHtml(copy.passwordLabel)}</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  ${hidden}
  <button type="submit">${escapeHtml(copy.button)}</button>
  <div class="foot">${escapeHtml(copy.footer)}</div>
</form>
</body></html>`;
}

/**
 * @param {object} o
 * @param {() => string} o.jwtSecret
 * @param {() => string} o.issuerUrl
 * @param {string[]} o.scopes
 * @param {object} o.stores  { clients(), authCodes(), connections() } → Promise<Model>
 * @param {(email, password) => Promise<{principal}|{error}>} o.authenticate
 * @param {(userId, companyId) => Promise<principal|null>} o.loadPrincipal
 * @param {object} [o.loginPage]  copy overrides (see DEFAULT_LOGIN_PAGE)
 * @param {number} [o.accessTokenTtlSec=3600]
 * @param {number} [o.authCodeTtlMs=300000]
 * @param {number} [o.connectionTtlDays=180]
 */
function createOAuth(o) {
    const SCOPES = o.scopes;
    const ACCESS_TOKEN_TTL_SEC = o.accessTokenTtlSec || 60 * 60;
    const AUTH_CODE_TTL_MS = o.authCodeTtlMs || 5 * 60 * 1000;
    const CONNECTION_TTL_DAYS = o.connectionTtlDays || 180;
    const copy = { ...DEFAULT_LOGIN_PAGE, ...(o.loginPage || {}) };

    const clientsStore = {
        async getClient(clientId) {
            const Clients = await o.stores.clients();
            return toClientInfo(await Clients.findOne({ clientId }).lean());
        },
        async registerClient(client) {
            const redirectUris = (client.redirect_uris || []).filter(isAllowedRedirectUri);
            if (redirectUris.length === 0) {
                const err = new Error('redirect_uris must be https (or http://localhost)');
                err.status = 400;
                throw err;
            }
            const { client_id, client_secret, client_secret_expires_at, client_name, redirect_uris, ...metadata } = client;
            const Clients = await o.stores.clients();
            const doc = await Clients.create({
                clientId: client_id,
                clientSecret: client_secret,
                clientSecretExpiresAt: client_secret_expires_at,
                clientName: client_name || 'Agente',
                redirectUris,
                metadata
            });
            return toClientInfo(doc.toObject());
        }
    };

    function sendLoginPage(res, data) {
        // Chrome applies form-action to the redirect that follows the POST, so the
        // client's redirect origin (claude.ai, localhost...) must be allowed here.
        let redirectOrigin = '';
        try { redirectOrigin = new URL(data.params.redirect_uri).origin; } catch (_) { /* no redirect yet */ }
        res.set('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${redirectOrigin}; base-uri 'none'`);
        res.set('Cache-Control', 'no-store');
        res.status(data.error ? 400 : 200).type('html').send(renderLoginPage(copy, data));
    }

    /** POST /oauth/login — validate credentials, issue the code, redirect back to the agent. */
    async function handleLogin(req, res) {
        const { email, password, client_id, redirect_uri, code_challenge, state, scope, resource } = req.body || {};
        const client = await clientsStore.getClient(client_id);
        const params = { client_id, redirect_uri, code_challenge, state, scope, resource };
        const fail = error => sendLoginPage(res, { clientName: client ? client.client_name : 'Agente', params, error });

        if (!client || !redirect_uri || !code_challenge) return fail('Solicitud de autorización inválida. Vuelve a conectar el agente.');
        if (!client.redirect_uris.includes(redirect_uri)) return fail('redirect_uri no registrada para este cliente.');

        const { principal, error } = await o.authenticate(email, password);
        if (error) return fail(error);

        const AuthCodes = await o.stores.authCodes();
        const code = randomToken();
        await AuthCodes.create({
            code,
            clientId: client.client_id,
            userId: principal.userId,
            companyId: principal.companyId,
            email: principal.email,
            codeChallenge: code_challenge,
            redirectUri: redirect_uri,
            scopes: SCOPES,
            resource,
            expiresAt: new Date(Date.now() + AUTH_CODE_TTL_MS)
        });

        const target = new URL(redirect_uri);
        target.searchParams.set('code', code);
        if (state) target.searchParams.set('state', state);
        res.redirect(302, target.toString());
    }

    function signAccessToken({ userId, companyId, email, clientId, scopes, tokenVersion, connectionId }) {
        return jwt.sign(
            {
                sub: userId, co: companyId, email, cid: clientId, tv: tokenVersion,
                ...(connectionId ? { cn: String(connectionId) } : {}),
                scope: scopes.join(' '), aud: 'mcp', typ: 'oauth'
            },
            o.jwtSecret(),
            { expiresIn: ACCESS_TOKEN_TTL_SEC }
        );
    }

    async function issueTokens(connection) {
        const principal = await o.loadPrincipal(connection.userId, connection.companyId);
        if (!principal || principal.deactivated || !principal.canUseAgentes) throw new Error('Access revoked');
        // A tokenVersion bump is the app's "log out everywhere"; a refresh token
        // must not outlive it, so the connection is pinned to the version it was
        // created under.
        const tv = principal.tokenVersion || 0;
        if (connection.isNew) connection.tokenVersion = tv;
        else if ((connection.tokenVersion || 0) !== tv) throw new Error('Session invalidated');
        const refreshToken = randomToken();
        connection.refreshTokenHash = sha256(refreshToken);
        connection.lastUsedAt = new Date();
        connection.name = principal.name;
        await connection.save();
        return {
            access_token: signAccessToken({
                userId: connection.userId,
                companyId: connection.companyId,
                email: connection.email,
                clientId: connection.clientId,
                scopes: connection.scopes,
                tokenVersion: tv,
                connectionId: connection._id
            }),
            token_type: 'bearer',
            expires_in: ACCESS_TOKEN_TTL_SEC,
            refresh_token: refreshToken,
            scope: connection.scopes.join(' ')
        };
    }

    const provider = {
        clientsStore,

        async authorize(client, params, res) {
            sendLoginPage(res, {
                clientName: client.client_name || 'Agente',
                params: {
                    client_id: client.client_id,
                    redirect_uri: params.redirectUri,
                    code_challenge: params.codeChallenge,
                    state: params.state,
                    scope: (params.scopes || []).join(' '),
                    resource: params.resource ? params.resource.toString() : undefined
                }
            });
        },

        async challengeForAuthorizationCode(client, authorizationCode) {
            const AuthCodes = await o.stores.authCodes();
            const doc = await AuthCodes.findOne({ code: authorizationCode, clientId: client.client_id }).lean();
            if (!doc || doc.expiresAt < new Date()) throw new Error('Authorization code invalid or expired');
            return doc.codeChallenge;
        },

        async exchangeAuthorizationCode(client, authorizationCode, _codeVerifier, redirectUri) {
            // Single use: delete atomically so a replayed code cannot mint a second connection
            const AuthCodes = await o.stores.authCodes();
            const doc = await AuthCodes.findOneAndDelete({ code: authorizationCode, clientId: client.client_id }).lean();
            if (!doc || doc.expiresAt < new Date()) throw new Error('Authorization code invalid or expired');
            if (redirectUri && doc.redirectUri && redirectUri !== doc.redirectUri) throw new Error('redirect_uri mismatch');
            const Connections = await o.stores.connections();
            const connection = new Connections({
                clientId: client.client_id,
                clientName: client.client_name,
                userId: doc.userId,
                companyId: doc.companyId,
                email: doc.email,
                refreshTokenHash: 'pending',
                scopes: doc.scopes,
                expiresAt: new Date(Date.now() + CONNECTION_TTL_DAYS * 86400000)
            });
            return issueTokens(connection);
        },

        async exchangeRefreshToken(client, refreshToken) {
            const Connections = await o.stores.connections();
            const connection = await Connections.findOne({ refreshTokenHash: sha256(refreshToken), clientId: client.client_id });
            if (!connection || connection.revokedAt || connection.expiresAt < new Date()) throw new Error('Refresh token invalid, expired or revoked');
            return issueTokens(connection);
        },

        async verifyAccessToken(token) {
            const payload = jwt.verify(token, o.jwtSecret(), { algorithms: ['HS256'], audience: 'mcp' });
            return {
                token,
                clientId: payload.cid,
                scopes: (payload.scope || SCOPES.join(' ')).split(' '),
                expiresAt: payload.exp,
                extra: { sub: payload.sub, co: payload.co, email: payload.email }
            };
        },

        async revokeToken(client, request) {
            const Connections = await o.stores.connections();
            await Connections.updateOne(
                { refreshTokenHash: sha256(request.token), clientId: client.client_id },
                { $set: { revokedAt: new Date() } }
            );
        }
    };

    return { provider, handleLogin, signAccessToken, SCOPES, ACCESS_TOKEN_TTL_SEC, escapeHtml };
}

module.exports = { createOAuth, escapeHtml, isAllowedRedirectUri, DEFAULT_LOGIN_PAGE };
