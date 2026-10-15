const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const express = require('express');
const request = require('supertest');
const { createMcpCore, ToolError } = require('..');
const { memModel } = require('./memModel');

process.env.JWT_SECRET = 'test-secret';


const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const b64url = b => b.toString('base64url');

function build({ checkConnection = false } = {}) {
    const stores = { clients: memModel(), authCodes: memModel(), connections: memModel(), audit: memModel() };
    const users = {
        'ana@test.com': { userId: 'u1', companyId: 'c1', password: 'secret123', name: 'Ana', canUseAgentes: true, deactivated: false, tokenVersion: 0, scope: 'all' },
        'bob@test.com': { userId: 'u2', companyId: 'c1', password: 'secret123', name: 'Bob', canUseAgentes: false, deactivated: false, tokenVersion: 0, scope: 'own' }
    };
    const byId = id => Object.values(users).find(u => u.userId === id);
    const calls = [];
    const core = createMcpCore({
        issuerUrl: () => 'http://localhost:3999',
        resourceName: 'TestApp',
        scopes: ['test:read'],
        accessPermission: 'useAgents',
        checkConnection,
        stores: {
            clients: async () => stores.clients,
            authCodes: async () => stores.authCodes,
            connections: async () => stores.connections,
            auditLog: async () => stores.audit
        },
        authenticate: async (email, password) => {
            const u = users[String(email).toLowerCase()];
            if (!u || u.password !== password) return { error: 'Correo o contraseña incorrectos.' };
            if (!u.canUseAgentes) return { error: 'La cuenta no tiene el permiso "agentes de IA".' };
            return { principal: { ...u, email } };
        },
        loadPrincipal: async (userId, companyId) => {
            const u = byId(userId);
            return u && u.companyId === companyId ? { ...u, email: Object.keys(users).find(e => users[e] === u) } : null;
        },
        loginPage: { heading: 'Acceso a <TestApp>' },
        server: { name: 'testapp', version: '1.0.0', instructions: 'test', rowCountKeys: ['items'], resources: [{ uri: 'test://ref', name: 'Ref', description: 'd', mimeType: 'text/plain', read: () => 'hello' }] },
        tools: {
            definitions: [
                { name: 'listar', title: 'Listar', description: 'lista', inputSchema: { type: 'object', properties: {} } },
                { name: 'fallar', title: 'Fallar', description: 'falla', inputSchema: { type: 'object', properties: {} } }
            ],
            execute: async (name, input, principal) => {
                calls.push({ name, input, principal });
                if (name === 'fallar') throw new ToolError('No puedes.');
                return { items: [1, 2, 3], scope: principal.scope };
            }
        }
    });
    const app = express();
    app.use(express.json());
    app.use(core.oauthRouter());
    app.use('/mcp', core.mcpRouter());
    app.get('/other', (req, res) => res.json({ ok: true }));
    // eslint-disable-next-line no-unused-vars
    app.use((err, req, res, next) => res.status(err.status || 500).json({ error: err.message }));
    return { app, core, stores, users, calls };
}

const rpc = (app, token, method, params = {}, id = 1) => {
    const r = request(app).post('/mcp').set('Accept', 'application/json, text/event-stream').send({ jsonrpc: '2.0', id, method, params });
    return token ? r.set('Authorization', `Bearer ${token}`) : r;
};
const tokenFor = (core, u, extra = {}) => core.signAccessToken({ userId: u.userId, companyId: u.companyId, email: 'x', clientId: 'test-client', scopes: ['test:read'], tokenVersion: 0, ...extra });

test('no token → 401 with resource metadata; wrong audience → 401; GET → 405', async () => {
    const { app } = build();
    const res = await rpc(app, null, 'tools/list');
    assert.equal(res.status, 401);
    assert.match(res.headers['www-authenticate'], /resource_metadata="http:\/\/localhost:3999\/\.well-known\/oauth-protected-resource\/mcp"/);
    const jwt = require('jsonwebtoken');
    const appToken = jwt.sign({ _id: 'u1', companyId: 'c1' }, 'test-secret');
    assert.equal((await rpc(app, appToken, 'tools/list')).status, 401);
    const get = await request(app).get('/mcp');
    assert.equal(get.status, 405);
    assert.equal(get.headers.allow, 'POST');
});

test('permission gate, deactivation, tokenVersion and foreign company are re-checked per call', async () => {
    const { app, core, users } = build();
    const ana = users['ana@test.com'];
    const bob = users['bob@test.com'];
    let res = await rpc(app, tokenFor(core, ana), 'tools/list');
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.result.tools.map(t => t.name), ['listar', 'fallar']);
    assert.ok(res.body.result.tools.every(t => t.annotations.readOnlyHint === true));
    res = await rpc(app, tokenFor(core, bob), 'tools/list');
    assert.equal(res.status, 403);
    assert.match(res.body.error, /useAgents/);
    ana.deactivated = true;
    assert.equal((await rpc(app, tokenFor(core, ana), 'tools/list')).status, 403);
    ana.deactivated = false;
    ana.tokenVersion = 1;
    assert.equal((await rpc(app, tokenFor(core, ana), 'tools/list')).status, 401);
    ana.tokenVersion = 0;
    assert.equal((await rpc(app, tokenFor(core, { ...ana, companyId: 'c9' }), 'tools/list')).status, 403);
});

test('tools/call scopes by principal, surfaces ToolError, hides other errors, audits every call', async () => {
    const { app, core, users, stores, calls } = build();
    const t = tokenFor(core, users['ana@test.com']);
    let res = await rpc(app, t, 'tools/call', { name: 'listar', arguments: { a: 1 } });
    assert.equal(res.status, 200);
    const out = JSON.parse(res.body.result.content[0].text);
    assert.deepEqual(out, { items: [1, 2, 3], scope: 'all' });
    assert.equal(calls[0].principal.userId, 'u1');
    res = await rpc(app, t, 'tools/call', { name: 'fallar', arguments: {} }, 2);
    assert.equal(res.body.result.isError, true);
    assert.equal(res.body.result.content[0].text, 'Error: No puedes.');
    res = await rpc(app, t, 'tools/call', { name: 'nope', arguments: {} }, 3);
    assert.match(res.body.result.content[0].text, /Herramienta desconocida/);
    await new Promise(r => setTimeout(r, 20));
    const rows = stores.audit.rows;
    assert.equal(rows.length, 3);
    assert.deepEqual(rows[0], { ...rows[0], userId: 'u1', tool: 'listar', ok: true, rowCount: 3, input: { a: 1 } });
    assert.equal(rows[1].ok, false);
    assert.equal(rows[1].error, 'No puedes.');
    const ref = await rpc(app, t, 'resources/read', { uri: 'test://ref' }, 4);
    assert.equal(ref.body.result.contents[0].text, 'hello');
});

test('rate limit is per user and CORS stays off the app routes', async () => {
    process.env.MCP_RATE_LIMIT_PER_MIN = '3';
    const { app, core, users } = build();
    delete process.env.MCP_RATE_LIMIT_PER_MIN;
    const ta = tokenFor(core, users['ana@test.com']);
    for (let i = 0; i < 3; i++) assert.equal((await rpc(app, ta, 'tools/list', {}, i + 1)).status, 200);
    const limited = await rpc(app, ta, 'tools/list', {}, 4);
    assert.equal(limited.status, 429);
    const meta = await request(app).get('/.well-known/oauth-authorization-server').set('Origin', 'https://claude.ai');
    assert.equal(meta.status, 200);
    assert.equal(meta.headers['access-control-allow-origin'], '*');
    assert.equal(meta.body.code_challenge_methods_supported[0], 'S256');
    assert.equal((await request(app).get('/.well-known/oauth-protected-resource')).status, 200);
    const other = await request(app).get('/other').set('Origin', 'https://evil.example');
    assert.equal(other.headers['access-control-allow-origin'], undefined);
});

test('full OAuth flow: register → login page → code → tokens → refresh → revoke (connection re-checked per call)', async () => {
    const { app, stores } = build({ checkConnection: true });
    const reg = await request(app).post('/register').send({ client_name: 'Cowork <x>', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' });
    assert.equal(reg.status, 201);
    const client = reg.body;
    const bad = await request(app).post('/register').send({ client_name: 'bad', redirect_uris: ['http://evil.example/cb'], token_endpoint_auth_method: 'none' });
    assert.ok(bad.status >= 400);

    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
    const page = await request(app).get('/authorize').query({ response_type: 'code', client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', scope: 'test:read' });
    assert.equal(page.status, 200);
    assert.match(page.text, /Cowork &lt;x&gt;/);
    assert.match(page.text, /Acceso a &lt;TestApp&gt;/);
    assert.match(page.headers['content-security-policy'], /form-action 'self' https:\/\/claude\.ai/);

    const login = body => request(app).post('/oauth/login').type('form').send({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, state: 'xyz', ...body });
    let res = await login({ email: 'ana@test.com', password: 'nope' });
    assert.equal(res.status, 400);
    assert.match(res.text, /incorrectos/);
    res = await login({ email: 'bob@test.com', password: 'secret123' });
    assert.match(res.text, /agentes de IA/);
    res = await login({ email: 'ana@test.com', password: 'secret123' });
    assert.equal(res.status, 302);
    const url = new URL(res.headers.location);
    assert.equal(url.searchParams.get('state'), 'xyz');
    const code = url.searchParams.get('code');

    const token = body => request(app).post('/token').type('form').send({ client_id: client.client_id, ...body });
    res = await token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT });
    assert.equal(res.status, 200);
    const { access_token, refresh_token } = res.body;
    assert.equal((await rpc(app, access_token, 'tools/list')).status, 200);
    // code is single use
    assert.ok((await token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT })).status >= 400);

    res = await token({ grant_type: 'refresh_token', refresh_token });
    assert.equal(res.status, 200);
    assert.notEqual(res.body.refresh_token, refresh_token);
    assert.ok((await token({ grant_type: 'refresh_token', refresh_token })).status >= 400, 'old refresh token rotated out');
    assert.equal(stores.connections.rows.length, 1);

    // revoking the connection from the app cuts the still-valid access token
    stores.connections.rows[0].revokedAt = new Date();
    assert.equal((await rpc(app, res.body.access_token, 'tools/list')).status, 401);
});
