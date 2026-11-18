// Session mode: the app signs its staff in by itself (no passwords here).
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const express = require('express');
const request = require('supertest');
const { createMcpCore } = require('..');
const { memModel } = require('./memModel');

process.env.JWT_SECRET = 'test-secret';
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const b64url = b => b.toString('base64url');

function build() {
    const stores = { clients: memModel(), authCodes: memModel(), connections: memModel(), audit: memModel() };
    const people = {
        u1: { userId: 'u1', companyId: 'c1', email: 'ana@test.com', name: 'Ana <Prueba>', canUseAgentes: true, deactivated: false, tokenVersion: 3 },
        u2: { userId: 'u2', companyId: 'c1', email: 'bob@test.com', name: 'Bob', canUseAgentes: false, deactivated: false, tokenVersion: 0 }
    };
    const core = createMcpCore({
        issuerUrl: () => 'http://localhost:3998',
        scopes: ['test:use'],
        accessPermission: 'agent',
        checkConnection: true,
        stores: {
            clients: async () => stores.clients, authCodes: async () => stores.authCodes,
            connections: async () => stores.connections, auditLog: async () => stores.audit
        },
        // the "app session" is a header in these tests
        sessionLogin: {
            currentPrincipal: async req => {
                const id = req.get('x-session');
                if (!id) return null;
                if (id === 'broken') return { error: 'Algo pasó con tu cuenta.' };
                return people[id] ? { ...people[id] } : null;
            },
            loginUrl: back => `/auth/login?next=${encodeURIComponent(back)}`
        },
        loadPrincipal: async (userId, companyId) => (people[userId] && people[userId].companyId === companyId ? { ...people[userId] } : null),
        loginPage: { heading: 'Acceso de agentes a Test' },
        server: { name: 'testapp', version: '1.0.0', instructions: 'test' },
        tools: {
            definitions: [
                { name: 'leer', description: 'lee', inputSchema: { type: 'object', properties: {} } },
                { name: 'escribir', description: 'escribe', inputSchema: { type: 'object', properties: {} },
                    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false } }
            ],
            execute: async name => ({ ok: name })
        }
    });
    const app = express();
    app.use(express.json());
    app.use(core.oauthRouter());
    app.use('/mcp', core.mcpRouter());
    // eslint-disable-next-line no-unused-vars
    app.use((err, req, res, next) => res.status(err.status || 500).json({ error: err.message }));
    return { app, core, stores, people };
}

async function register(app) {
    const reg = await request(app).post('/register').send({ client_name: 'Claude <x>', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' });
    assert.equal(reg.status, 201);
    return reg.body;
}
function pkce() {
    const verifier = b64url(crypto.randomBytes(32));
    return { verifier, challenge: b64url(crypto.createHash('sha256').update(verifier).digest()) };
}
const authorizeQuery = (client, challenge) => ({ response_type: 'code', client_id: client.client_id, redirect_uri: REDIRECT,
    code_challenge: challenge, code_challenge_method: 'S256', state: 'st-1', scope: 'test:use' });
const formOf = html => Object.fromEntries([...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)]
    .map(m => [m[1], m[2].replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>')]));

test('createMcpCore needs exactly one of authenticate or sessionLogin', () => {
    const base = { issuerUrl: () => 'x', stores: {}, loadPrincipal: async () => null, tools: { definitions: [], execute: async () => null }, server: { name: 'a' } };
    assert.throws(() => createMcpCore(base), /exactly one/);
    assert.throws(() => createMcpCore({ ...base, authenticate: async () => ({}), sessionLogin: { currentPrincipal() {}, loginUrl() {} } }), /exactly one/);
    assert.throws(() => createMcpCore({ ...base, sessionLogin: {} }), /currentPrincipal/);
});

test('no session → app sign-in that comes back to the same authorization; no permission → message, no form', async () => {
    const { app } = build();
    const client = await register(app);
    const { challenge } = pkce();
    let r = await request(app).get('/authorize').query(authorizeQuery(client, challenge));
    assert.equal(r.status, 302);
    const loc = new URL(r.headers.location, 'http://localhost:3998');
    assert.equal(loc.pathname, '/auth/login');
    const back = new URL(loc.searchParams.get('next'), 'http://localhost:3998');
    assert.equal(back.pathname, '/authorize');
    for (const [k, v] of Object.entries(authorizeQuery(client, challenge))) assert.equal(back.searchParams.get(k), v, k);

    r = await request(app).get('/authorize').query(authorizeQuery(client, challenge)).set('x-session', 'u2');
    assert.equal(r.status, 403);
    assert.match(r.text, /Pídeselo a un administrador/);
    assert.doesNotMatch(r.text, /<form/);
    r = await request(app).get('/authorize').query(authorizeQuery(client, challenge)).set('x-session', 'broken');
    assert.equal(r.status, 403);
    assert.match(r.text, /Algo pasó/);
    // no password form in session mode
    assert.equal((await request(app).post('/oauth/login').type('form').send({ email: 'a', password: 'b' })).status, 404);
});

test('consent: page escapes, anti-forgery token is bound to person + request, deny returns access_denied', async () => {
    const { app } = build();
    const client = await register(app);
    const { challenge } = pkce();
    const page = await request(app).get('/authorize').query(authorizeQuery(client, challenge)).set('x-session', 'u1');
    assert.equal(page.status, 200);
    assert.match(page.text, /Claude &lt;x&gt;/);
    assert.match(page.text, /Conectado como <strong>Ana &lt;Prueba&gt;<\/strong>/);
    assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.match(page.headers['content-security-policy'], /form-action 'self' https:\/\/claude\.ai/);
    const form = formOf(page.text);
    assert.ok(form.csrf);
    const consent = (body, who = 'u1') => request(app).post('/oauth/consent').type('form').set('x-session', who).send(body);

    // no session at POST time, someone else's session, a tampered request, a forged token
    assert.equal((await request(app).post('/oauth/consent').type('form').send({ ...form, decision: 'allow' })).status, 401);
    assert.equal((await consent({ ...form, decision: 'allow' }, 'u2')).status, 403);
    assert.equal((await consent({ ...form, state: 'otro', decision: 'allow' })).status, 400);
    assert.equal((await consent({ ...form, csrf: `${Date.now() + 60000}.forged`, decision: 'allow' })).status, 400);
    assert.equal((await consent({ ...form, redirect_uri: 'https://evil.example/cb', decision: 'allow' })).status, 400);
    const expired = `${Date.now() - 1}.${form.csrf.split('.')[1]}`;
    assert.equal((await consent({ ...form, csrf: expired, decision: 'allow' })).status, 400);

    let r = await consent({ ...form, decision: 'deny' });
    assert.equal(r.status, 302);
    let url = new URL(r.headers.location);
    assert.equal(url.origin + url.pathname, REDIRECT);
    assert.equal(url.searchParams.get('error'), 'access_denied');
    assert.equal(url.searchParams.get('state'), 'st-1');
    assert.equal(url.searchParams.get('code'), null);
});

test('full flow in session mode: consent → code → tokens; per call: permission, tokenVersion, revocation; write annotations kept', async () => {
    const { app, stores, people } = build();
    const client = await register(app);
    const { verifier, challenge } = pkce();
    const page = await request(app).get('/authorize').query(authorizeQuery(client, challenge)).set('x-session', 'u1');
    const r = await request(app).post('/oauth/consent').type('form').set('x-session', 'u1').send({ ...formOf(page.text), decision: 'allow' });
    assert.equal(r.status, 302);
    const code = new URL(r.headers.location).searchParams.get('code');
    assert.ok(code);
    const tok = await request(app).post('/token').type('form').send({ client_id: client.client_id, grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT });
    assert.equal(tok.status, 200);
    assert.equal(stores.connections.rows[0].tokenVersion, 3);
    const rpc = (method, params = {}) => request(app).post('/mcp').set('Accept', 'application/json, text/event-stream')
        .set('Authorization', `Bearer ${tok.body.access_token}`).send({ jsonrpc: '2.0', id: 1, method, params });
    const list = await rpc('tools/list');
    assert.equal(list.status, 200);
    const tools = Object.fromEntries(list.body.result.tools.map(t => [t.name, t.annotations]));
    assert.equal(tools.leer.readOnlyHint, true);
    assert.equal(tools.escribir.readOnlyHint, false);

    people.u1.canUseAgentes = false;
    assert.equal((await rpc('tools/list')).status, 403);
    people.u1.canUseAgentes = true;
    people.u1.tokenVersion = 4;                       // "cerrar sesión en todos los dispositivos"
    assert.equal((await rpc('tools/list')).status, 401);
    people.u1.tokenVersion = 3;
    assert.equal((await rpc('tools/list')).status, 200);
    stores.connections.rows[0].revokedAt = new Date();   // Revocar in the app
    assert.equal((await rpc('tools/list')).status, 401);
});
