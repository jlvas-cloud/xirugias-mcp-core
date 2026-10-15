/**
 * Mongoose schemas behind the MCP endpoint. Built with the host app's
 * mongoose (peer dependency) so the models live on the app's connections.
 *
 * The three OAuth schemas belong in a database shared by every tenant
 * because a client registers and a token is minted before any tenant is
 * known. The audit log is per tenant so a company only ever sees its own
 * agents' activity.
 */
const mongoose = require('mongoose');
const { Schema } = mongoose;

// Agents register themselves (dynamic client registration): Cowork,
// claude.ai, Claude Desktop, Codex... each get their own record.
const mcpOAuthClientSchema = new Schema({
    clientId: { type: String, required: true, unique: true },
    clientSecret: String,
    clientSecretExpiresAt: Number,
    clientName: String,
    redirectUris: { type: [String], default: [] },
    metadata: Schema.Types.Mixed
}, { timestamps: true });

// Short-lived, single-use, deleted on exchange; the TTL index sweeps the rest.
const mcpAuthCodeSchema = new Schema({
    code: { type: String, required: true, unique: true },
    clientId: { type: String, required: true },
    userId: { type: String, required: true },      // local (tenant) user _id
    companyId: { type: String, required: true },
    email: String,
    codeChallenge: { type: String, required: true },
    redirectUri: String,
    scopes: { type: [String], default: [] },
    resource: String,
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });

// One document per live agent <-> person connection. The refresh token is
// stored hashed; rotation replaces the hash on the same document so a
// connection can be listed and revoked as a unit.
const mcpConnectionSchema = new Schema({
    clientId: { type: String, required: true, index: true },
    clientName: String,
    userId: { type: String, required: true, index: true },
    companyId: { type: String, required: true, index: true },
    email: String,
    name: String,
    refreshTokenHash: { type: String, required: true, unique: true },
    scopes: { type: [String], default: [] },
    tokenVersion: { type: Number, default: 0 },   // user's tokenVersion when the connection was made
    expiresAt: { type: Date, required: true },
    revokedAt: Date,
    lastUsedAt: Date
}, { timestamps: true });

// One row per tool call. `input` keeps the arguments so a question that
// worked for one person can be found and reused by another.
const mcpAuditLogSchema = new Schema({
    userId: { type: String, index: true },
    email: String,
    client: String,
    tool: { type: String, index: true },
    input: Schema.Types.Mixed,
    ok: Boolean,
    error: String,
    rowCount: Number,
    resultChars: Number,
    durationMs: Number
}, { timestamps: { createdAt: true, updatedAt: false } });

mcpAuditLogSchema.index({ createdAt: -1 });

module.exports = { mcpOAuthClientSchema, mcpAuthCodeSchema, mcpConnectionSchema, mcpAuditLogSchema };
