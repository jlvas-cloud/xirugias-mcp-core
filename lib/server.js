/**
 * MCP server wrapper: one Server instance per request (stateless Streamable
 * HTTP), bound to the authenticated principal so every tool call is scoped
 * by the app's tool layer and written to the tenant's audit log.
 *
 * The app supplies `tools.definitions` (name, title, description,
 * inputSchema) and `tools.execute(name, input, principal)`; a thrown
 * `ToolError` is shown to the agent verbatim, anything else is hidden.
 */
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const {
    ListToolsRequestSchema,
    CallToolRequestSchema,
    ListResourcesRequestSchema,
    ReadResourceRequestSchema
} = require('@modelcontextprotocol/sdk/types.js');

class ToolError extends Error {}

// Every tool is a read: annotate it so clients (Claude Team/Cowork) can
// treat it as safe instead of gating each call behind a permission prompt.
const READ_ONLY_ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

function defaultRowCount(result, keys) {
    if (Array.isArray(result)) return result.length;
    if (result && typeof result === 'object') {
        for (const key of keys) {
            if (Array.isArray(result[key])) return result[key].length;
        }
        return 1;
    }
    return undefined;
}

/**
 * @param {object} o
 * @param {string} o.name  server name
 * @param {string} o.version
 * @param {string} o.instructions
 * @param {{definitions: object[], execute: Function}} o.tools
 * @param {Array<{uri, name, description, mimeType, read: () => string}>} [o.resources]
 * @param {(companyId) => Promise<Model>} o.auditLog
 * @param {number} [o.maxResultChars=60000]
 * @param {string[]} [o.rowCountKeys=[]]  result keys whose array length counts as rows
 * @param {Function} [o.isToolError]  extra predicate for errors safe to show
 * @param {(def, principal) => boolean} [o.toolVisible]  hide tools per principal
 */
function createMcpServerFactory(o) {
    const MAX_RESULT_CHARS = o.maxResultChars || 60000;
    const resources = o.resources || [];
    const rowCountKeys = o.rowCountKeys || [];
    const isToolError = err => err instanceof ToolError || (o.isToolError ? o.isToolError(err) : false);
    const visible = (def, principal) => (o.toolVisible ? o.toolVisible(def, principal) : true);

    function toMcpTool(def) {
        return { name: def.name, title: def.title || def.name, description: def.description, inputSchema: def.inputSchema, annotations: READ_ONLY_ANNOTATIONS };
    }

    function serialize(result) {
        const text = JSON.stringify(result, null, 1);
        if (text.length <= MAX_RESULT_CHARS) return text;
        return `${text.slice(0, MAX_RESULT_CHARS)}\n… [resultado truncado a ${MAX_RESULT_CHARS} caracteres; usa filtros o limit para acotar]`;
    }

    async function runTool(name, input, user) {
        const started = Date.now();
        let text;
        let ok = true;
        let error;
        let rowCount;
        try {
            const def = o.tools.definitions.find(d => d.name === name);
            if (!def || !visible(def, user)) throw new ToolError(`Herramienta desconocida: ${name}`);
            const result = await o.tools.execute(name, input, user);
            rowCount = defaultRowCount(result, rowCountKeys);
            text = serialize(result);
        } catch (err) {
            ok = false;
            error = isToolError(err) ? err.message : 'Error interno al ejecutar la herramienta';
            if (!isToolError(err)) console.error(`MCP tool ${name} failed:`, err);
            text = `Error: ${error}`;
        }
        const durationMs = Date.now() - started;
        Promise.resolve(o.auditLog(user.companyId))
            .then(AuditLog => AuditLog.create({
                userId: user.userId,
                email: user.email,
                client: user.clientId ? `${user.clientId} ${user.client}`.trim() : user.client,
                tool: name,
                input,
                ok,
                error,
                rowCount: ok ? rowCount : undefined,
                resultChars: text.length,
                durationMs
            }))
            .catch(err => console.error('MCP audit log failed:', err.message));
        return { content: [{ type: 'text', text }], isError: !ok };
    }

    function createMcpServer(user) {
        const server = new Server(
            { name: o.name, version: o.version },
            { capabilities: { tools: {}, resources: {} }, instructions: o.instructions }
        );

        server.setRequestHandler(ListToolsRequestSchema, async () => ({
            tools: o.tools.definitions.filter(d => visible(d, user)).map(toMcpTool)
        }));

        server.setRequestHandler(CallToolRequestSchema, async (req) => {
            const { name, arguments: args } = req.params;
            return runTool(name, args || {}, user);
        });

        server.setRequestHandler(ListResourcesRequestSchema, async () => ({
            resources: resources.map(({ uri, name, description, mimeType }) => ({ uri, name, description, mimeType }))
        }));

        server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
            const res = resources.find(r => r.uri === req.params.uri);
            if (!res) throw new Error(`Recurso desconocido: ${req.params.uri}`);
            return { contents: [{ uri: res.uri, mimeType: res.mimeType, text: res.read() }] };
        });

        return server;
    }

    return { createMcpServer, runTool };
}

module.exports = { createMcpServerFactory, ToolError, READ_ONLY_ANNOTATIONS };
