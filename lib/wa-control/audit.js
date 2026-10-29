'use strict';

const { controlModels } = require('./models');
const { redactSecrets } = require('./text');

async function recordAudit(entry = {}) {
    try {
        const { WaAudit } = controlModels();
        await WaAudit.create({
            at: entry.at || new Date(),
            action: String(entry.action || 'evento').slice(0, 80),
            status: entry.status || 'ok',
            actor: String(entry.actor || 'sistema').slice(0, 120),
            orderId: entry.orderId ? String(entry.orderId) : '',
            waId: entry.waId ? String(entry.waId) : '',
            operationId: entry.operationId ? String(entry.operationId) : '',
            before: entry.before ? redactSecrets(entry.before) : undefined,
            after: entry.after ? redactSecrets(entry.after) : undefined,
            result: String(entry.result || '').slice(0, 500),
            error: String(entry.error || '').slice(0, 500),
            attempt: entry.attempt || 1
        });
    } catch (err) {
        console.error('[wa-audit] no se pudo guardar el evento:', err.message);
    }
}

module.exports = { recordAudit };
