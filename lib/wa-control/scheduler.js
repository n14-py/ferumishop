'use strict';

const crypto = require('crypto');
const { controlModels } = require('./models');
const service = require('./service');

let timer = null;

async function tick() {
    const { WaJobLock } = controlModels();
    const owner = crypto.randomBytes(8).toString('hex');
    const now = new Date();
    const until = new Date(now.getTime() + 50000);
    let lock = null;
    try {
        lock = await WaJobLock.findOneAndUpdate(
            { name: 'maintenance', $or: [{ until: { $lt: now } }, { until: { $exists: false } }] },
            { $set: { name: 'maintenance', owner, until } },
            { upsert: true, new: true }
        );
    } catch (err) {
        if (err && err.code === 11000) return;
        throw err;
    }
    if (!lock || lock.owner !== owner) return;
    const result = await service.runMaintenance();
    console.log('[wa-control] mantenimiento', JSON.stringify(result));
}

function start() {
    if (timer) return Promise.resolve();
    timer = setInterval(() => {
        tick().catch((err) => console.error('[wa-control] mantenimiento', err.message));
    }, 60000);
    if (typeof timer.unref === 'function') timer.unref();
    return service.ensureDefaults()
        .then(() => tick())
        .catch((err) => console.error('[wa-control] inicio', err.message));
}

module.exports = { start, tick };
