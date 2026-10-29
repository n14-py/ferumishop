'use strict';

function createGather({ delayMs = 10000, schedule = setTimeout, clear = clearTimeout } = {}) {
    const buckets = new Map();
    return {
        delayMs,
        push(key, item, flush) {
            const id = String(key || 'unknown');
            let bucket = buckets.get(id);
            if (!bucket) {
                bucket = { items: [] };
                buckets.set(id, bucket);
                bucket.timer = schedule(() => {
                    const items = bucket.items.slice();
                    buckets.delete(id);
                    try {
                        flush(items);
                    } catch (err) {
                        console.error('[whatsapp] tanda', err.message);
                    }
                }, delayMs);
            }
            bucket.items.push(item);
            return { waiting: bucket.items.length, delayMs };
        },
        cancel(key) {
            const bucket = buckets.get(String(key || ''));
            if (!bucket) return;
            clear(bucket.timer);
            buckets.delete(String(key || ''));
        }
    };
}

function mergeIncoming(items) {
    const list = (items || []).filter(Boolean);
    const last = list[list.length - 1] || {};
    const texts = [];
    let location = null;
    let imageId = '';
    const wamids = [];
    const claimedIds = [];
    for (const item of list) {
        if (item.wamid) wamids.push(item.wamid);
        if (item.claimedId) claimedIds.push(String(item.claimedId));
        if (item.location) location = item.location;
        if (item.imageId) imageId = item.imageId;
        const text = String(item.text || '').trim();
        if (!text || text === '[foto]' || text.startsWith('[Ubicación compartida')) continue;
        texts.push(text);
    }
    let type = last.type || 'text';
    if (imageId && location) type = 'mixed';
    else if (location) type = 'location';
    else if (imageId) type = 'image';
    return {
        ...last,
        text: [...new Set(texts)].join('\n').trim(),
        location,
        imageId,
        wamids,
        claimedIds,
        type
    };
}

module.exports = {
    createGather,
    mergeIncoming
};
