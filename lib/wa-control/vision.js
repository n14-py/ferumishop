'use strict';

const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/webp']);
const MAX_BYTES = 5 * 1024 * 1024;

function visionStatus() {
    const enabled = String(process.env.WA_VISION_ENABLED || '').trim().toLowerCase() === 'true';
    const model = String(process.env.WA_VISION_MODEL || '').trim();
    const hasKey = Boolean(String(process.env.GEMINI_API_KEY || '').trim());
    if (!enabled) {
        return {
            available: false,
            reason: 'La búsqueda por foto está apagada. Para activarla hace falta WA_VISION_ENABLED=true, GEMINI_API_KEY y WA_VISION_MODEL de un modelo con visión.'
        };
    }
    if (!hasKey) return { available: false, reason: 'Falta GEMINI_API_KEY. No puedo analizar la foto.' };
    if (!model) return { available: false, reason: 'Falta WA_VISION_MODEL. No uso el modelo de texto como si viera imágenes.' };
    return { available: true, model, reason: '' };
}

function validateInboundImage({ mime, size }) {
    const type = String(mime || '').toLowerCase().split(';')[0].trim();
    if (!ALLOWED_MIME.has(type)) return { ok: false, reason: 'tipo_no_permitido' };
    if (!Number.isFinite(size) || size <= 0 || size > MAX_BYTES) return { ok: false, reason: 'tamano_no_permitido' };
    return { ok: true, mime: type };
}

function tokens(value) {
    return String(value || '')
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .split(/[^a-z0-9]+/)
        .filter((token) => token.length > 2);
}

function scoreProduct(description, product) {
    const described = new Set(tokens(description));
    const haystack = tokens([product.name, product.description, ...(product.variants || []).map((variant) => variant.name)].join(' '));
    if (!described.size || !haystack.length) return 0;
    let hits = 0;
    for (const token of haystack) if (described.has(token)) hits += 1;
    return hits / Math.max(haystack.length, 1);
}

function matchCatalogByDescription(description, products) {
    const ranked = (products || [])
        .map((product) => ({ product, score: scoreProduct(description, product) }))
        .filter((item) => item.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, 5);
    return ranked.map((item) => {
        const name = String(item.product.name || '').trim().toLowerCase();
        const described = String(description || '').trim().toLowerCase();
        let confidence = 'aproximada';
        if (name && described === name) confidence = 'exacta';
        else if (item.score >= 0.72) confidence = 'probable';
        return {
            id: String(item.product.id || item.product._id || ''),
            name: item.product.name,
            price: item.product.price,
            stock: item.product.stock,
            score: Math.round(item.score * 100) / 100,
            confidence,
            photos: item.product.photos || []
        };
    });
}

function imagePurpose({ text, shipping, cart }) {
    const raw = String(text || '').toLowerCase();
    if (/casa|fachada|porton|portón|referencia de la casa/.test(raw)) return 'house';
    if (/parecid|igual|producto|venden|tienen|busco|esto/.test(raw)) return 'catalog';
    if (!shipping?.method && !shipping?.lat && !(cart || []).length) return 'catalog';
    if (shipping?.method) return 'house';
    return 'catalog';
}

async function describeProductImage({ buffer, mime, fetchImpl = fetch }) {
    const status = visionStatus();
    if (!status.available) return { available: false, reason: status.reason };
    const check = validateInboundImage({ mime, size: buffer?.length || 0 });
    if (!check.ok) return { available: false, reason: check.reason };
    const key = String(process.env.GEMINI_API_KEY || '').trim();
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(status.model)}:generateContent?key=${encodeURIComponent(key)}`;
    const response = await fetchImpl(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{
                parts: [
                    { text: 'Describí solo el producto visible. Respondé JSON con nombre, tipo, colores y texto_visible. No afirmes que una tienda lo vende.' },
                    { inline_data: { mime_type: check.mime, data: Buffer.from(buffer).toString('base64') } }
                ]
            }]
        }),
        signal: AbortSignal.timeout(20000)
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
        const error = new Error(json?.error?.message || 'El modelo de visión no respondió.');
        error.status = response.status;
        throw error;
    }
    const text = (json?.candidates?.[0]?.content?.parts || []).map((part) => part.text || '').join('');
    return { available: true, text, model: status.model };
}

module.exports = {
    ALLOWED_MIME,
    MAX_BYTES,
    visionStatus,
    validateInboundImage,
    matchCatalogByDescription,
    imagePurpose,
    describeProductImage
};
