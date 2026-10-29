'use strict';

const BANKS = ['ueno', 'itau', 'itaú', 'continental', 'familiar', 'atlas', 'gnb', 'sudameris', 'bnf', 'vision', 'visión', 'interfisa', 'solar'];

function integerAmount(value) {
    if (value == null || value === '') return null;
    if (typeof value === 'number' && Number.isFinite(value)) {
        if (value > 0 && value < 1000 && !Number.isInteger(value)) return null;
        return value > 0 ? Math.round(value) : null;
    }
    const digits = String(value).replace(/[^\d]/g, '');
    const amount = parseInt(digits, 10);
    return Number.isFinite(amount) && amount > 0 ? amount : null;
}

function moneyFrom(text) {
    const source = String(text || '');
    const labeled = source.match(/(?:gs\.?|guaran[ií]es|monto|importe)\s*[:.]?\s*([\d][\d.]*(?:[.,]\d+)?)/i)
        || source.match(/\b([\d.]{4,})\s*(?:gs|guaran)/i);
    return labeled ? integerAmount(labeled[1]) : null;
}

function captureName(raw, labels) {
    const match = String(raw || '').match(new RegExp(`\\b(?:${labels})\\s*[:\\-]?\\s*([A-Za-zÁÉÍÓÚÑáéíóúñ][A-Za-zÁÉÍÓÚÑáéíóúñ .]{1,80})`, 'i'));
    if (!match) return '';
    return match[1]
        .split(/\b(?:monto|importe|banco|fecha|cuenta|destinatario|beneficiario|ordenante|remitente|emisor|origen|concepto|numero|nro|comprobante|transferencia|enviada|recibida|gs|guaranies)\b/i)[0]
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 80);
}

function parseTransferText(text) {
    const raw = String(text || '').replace(/\s+/g, ' ').trim();
    const bankHit = BANKS.find((name) => raw.toLowerCase().includes(name)) || '';
    const recipient = captureName(raw, 'destinatario|beneficiario|para');
    const sender = captureName(raw, 'ordenante|remitente|emisor|origen|de');
    const amount = moneyFrom(raw);
    return {
        isTransfer: Boolean(amount || bankHit || recipient || sender),
        amount,
        bank: bankHit ? bankHit[0].toUpperCase() + bankHit.slice(1) : '',
        recipientName: recipient,
        senderName: sender
    };
}

function visionConfigured() {
    const key = String(process.env.GEMINI_API_KEY || '').trim();
    const model = String(process.env.WA_VISION_MODEL || 'gemini-2.0-flash').trim();
    return { ok: Boolean(key), key, model };
}

function interpretReceiptVision(text) {
    const source = String(text || '').trim();
    const start = source.indexOf('{');
    const end = source.lastIndexOf('}');
    let data = {};
    let rawText = source;
    if (start >= 0 && end > start) {
        try {
            data = JSON.parse(source.slice(start, end + 1));
            const transcript = `${source.slice(0, start)} ${source.slice(end + 1)}`.replace(/\bJSON:\s*/gi, ' ').replace(/\s+/g, ' ').trim();
            rawText = transcript.length >= 15 ? transcript : source;
        } catch {
            data = {};
        }
    }
    const fromText = parseTransferText(rawText);
    const jsonAmount = integerAmount(data.monto);
    let amount = jsonAmount || fromText.amount;
    if (fromText.amount && jsonAmount && jsonAmount < 1000 && fromText.amount >= 1000) amount = fromText.amount;
    const parsed = {
        isTransfer: data.es_transferencia === true || Boolean(amount || data.banco || data.destinatario || data.emisor || fromText.bank || fromText.recipientName || fromText.senderName),
        amount: amount || null,
        bank: String(data.banco || fromText.bank || '').slice(0, 40),
        recipientName: String(data.destinatario || fromText.recipientName || '').slice(0, 80),
        senderName: String(data.emisor || fromText.senderName || '').slice(0, 80)
    };
    if (data.es_transferencia === false && !amount && !parsed.bank && !parsed.recipientName && !parsed.senderName) parsed.isTransfer = false;
    return { rawText: rawText.slice(0, 8000), parsed };
}

async function readReceiptImage(buffer, mime, fetchImpl = fetch) {
    const cfg = visionConfigured();
    if (!cfg.ok || !buffer) return { available: false, rawText: '', parsed: parseTransferText('') };
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(cfg.model)}:generateContent?key=${encodeURIComponent(cfg.key)}`;
    const response = await fetchImpl(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{
                parts: [
                    { text: 'Transcribí TODO el texto visible de esta imagen, línea por línea, sin resumir y sin omitir montos, nombres, bancos, fechas ni números. Después, en la última línea, escribí JSON: {"es_transferencia":true,"monto":0,"banco":"","destinatario":"","emisor":""}. El monto es un entero en guaraníes, sin puntos. Si un dato no está escrito, dejalo vacío. No inventes.' },
                    { inline_data: { mime_type: mime || 'image/jpeg', data: Buffer.from(buffer).toString('base64') } }
                ]
            }]
        }),
        signal: AbortSignal.timeout(20000)
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
        const error = new Error(json?.error?.message || 'No pude leer el comprobante.');
        error.status = response.status;
        throw error;
    }
    const text = (json?.candidates?.[0]?.content?.parts || []).map((part) => part.text || '').join('\n');
    const read = interpretReceiptVision(text);
    return { available: true, rawText: read.rawText, parsed: read.parsed };
}

function trashStillVisible(rejectedAt, now = new Date()) {
    if (!rejectedAt) return false;
    const age = now.getTime() - new Date(rejectedAt).getTime();
    return age >= 0 && age <= 30 * 24 * 60 * 60 * 1000;
}

module.exports = {
    parseTransferText,
    interpretReceiptVision,
    readReceiptImage,
    visionConfigured,
    trashStillVisible
};
