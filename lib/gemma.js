'use strict';

/**
 * Cliente Gemma rotativo, igual que lfaftechapi/utils/geminiClient.js:
 * modelo gemma-4-31b-it + varias GEMINI_API_KEY.
 */

const { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } = require('@google/generative-ai');

const RAW_KEYS = [
    process.env.GEMINI_API_KEY,
    process.env.GEMINI_API_KEY_2,
    process.env.GEMINI_API_KEY_3,
    process.env.GEMINI_API_KEY_4,
    process.env.GEMINI_API_KEY_5
];

function listedKeys() {
    return RAW_KEYS.filter((key) => key && String(key).trim().length > 10).map((k) => String(k).trim());
}

let currentKeyIndex = 0;

function config() {
    const keys = listedKeys();
    return {
        ok: keys.length > 0,
        keys,
        model: String(process.env.GEMMA_MODEL || 'gemma-4-31b-it').trim(),
        keyCount: keys.length
    };
}

const SAFETY = [
    { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE }
];

function getModel() {
    const cfg = config();
    if (!cfg.ok) throw new Error('Falta GEMINI_API_KEY en el servidor (Gemma).');
    const currentKey = cfg.keys[currentKeyIndex % cfg.keys.length];
    const genAI = new GoogleGenerativeAI(currentKey);
    return genAI.getGenerativeModel({
        model: cfg.model,
        safetySettings: SAFETY
    });
}

function rotateKey() {
    const cfg = config();
    if (cfg.keys.length <= 1) return;
    currentKeyIndex = (currentKeyIndex + 1) % cfg.keys.length;
    console.log(`[Gemma] Cambiando a API Key #${currentKeyIndex + 1} por límite de cuota.`);
}

function isQuotaError(error) {
    const msg = String(error?.message || error || '');
    return msg.includes('429')
        || msg.includes('Quota exceeded')
        || msg.includes('Resource has been exhausted')
        || msg.includes('API key not valid')
        || msg.includes('400');
}

function textFromRest(json) {
    const parts = json?.candidates?.[0]?.content?.parts;
    if (!Array.isArray(parts)) return '';
    return parts.map((p) => p.text || '').join('');
}

async function generateContentRest(prompt, apiKey, model) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{ role: 'user', parts: [{ text: prompt }] }]
        }),
        signal: AbortSignal.timeout(90000)
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
        const msg = json?.error?.message || `Gemma REST ${response.status}`;
        const err = new Error(msg);
        err.status = response.status;
        err.payload = json;
        throw err;
    }
    const text = textFromRest(json);
    if (!text) throw new Error('Gemma REST no devolvió texto.');
    return text;
}

async function generateContentWithRetry(prompt, retries = 0) {
    const cfg = config();
    if (!cfg.ok) throw new Error('Falta GEMINI_API_KEY en el servidor (Gemma).');

    try {
        const model = getModel();
        const result = await model.generateContent(prompt);
        const text = result?.response?.text?.() || '';
        if (text && text.trim()) return text;
        throw new Error('Gemma SDK devolvió texto vacío.');
    } catch (error) {
        try {
            const apiKey = cfg.keys[currentKeyIndex % cfg.keys.length];
            return await generateContentRest(prompt, apiKey, cfg.model);
        } catch (restError) {
            const err = restError.message ? restError : error;
            if (isQuotaError(err) && retries < cfg.keys.length) {
                console.warn(`[Gemma] Fallo en Key #${currentKeyIndex + 1}: ${String(err.message).slice(0, 80)}`);
                rotateKey();
                return generateContentWithRetry(prompt, retries + 1);
            }
            throw err;
        }
    }
}

function extractJsonObject(raw) {
    let jsonText = String(raw || '').replace(/```json/gi, '').replace(/```/g, '').trim();
    const inicio = jsonText.indexOf('{');
    const fin = jsonText.lastIndexOf('}');
    if (inicio === -1 || fin === -1 || fin <= inicio) {
        throw new Error('La IA no devolvió llaves de JSON válidas.');
    }
    return JSON.parse(jsonText.substring(inicio, fin + 1));
}

module.exports = {
    config,
    generateContentWithRetry,
    extractJsonObject,
    rotateKey
};
