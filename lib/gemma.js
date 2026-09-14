'use strict';

/**
 * Cliente Gemma 4 via Gemini REST.
 * gemma-4-31b-it suele devolver 500 "Internal error encountered" (falla de Google,
 * sobre todo con prompts largos). Reintenta y cae a gemma-4-26b-a4b-it.
 * Si Google no responde, usa DeepInfra (DeepSeek) si hay DEEPINFRA_API_KEY.
 */

const RAW_KEYS = [
    process.env.GEMINI_API_KEY,
    process.env.GEMINI_API_KEY_2,
    process.env.GEMINI_API_KEY_3,
    process.env.GEMINI_API_KEY_4,
    process.env.GEMINI_API_KEY_5
];

const DEFAULT_MODELS = ['gemma-4-26b-a4b-it', 'gemma-4-31b-it'];

function listedKeys() {
    return RAW_KEYS.filter((key) => key && String(key).trim().length > 10).map((k) => String(k).trim());
}

function normalizeModel(name) {
    return String(name || '').trim().replace(/^models\//, '');
}

function listedModels() {
    const preferred = normalizeModel(process.env.GEMMA_MODEL);
    const all = [preferred, ...DEFAULT_MODELS].filter(Boolean);
    return [...new Set(all)];
}

let currentKeyIndex = 0;

function config() {
    const keys = listedKeys();
    const models = listedModels();
    return {
        ok: keys.length > 0,
        keys,
        model: models[0] || DEFAULT_MODELS[0],
        models,
        keyCount: keys.length
    };
}

function rotateKey() {
    const cfg = config();
    if (cfg.keys.length <= 1) return;
    currentKeyIndex = (currentKeyIndex + 1) % cfg.keys.length;
    console.log(`[Gemma] Cambiando a API Key #${currentKeyIndex + 1} por límite de cuota.`);
}

function errorText(error) {
    if (!error) return '';
    const payloadMsg = error.payload?.error?.message || error.payload?.message || '';
    return `${error.message || ''} ${payloadMsg} ${error.status || ''}`.trim();
}

function isRetryableError(error) {
    const msg = errorText(error);
    const status = Number(error?.status) || 0;
    return status === 429
        || status === 500
        || status === 503
        || status === 502
        || /Internal error/i.test(msg)
        || /INTERNAL/i.test(msg)
        || /Quota exceeded/i.test(msg)
        || /Resource has been exhausted/i.test(msg)
        || /UNAVAILABLE/i.test(msg)
        || /overloaded/i.test(msg);
}

function isQuotaError(error) {
    const msg = errorText(error);
    const status = Number(error?.status) || 0;
    return status === 429
        || /Quota exceeded/i.test(msg)
        || /Resource has been exhausted/i.test(msg)
        || /API key not valid/i.test(msg);
}

function thinkingNotSupported(error) {
    const msg = errorText(error);
    return /thinking/i.test(msg) || (Number(error?.status) === 400 && /generationConfig/i.test(msg));
}

function textFromRest(json) {
    const parts = json?.candidates?.[0]?.content?.parts;
    if (!Array.isArray(parts)) return '';
    return parts.map((p) => p.text || '').join('');
}

function restBody(prompt, { thinking = true } = {}) {
    const generationConfig = {
        temperature: 0.55,
        maxOutputTokens: 4096
    };
    if (thinking) {
        generationConfig.thinkingConfig = { thinkingLevel: 'minimal' };
    }
    return {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig
    };
}

async function generateContentRest(prompt, apiKey, model, options = {}) {
    const name = normalizeModel(model);
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(name)}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(restBody(prompt, options)),
        signal: AbortSignal.timeout(90000)
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
        const msg = json?.error?.message || `Gemma REST ${response.status}`;
        const err = new Error(msg);
        err.status = response.status;
        err.payload = json;
        err.model = name;
        throw err;
    }
    const text = textFromRest(json);
    if (!text) {
        const err = new Error('Gemma REST no devolvió texto.');
        err.payload = json;
        err.model = name;
        throw err;
    }
    return text;
}

async function sleep(ms) {
    await new Promise((resolve) => setTimeout(resolve, ms));
}

async function generateContentDeepInfra(prompt) {
    const deepinfra = require('./deepinfra');
    const cfg = deepinfra.config();
    if (!cfg.ok) {
        const err = new Error('Falta DEEPINFRA_API_KEY para el respaldo.');
        err.status = 0;
        throw err;
    }
    console.log(`[Gemma] Google falló. Probando DeepInfra (${cfg.model})...`);
    const json = await deepinfra.chat({
        messages: [
            { role: 'system', content: 'Respondé ÚNICAMENTE un JSON válido. Sin markdown, sin texto extra.' },
            { role: 'user', content: prompt }
        ],
        temperature: 0.5,
        maxTokens: 4000
    });
    const text = String(deepinfra.assistantMessage(json).content || '').trim();
    if (!text) throw new Error('DeepInfra no devolvió texto.');
    return text;
}

async function generateContentWithRetry(prompt) {
    const cfg = config();
    if (!cfg.ok) throw new Error('Falta GEMINI_API_KEY en el .env (Gemma).');

    const tried = [];
    let lastError = null;

    for (const model of cfg.models) {
        for (let attempt = 0; attempt < 2; attempt++) {
            const apiKey = cfg.keys[currentKeyIndex % cfg.keys.length];
            const thinking = attempt === 0;
            try {
                console.log(`[Gemma] Llamando ${model}${thinking ? '' : ' (sin thinking)'}...`);
                const text = await generateContentRest(prompt, apiKey, model, { thinking });
                return text;
            } catch (error) {
                lastError = error;
                error.model = model;
                tried.push(`${model}${thinking ? '' : '/no-thinking'}: ${error.message}`);
                console.warn(`[Gemma] ${model} falló: ${String(error.message).slice(0, 120)}`);

                if (thinking && thinkingNotSupported(error)) continue;
                if (isQuotaError(error) && cfg.keys.length > 1) {
                    rotateKey();
                    continue;
                }
                if (isRetryableError(error) && attempt === 0) {
                    await sleep(700);
                    continue;
                }
                break;
            }
        }
    }

    try {
        return await generateContentDeepInfra(prompt);
    } catch (deepError) {
        if (!/Falta DEEPINFRA/i.test(String(deepError.message || ''))) {
            lastError = deepError;
            tried.push(`deepinfra: ${deepError.message}`);
        }
    }

    const err = lastError || new Error('Gemma no devolvió texto.');
    err.tried = tried;
    if (/Internal error/i.test(err.message || '')) {
        err.message = `Google devolvió 500 Internal error en ${err.model || cfg.model} (falla conocida de Gemma 4 31B con prompts largos). Probé: ${tried.join(' | ')}`;
    }
    throw err;
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
    DEFAULT_MODELS,
    config,
    listedModels,
    listedKeys,
    isRetryableError,
    isQuotaError,
    restBody,
    generateContentRest,
    generateContentWithRetry,
    extractJsonObject,
    rotateKey
};
