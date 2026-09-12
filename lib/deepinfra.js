'use strict';

function config() {
    const apiKey = String(process.env.DEEPINFRA_API_KEY || process.env.DEEPINFRA_TOKEN || '').trim();
    const model = String(process.env.DEEPINFRA_MODEL || 'deepseek-ai/DeepSeek-V3.2').trim();
    return {
        apiKey,
        model,
        url: 'https://api.deepinfra.com/v1/openai/chat/completions',
        ok: Boolean(apiKey)
    };
}

async function chat({ messages, tools, temperature = 0.65, maxTokens = 1200 }) {
    const cfg = config();
    if (!cfg.ok) throw new Error('Falta DEEPINFRA_API_KEY en el servidor.');

    const payload = {
        model: cfg.model,
        messages,
        temperature,
        max_tokens: maxTokens
    };
    if (tools && tools.length) {
        payload.tools = tools;
        payload.tool_choice = 'auto';
    }

    const response = await fetch(cfg.url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${cfg.apiKey}`
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(60000)
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
        const msg = json?.error?.message || json?.detail || `DeepInfra ${response.status}`;
        const err = new Error(msg);
        err.payload = json;
        throw err;
    }
    return json;
}

function assistantMessage(json) {
    return json?.choices?.[0]?.message || { role: 'assistant', content: '' };
}

module.exports = {
    config,
    chat,
    assistantMessage
};
