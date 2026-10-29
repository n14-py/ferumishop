'use strict';

const { normalizeText, guardCustomerReply, customerSafeText } = require('./text');

const STEP_WORDS = ['delivery propio', 'motobolt', 'transportadora', 'pagopar', 'transferencia', 'efectivo'];

function amountDigits(facts) {
    const found = String(facts || '').match(/\d{1,3}(?:\.\d{3})+/g) || [];
    return [...new Set(found.map((value) => value.replace(/\D/g, '')).filter((value) => value.length >= 4))];
}

function linksIn(facts) {
    return String(facts || '').match(/https?:\/\/\S+/g) || [];
}

function aliasesIn(facts) {
    return String(facts || '').match(/\b[a-z0-9]+(?:[.\-][a-z0-9]+)+\b/gi) || [];
}

function wordsIn(facts) {
    const plain = normalizeText(facts);
    return STEP_WORDS.filter((word) => plain.includes(word));
}

function missingBits(facts, text) {
    const spoken = String(text || '');
    const spokenDigits = spoken.replace(/\D/g, '');
    const spokenPlain = normalizeText(spoken);
    const missing = [];
    for (const amount of amountDigits(facts)) {
        if (!spokenDigits.includes(amount)) missing.push(amount.replace(/\B(?=(\d{3})+(?!\d))/g, '.'));
    }
    for (const link of linksIn(facts)) {
        if (!spoken.includes(link)) missing.push(link);
    }
    for (const alias of aliasesIn(facts)) {
        if (!spoken.toLowerCase().includes(alias.toLowerCase())) missing.push(alias);
    }
    for (const word of wordsIn(facts)) {
        if (!spokenPlain.includes(word)) missing.push(word);
    }
    return missing;
}

function leaksPrivate(text) {
    return /maps\.google|google\.com\/maps|(?:^|\s)-?\d{1,2}\.\d{4,}/.test(String(text || ''));
}

function sameScript(facts, text) {
    const left = normalizeText(facts).replace(/[^a-z0-9]+/g, ' ').trim();
    const right = normalizeText(text).replace(/[^a-z0-9]+/g, ' ').trim();
    return Boolean(left) && left === right;
}

function polish(text, paymentConfirmed) {
    const safe = customerSafeText(guardCustomerReply(text, {
        paymentConfirmed: Boolean(paymentConfirmed),
        maxDiscount: 0,
        motoboltDispatched: false
    }));
    return String(safe || '').trim();
}

function persona(options) {
    const name = String(options.customerName || '').trim();
    const lines = [
        'Sos la persona que atiende Ferumi Shop por WhatsApp. No sos un menú ni un contestador.',
        'Hablá de vos, en español de Paraguay, cálida y concreta. Una sola respuesta, en prosa.',
        'Si la clienta hizo una pregunta, contestala primero con los datos de abajo. Después seguí el pedido.',
        'El pedido va así: saludo y, si quiere pedir, el nombre; qué quiere y le mostrás ese producto; formas de envío; métodos de pago; recién ahí los datos.',
        'No inventes precios, stock, alias ni horarios. No menciones coordenadas, kilómetros, pins ni links de mapas.',
        'No ofrezcas otros productos. No uses viñetas ni títulos.',
        '',
        'Datos de este paso, dichos con tus palabras:',
        String(options.facts || '').trim()
    ];
    if (options.askName && !name) {
        lines.push('Todavía no sabés su nombre. Si está pidiendo, pedile el nombre en la misma respuesta, sin frenar lo demás.');
    } else if (name) {
        lines.push(`Ya se llama ${name}. No vuelvas a pedir el nombre.`);
    }
    if (options.paymentConfirmed) lines.push('La transferencia YA está confirmada. No digas que falta confirmarla.');
    else lines.push('No digas que el pago está confirmado.');
    return lines.join('\n');
}

function historyMessages(history) {
    return (history || []).slice(-8).map((item) => ({
        role: item.role === 'assistant' ? 'assistant' : 'user',
        content: String(item.content || '').slice(0, 500)
    })).filter((item) => item.content);
}

async function defaultChat(messages) {
    const deepinfra = require('../deepinfra');
    if (!deepinfra.config().ok) return '';
    const json = await deepinfra.chat({ messages, temperature: 0.75, maxTokens: 420 });
    return String(deepinfra.assistantMessage(json).content || '').trim();
}

async function speakTurn(options = {}) {
    const facts = String(options.facts || '').trim();
    if (!facts) return { text: '', spoken: false, missing: [] };
    const chat = options.chat || defaultChat;
    const messages = [
        { role: 'system', content: persona(options) },
        ...historyMessages(options.history),
        { role: 'user', content: String(options.text || 'Seguimos con el pedido.').slice(0, 500) }
    ];
    let spoken = '';
    try {
        spoken = polish(await chat(messages), options.paymentConfirmed);
    } catch (err) {
        spoken = '';
    }
    let missing = missingBits(facts, spoken);
    const copied = sameScript(facts, spoken);
    if (spoken && !leaksPrivate(spoken) && !missing.length && !copied) return { text: spoken, spoken: true, missing };
    try {
        const retry = messages.concat([
            { role: 'assistant', content: spoken || 'Dame un segundo.' },
            { role: 'user', content: `No copies el texto. Decilo como en una conversación, en un solo mensaje, e incluí estos datos tal cual: ${missing.concat(copied ? ['dicho con tus palabras'] : []).concat(leaksPrivate(spoken) ? ['sin coordenadas ni mapas'] : []).join(', ') || 'los datos del paso'}.` }
        ]);
        spoken = polish(await chat(retry), options.paymentConfirmed);
    } catch (err) {
        spoken = '';
    }
    missing = missingBits(facts, spoken);
    if (!spoken || leaksPrivate(spoken) || missing.length || sameScript(facts, spoken)) return { text: facts, spoken: false, missing };
    return { text: spoken, spoken: true, missing };
}

module.exports = {
    amountDigits,
    missingBits,
    leaksPrivate,
    sameScript,
    speakTurn
};
