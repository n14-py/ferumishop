'use strict';

const gemma = require('./gemma');
const deepinfra = require('./deepinfra');

const FIELDS = [
    'commercialTitle',
    'subtitle',
    'shortDescription',
    'description',
    'benefits',
    'features',
    'howToUse',
    'faqs',
    'tags',
    'keywords',
    'seoTitle',
    'seoDescription',
    'slug',
    'commercialText'
];

const BANNED = [
    { re: /certific/i, stem: /certific/i },
    { re: /hipoalerg/i, stem: /hipoalerg/i },
    { re: /dermatol/i, stem: /dermatol/i },
    { re: /cl[ií]nicamente/i, stem: /clinic/i },
    { re: /\bFDA\b/i, stem: /\bFDA\b/i },
    { re: /\bANMAT\b/i, stem: /\bANMAT\b/i },
    { re: /org[aá]nic/i, stem: /organ/i },
    { re: /vegano/i, stem: /vegano/i },
    { re: /cruelty/i, stem: /cruelty/i },
    { re: /laboratorio/i, stem: /laboratorio/i },
    { re: /registro sanitario/i, stem: /registro sanitario/i }
];

function providerReady() {
    return {
        gemma: gemma.config().ok,
        deepinfra: deepinfra.config().ok
    };
}

function clip(value, max) {
    return String(value || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

function sourceAllows(source, rule) {
    return rule.stem.test(source);
}

function cleanSentence(text, source) {
    const parts = String(text || '').split(/(?<=[.!?])\s+/);
    return parts.filter((sentence) => {
        return !BANNED.some((rule) => rule.re.test(sentence) && !sourceAllows(source, rule));
    }).join(' ').trim();
}

function cleanList(list, source) {
    return (Array.isArray(list) ? list : [])
        .map((item) => cleanSentence(item, source))
        .filter(Boolean)
        .slice(0, 12);
}

function slugify(text) {
    return String(text || '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 80);
}

function normalize(raw, wanted, source) {
    const data = raw && typeof raw === 'object' ? raw : {};
    const faqs = (Array.isArray(data.faqs) ? data.faqs : [])
        .map((faq) => ({
            question: cleanSentence(faq?.question || faq?.q || '', source).slice(0, 180),
            answer: cleanSentence(faq?.answer || faq?.a || '', source).slice(0, 500)
        }))
        .filter((faq) => faq.question && faq.answer)
        .slice(0, 6);
    const all = {
        commercialTitle: clip(cleanSentence(data.commercialTitle, source), 90),
        subtitle: clip(cleanSentence(data.subtitle, source), 140),
        shortDescription: clip(cleanSentence(data.shortDescription, source), 280),
        description: cleanSentence(data.description, source).slice(0, 1800),
        benefits: cleanList(data.benefits, source),
        features: cleanList(data.features, source),
        howToUse: cleanSentence(data.howToUse, source).slice(0, 800),
        faqs,
        tags: cleanList(data.tags, source).slice(0, 10),
        keywords: cleanList(data.keywords, source).slice(0, 12),
        seoTitle: clip(cleanSentence(data.seoTitle, source), 60),
        seoDescription: clip(cleanSentence(data.seoDescription, source), 155),
        slug: slugify(data.slug || data.commercialTitle || ''),
        commercialText: cleanSentence(data.commercialText, source).slice(0, 400)
    };
    const fields = {};
    for (const key of wanted) {
        if (all[key] != null && all[key] !== '' && !(Array.isArray(all[key]) && !all[key].length)) {
            fields[key] = all[key];
        }
    }
    return fields;
}

function buildPrompt({ name, notes, price, category, brand, wanted }) {
    return `Sos la redactora de FERUMI, marca paraguaya de pestañas, belleza y cosméticos.
Escribí en español de Paraguay, natural, comercial y concreto. Sin frases vacías, sin signos de exclamación en serie y sin repetir el nombre del producto en cada oración.

DATOS QUE SÍ PODÉS USAR (nada fuera de esto):
- Marca: ${brand || 'FERUMI'}
- Nombre: ${name || '(sin nombre)'}
- Categoría: ${category || '(sin categoría)'}
- Precio de referencia en guaraníes: ${price || '(no informado)'}
- Notas del administrador:
${notes || '(no hay notas adicionales)'}

REGLAS DURAS:
- No inventes ingredientes, materiales, medidas, colores, certificaciones, registros sanitarios, origen de fábrica, premios ni beneficios que no estén en las notas.
- Si un dato no está, omitilo. No lo completes con un lugar común.
- No digas que es hipoalergénico, dermatológico, orgánico, vegano o clínicamente probado salvo que las notas lo digan.
- El texto tiene que ayudar a entender el producto y a decidir la compra, con tono de marca, no de catálogo genérico.

Devolvé SOLO un JSON con estas claves: ${wanted.join(', ')}.
benefits, features, tags y keywords son arrays de strings.
faqs es un array de objetos { "question", "answer" }.
description es un párrafo o dos, en texto plano, sin HTML.
slug en minúsculas, con guiones, sin tildes.
seoTitle máximo 60 caracteres. seoDescription máximo 155.`;
}

async function fromGemma(prompt) {
    return gemma.generateJsonObjectWithRetry(prompt, { attempts: 2 });
}

async function fromDeepinfra(prompt) {
    const json = await deepinfra.chat({
        messages: [
            { role: 'system', content: 'Respondé únicamente con JSON válido.' },
            { role: 'user', content: prompt }
        ],
        temperature: 0.4,
        maxTokens: 1800
    });
    const content = json?.choices?.[0]?.message?.content || '';
    return gemma.extractJsonObject(content);
}

async function generate(input = {}) {
    const ready = providerReady();
    if (!ready.gemma && !ready.deepinfra) {
        const error = new Error('La IA de FERUMI no está configurada. Hace falta GEMINI_API_KEY o DEEPINFRA_API_KEY en el servidor.');
        error.status = 503;
        throw error;
    }
    const name = clip(input.name, 180);
    if (!name) {
        const error = new Error('Escribí al menos el nombre del producto.');
        error.status = 400;
        throw error;
    }
    const wanted = input.field && input.field !== 'all' && FIELDS.includes(input.field)
        ? [input.field]
        : FIELDS;
    const notes = clip(input.notes, 4000);
    const source = [name, input.category, input.brand, notes].filter(Boolean).join('\n');
    const prompt = buildPrompt({
        name,
        notes,
        price: input.price,
        category: clip(input.category, 80),
        brand: clip(input.brand, 80) || 'FERUMI',
        wanted
    });
    let raw;
    let engine = '';
    if (ready.gemma) {
        try {
            raw = await fromGemma(prompt);
            engine = 'gemma';
        } catch (err) {
            if (!ready.deepinfra) throw err;
            raw = await fromDeepinfra(prompt);
            engine = 'deepinfra';
        }
    } else {
        raw = await fromDeepinfra(prompt);
        engine = 'deepinfra';
    }
    return {
        engine,
        field: wanted.length === 1 ? wanted[0] : 'all',
        fields: normalize(raw, wanted, source)
    };
}

module.exports = {
    FIELDS,
    providerReady,
    generate,
    normalize,
    cleanSentence
};
