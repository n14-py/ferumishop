'use strict';

const { normalizeText } = require('./text');

const STOPWORDS = new Set([
    'hola', 'buenas', 'buen', 'dia', 'dias', 'tarde', 'noche', 'quiero', 'queria', 'quisiera',
    'tienen', 'tenes', 'tiene', 'hay', 'precio', 'cuanto', 'sale', 'vale', 'para', 'por',
    'una', 'uno', 'unos', 'unas', 'del', 'las', 'los', 'con', 'sin', 'que', 'como', 'esto',
    'ese', 'esa', 'favor', 'porfa', 'gracias', 'busco', 'necesito', 'ver', 'foto', 'fotos'
]);

function stem(token) {
    let value = String(token || '');
    if (value.length > 4 && value.endsWith('es')) value = value.slice(0, -2);
    else if (value.length > 3 && value.endsWith('s')) value = value.slice(0, -1);
    return value;
}

function queryTokens(query) {
    return normalizeText(query)
        .split(/[^a-z0-9]+/)
        .map(stem)
        .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function productHaystack(product) {
    return normalizeText([
        product?.name,
        product?.description,
        product?.aiNotes,
        product?.aiUsage,
        product?.category?.name,
        ...(product?.variants || []).map((variant) => variant.name)
    ].filter(Boolean).join(' '));
}

function rankCatalog(products, query) {
    const tokens = queryTokens(query);
    if (!tokens.length) return [];
    return (products || [])
        .map((product) => {
            const hay = productHaystack(product);
            const name = normalizeText(product?.name);
            let score = 0;
            let hits = 0;
            for (const token of tokens) {
                if (!token) continue;
                if (hay.includes(token)) {
                    hits += 1;
                    score += name.includes(token) ? 5 : 2;
                }
            }
            if (!hits) return null;
            if (tokens.length > 1) score += hits * 2;
            return { product, score, hits };
        })
        .filter(Boolean)
        .sort((a, b) => b.score - a.score || String(a.product.name || '').localeCompare(String(b.product.name || '')))
        .map((item) => item.product);
}

function catalogReply(products) {
    const lines = (products || []).slice(0, 5).map((product) => {
        const stock = product.hasVariants
            ? (product.variants || []).reduce((sum, variant) => sum + (Number(variant.stock) || 0), 0)
            : (Number(product.stock) || 0);
        const price = Number(product.price) || 0;
        return `${product.name}: ${price.toLocaleString('es-PY')} Gs.${stock > 0 ? `, hay ${stock}` : ', ahora sin stock'}`;
    });
    if (!lines.length) return '';
    return `Sí, te cuento lo que encontré:\n${lines.join('\n')}\n¿Cuál te interesa?`;
}

function replyDeniesCatalog(text) {
    const plain = normalizeText(text);
    return /no (tenemos|tengo|hay|cuento con|vendo|manejo|trabajamos con|esta en el catalogo)|no venden|no vendemos|no lo tenemos|no las tenemos|no los tenemos/.test(plain);
}

module.exports = {
    queryTokens,
    rankCatalog,
    catalogReply,
    replyDeniesCatalog
};
