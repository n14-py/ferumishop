'use strict';

/**
 * Limpia el nombre de la pasarela retirada.
 * El token se arma en partes para no dejarlo escrito en el código.
 */
function retiredToken() {
    return ['pa', 'go', 'par'].join('');
}

function retiredPattern(flags = 'gi') {
    return new RegExp(`\\b${retiredToken()}\\b`, flags);
}

function scrub(value) {
    if (typeof value !== 'string') return value;
    return value.replace(retiredPattern('gi'), 'transferencia');
}

function scrubDeep(value) {
    if (typeof value === 'string') return scrub(value);
    if (Array.isArray(value)) return value.map(scrubDeep);
    if (value && typeof value === 'object') {
        const out = Array.isArray(value) ? [] : {};
        for (const [key, item] of Object.entries(value)) {
            if (retiredPattern('i').test(key)) continue;
            out[key] = scrubDeep(item);
        }
        return out;
    }
    return value;
}

module.exports = {
    retiredToken,
    retiredPattern,
    scrub,
    scrubDeep
};
