'use strict';

function slugifyName(name) {
    const first = String(name || 'cliente').trim().split(/\s+/)[0] || 'cliente';
    const clean = first
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-z0-9]+/g, '')
        .slice(0, 18);
    return clean || 'cliente';
}

function localPhoneDigits(phone) {
    let p = String(phone || '').replace(/\D/g, '');
    if (p.startsWith('595')) p = '0' + p.slice(3);
    if (p.startsWith('9') && p.length === 9) p = '0' + p;
    return p;
}

function makeCheckoutSlug({ phone, name, suffix = '' } = {}) {
    return `${localPhoneDigits(phone)}${slugifyName(name)}pedido${suffix || ''}`;
}

function isPaySlug(slug) {
    return /^\d{6,15}[a-z0-9]+pedido[a-z0-9]*$/i.test(String(slug || ''));
}

function publicPayUrl(slug) {
    const base = String(process.env.BASE_URL || 'https://www.ferumi.shop').replace(/\/$/, '');
    return `${base}/${encodeURIComponent(slug)}`;
}

function publicTrackingUrl(ticketOrOrder) {
    const base = String(process.env.BASE_URL || 'https://www.ferumi.shop').replace(/\/$/, '');
    return `${base}/tracking?q=${encodeURIComponent(ticketOrOrder || '')}`;
}

module.exports = {
    slugifyName,
    localPhoneDigits,
    makeCheckoutSlug,
    isPaySlug,
    publicPayUrl,
    publicTrackingUrl
};
