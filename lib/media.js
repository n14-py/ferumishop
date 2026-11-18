'use strict';

function cdn(url, transform) {
    const value = String(url || '');
    if (!value || !transform || value.indexOf('/upload/') === -1) return value;
    return value.replace('/upload/', `/upload/${transform}/`);
}

function heroShots(products, limit = 3) {
    const shots = [];
    const seen = new Set();
    (products || []).forEach((product) => {
        if (shots.length >= limit || !product || !product.photos || !product.photos[0]) return;
        const photo = product.photos[0];
        if (seen.has(photo)) return;
        seen.add(photo);
        const key = product.slug || product._id;
        shots.push({
            src: cdn(photo, 'w_900,c_fill,g_auto,q_auto,f_auto'),
            alt: (product.photoAlts && product.photoAlts[0]) || product.commercialTitle || product.name || '',
            href: key ? `/producto/${key}` : '/tienda'
        });
    });
    return shots;
}

module.exports = { cdn, heroShots };
