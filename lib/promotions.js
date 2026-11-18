'use strict';

function isLive(promo, now = new Date()) {
    if (!promo || promo.active === false) return false;
    const time = now.getTime();
    if (promo.startsAt && new Date(promo.startsAt).getTime() > time) return false;
    if (promo.endsAt && new Date(promo.endsAt).getTime() < time) return false;
    return true;
}

function liveList(list, now = new Date()) {
    return (list || [])
        .filter((promo) => isLive(promo, now))
        .sort((a, b) => {
            const featured = Number(Boolean(b.featured)) - Number(Boolean(a.featured));
            if (featured) return featured;
            return (Number(a.sortOrder) || 0) - (Number(b.sortOrder) || 0);
        });
}

function productIds(promo) {
    return (promo?.productIds || []).map((id) => String(id?._id || id));
}

function appliesTo(promo, product) {
    if (!promo || !product) return false;
    const ids = productIds(promo);
    if (!ids.length) return false;
    return ids.includes(String(product._id || product.id || ''));
}

function roundGs(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return 0;
    return Math.max(0, Math.round(number));
}

function priceFromPromo(base, promo, product) {
    const type = promo.discountType;
    const value = Number(promo.discountValue) || 0;
    if (type === 'percent' && value > 0) {
        const percent = Math.min(100, value);
        return roundGs(base * (1 - percent / 100));
    }
    if (type === 'amount' && value > 0) return roundGs(base - value);
    if (type === 'fixed_price') {
        const override = (promo.priceOverrides || []).find((row) => String(row.productId) === String(product._id || product.id));
        if (override && Number(override.price) > 0) return roundGs(override.price);
        if (value > 0) return roundGs(value);
    }
    return base;
}

function effectivePrice(product, promotions, now = new Date()) {
    const base = roundGs(product?.price);
    const candidates = [{ price: base, source: 'base' }];
    if (product?.isOnPromo && Number(product.promoPrice) > 0) {
        candidates.push({ price: roundGs(product.promoPrice), source: 'producto' });
    }
    for (const promo of liveList(promotions, now)) {
        if (!appliesTo(promo, product)) continue;
        const next = priceFromPromo(base, promo, product);
        if (next < base) candidates.push({ price: next, source: 'promocion', promo });
    }
    const best = candidates.reduce((win, item) => (item.price < win.price ? item : win));
    const onPromo = best.price < base;
    return {
        price: best.price,
        compareAt: onPromo ? base : null,
        onPromo,
        source: best.source,
        promoTitle: best.promo?.title || ''
    };
}

function decorate(product, promotions, now) {
    const pricing = effectivePrice(product, promotions, now);
    return {
        pricing,
        isNew: Boolean(product?.isNew),
        featured: Boolean(product?.isFeatured)
    };
}

module.exports = {
    isLive,
    liveList,
    appliesTo,
    effectivePrice,
    decorate,
    priceFromPromo
};
