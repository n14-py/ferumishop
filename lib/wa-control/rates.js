'use strict';

const { normalizeText } = require('./text');

function levenshtein(a, b) {
    const s = String(a || '');
    const t = String(b || '');
    const rows = Array.from({ length: s.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= t.length; j += 1) rows[0][j] = j;
    for (let i = 1; i <= s.length; i += 1) {
        for (let j = 1; j <= t.length; j += 1) {
            const cost = s[i - 1] === t[j - 1] ? 0 : 1;
            rows[i][j] = Math.min(
                rows[i - 1][j] + 1,
                rows[i][j - 1] + 1,
                rows[i - 1][j - 1] + cost
            );
        }
    }
    return rows[s.length][t.length];
}

function placeNames(place) {
    return [place?.name, ...(place?.aliases || [])].map(normalizeText).filter(Boolean);
}

function resolvePlace(query, places) {
    const q = normalizeText(query);
    if (!q) return { status: 'missing' };
    const exact = (places || []).filter((place) => place.active !== false && placeNames(place).includes(q));
    if (exact.length === 1) return { status: 'exact', place: exact[0] };
    if (exact.length > 1) return { status: 'ambiguous', candidates: exact };
    if (q.length < 4) return { status: 'unknown' };
    const scored = (places || [])
        .filter((place) => place.active !== false)
        .map((place) => {
            const best = Math.min(...placeNames(place).map((name) => levenshtein(q, name)));
            return { place, distance: best };
        })
        .filter((item) => item.distance <= 2)
        .sort((a, b) => a.distance - b.distance);
    if (!scored.length) return { status: 'unknown' };
    if (scored.length > 1 && scored[0].distance === scored[1].distance) {
        return { status: 'ambiguous', candidates: scored.slice(0, 4).map((item) => item.place) };
    }
    return { status: 'fuzzy', place: scored[0].place, distance: scored[0].distance };
}

function specificity(rate) {
    if (rate.neighborhoodId || rate.neighborhood) return 4;
    if (rate.zoneId || rate.zone) return 3;
    if (rate.cityId || rate.city) return 2;
    if (rate.department) return 1;
    return 0;
}

function rateMatches(rate, input, now) {
    if (!rate || rate.active === false) return false;
    if (rate.method && input.method && rate.method !== input.method) return false;
    if (rate.startsAt && new Date(rate.startsAt) > now) return false;
    if (rate.endsAt && new Date(rate.endsAt) < now) return false;
    if (rate.city && input.city && normalizeText(rate.city) !== normalizeText(input.city)) return false;
    if (rate.zone && input.zone && normalizeText(rate.zone) !== normalizeText(input.zone)) return false;
    if (rate.neighborhood && input.neighborhood && normalizeText(rate.neighborhood) !== normalizeText(input.neighborhood)) return false;
    if ((rate.city || rate.zone || rate.neighborhood) && !input.city && !input.zone && !input.neighborhood) return false;
    return true;
}

function applyMoneyRules(rate, input) {
    const base = Number(rate.basePrice);
    let amount = Number.isFinite(base) ? base : null;
    const surcharges = (rate.surcharges || []).reduce((sum, item) => sum + (Number(item.amount) || 0), 0);
    let discount = 0;
    if (amount != null) amount += surcharges;
    const subtotal = Number(input.subtotal) || 0;
    if (amount != null && rate.freeFrom != null && subtotal >= Number(rate.freeFrom)) {
        discount = amount;
        amount = 0;
    }
    return {
        base: Number.isFinite(base) ? base : null,
        surcharges,
        discount,
        amount
    };
}

function quoteShipping(rates, input, now = new Date()) {
    const method = input?.method || '';
    if (!method) return { ok: false, available: false, reason: 'falta_modalidad', conflict: false };
    if (method === 'delivery_propio' && !input?.city && !input?.zone) {
        return { ok: false, available: false, reason: 'falta_destino', conflict: false };
    }
    const matched = (rates || []).filter((rate) => rateMatches(rate, input, now));
    if (!matched.length) {
        if (method === 'motobolt') {
            return {
                ok: true,
                available: input.far ? false : true,
                amount: input.far ? null : 0,
                priced: !input.far,
                reason: input.far ? 'motobolt_fuera_de_cobertura' : 'politica_motobolt_paga_al_conductor',
                policy: 'motobolt_driver_paid',
                eta: input.far ? null : 'Se coordina después del pago confirmado',
                ruleId: null,
                conflict: false,
                includedInOrder: !input.far
            };
        }
        if (method === 'retiro') {
            return {
                ok: true, available: true, amount: 0, priced: true, reason: 'retiro_sin_costo',
                policy: 'pickup', eta: 'Cuando el pedido esté listo', ruleId: null, conflict: false, includedInOrder: true
            };
        }
        if (method === 'transportadora') {
            return {
                ok: true, available: true, amount: 0, priced: false,
                reason: 'transportadora_sin_tarifa_cargada',
                policy: 'carrier_unpriced',
                eta: null, ruleId: null, conflict: false, includedInOrder: false
            };
        }
        return { ok: false, available: false, amount: null, priced: false, reason: 'sin_tarifa', conflict: false, ruleId: null };
    }
    const ranked = matched.map((rate) => ({ rate, score: specificity(rate) }));
    const bestScore = Math.max(...ranked.map((item) => item.score));
    const specific = ranked.filter((item) => item.score === bestScore).map((item) => item.rate);
    const bestPriority = Math.max(...specific.map((rate) => Number(rate.priority) || 0));
    const winners = specific.filter((rate) => (Number(rate.priority) || 0) === bestPriority);
    const priced = winners.map((rate) => applyMoneyRules(rate, input));
    const amounts = [...new Set(priced.map((item) => item.amount))];
    if (winners.length > 1 && amounts.length > 1) {
        return {
            ok: false,
            available: false,
            conflict: true,
            reason: 'conflicto_de_tarifas',
            rules: winners.map((rate) => ({ id: String(rate.id || rate._id || ''), name: rate.name || rate.city || rate.method, priority: rate.priority || 0 }))
        };
    }
    const winner = winners[0];
    const money = priced[0];
    return {
        ok: money.amount != null,
        available: winner.available !== false && money.amount != null,
        amount: money.amount,
        priced: money.amount != null,
        base: money.base,
        surcharges: money.surcharges,
        discount: money.discount,
        eta: winner.eta || '',
        reason: winner.name || 'tarifa_configurada',
        ruleId: String(winner.id || winner._id || ''),
        ruleName: winner.name || '',
        priority: Number(winner.priority) || 0,
        specificity: specificity(winner),
        conflict: false,
        includedInOrder: true,
        policy: 'configured_rate'
    };
}

module.exports = {
    levenshtein,
    resolvePlace,
    specificity,
    quoteShipping,
    rateMatches
};
