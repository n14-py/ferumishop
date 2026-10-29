'use strict';

const { normalizeText } = require('./text');

const CATEGORIES = [
    'clima', 'delivery_suspendido', 'retraso', 'horario', 'inventario', 'pago',
    'producto_no_disponible', 'promocion', 'feriado', 'transportadora', 'whatsapp',
    'cierre', 'otra'
];

const SCOPES = [
    'new_conversations', 'new_orders', 'not_prepared', 'prepared_not_shipped',
    'all_pending', 'customers', 'zones'
];

function situationIsLive(situation, now = new Date()) {
    if (!situation || situation.status === 'cancelled' || situation.status === 'expired') return false;
    if (situation.status === 'draft') return false;
    if (situation.startsAt && new Date(situation.startsAt) > now) return false;
    if (situation.endsAt && new Date(situation.endsAt) < now) return false;
    return situation.status === 'active' || situation.status === 'scheduled';
}

function orderIsPrepared(order) {
    const logistics = order.logisticsStatus || '';
    const fulfillment = order.fulfillmentStatus || '';
    return ['listo_despacho', 'programado', 'despachado', 'en_camino', 'entregado'].includes(logistics)
        || ['preparado', 'esperando_motobolt', 'enviando', 'esperando_retiro', 'entregado'].includes(fulfillment);
}

function orderMatchesScope(order, situation) {
    if (!order || !situation) return false;
    if (order.fulfillmentStatus === 'entregado' || order.logisticsStatus === 'entregado') return false;
    if (order.fulfillmentStatus === 'cancelado' || order.status === 'cancelado' || order.logisticsStatus === 'cancelado') return false;
    const methods = situation.methods || [];
    if (methods.length && !methods.includes(order.shippingMethod)) return false;
    const cities = (situation.cities || []).map(normalizeText);
    if (cities.length && !cities.includes(normalizeText(order.shippingCity))) return false;
    const zones = (situation.zones || []).map(normalizeText);
    if (zones.length && !zones.includes(normalizeText(order.shippingZone || order.zone || ''))) return false;
    const customers = situation.customerWaIds || [];
    if (customers.length && !customers.includes(order.waFrom)) return false;
    const ids = (situation.orderIds || []).map(String);
    if (ids.length && !ids.includes(String(order.id || order._id || ''))) return false;
    const scope = situation.scope || 'all_pending';
    if (scope === 'customers') return customers.includes(order.waFrom);
    if (scope === 'zones') return zones.includes(normalizeText(order.shippingZone || order.shippingCity || ''));
    if (scope === 'new_orders' || scope === 'new_conversations') return false;
    if (scope === 'not_prepared') return !orderIsPrepared(order);
    if (scope === 'prepared_not_shipped') {
        return orderIsPrepared(order) && !['despachado', 'en_camino', 'entregado', 'enviando', 'esperando_motobolt'].includes(order.logisticsStatus || order.fulfillmentStatus);
    }
    return true;
}

function affectsNewOrder(situation, input) {
    if (!situationIsLive(situation, input.now || new Date())) return false;
    const scope = situation.scope || 'all_pending';
    if (!['new_orders', 'new_conversations', 'all_pending', 'zones'].includes(scope)) return false;
    if ((situation.methods || []).length && input.method && !situation.methods.includes(input.method)) return false;
    if ((situation.cities || []).length && input.city && !(situation.cities || []).map(normalizeText).includes(normalizeText(input.city))) return false;
    return true;
}

function situationConflicts(list, now = new Date()) {
    const live = (list || []).filter((item) => situationIsLive(item, now));
    const conflicts = [];
    for (let i = 0; i < live.length; i += 1) {
        for (let j = i + 1; j < live.length; j += 1) {
            const a = live[i];
            const b = live[j];
            const actionsA = new Set(a.authorizedActions || []);
            const actionsB = new Set(b.authorizedActions || []);
            const contradictory = (actionsA.has('suspend_delivery') && actionsB.has('force_dispatch'))
                || (actionsB.has('suspend_delivery') && actionsA.has('force_dispatch'))
                || (actionsA.has('close_store') && actionsB.has('normal_operations'));
            if (!contradictory) continue;
            if ((Number(a.priority) || 0) !== (Number(b.priority) || 0)) continue;
            conflicts.push({
                a: a.title || a.id,
                b: b.title || b.id,
                reason: 'misma prioridad y acciones contradictorias'
            });
        }
    }
    return conflicts;
}

function proposedDate(order, situation) {
    if (!orderMatchesScope(order, situation)) return null;
    if (!(situation.authorizedActions || []).includes('reschedule_next_day')) return null;
    const base = situation.rescheduleFor ? new Date(situation.rescheduleFor) : new Date();
    if (!situation.rescheduleFor) base.setDate(base.getDate() + 1);
    return base;
}

module.exports = {
    CATEGORIES,
    SCOPES,
    situationIsLive,
    orderMatchesScope,
    affectsNewOrder,
    situationConflicts,
    proposedDate,
    orderIsPrepared
};
