'use strict';

const WEEKDAYS = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

function zonedParts(date, timeZone = 'America/Asuncion') {
    const fmt = new Intl.DateTimeFormat('en-US', {
        timeZone,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        weekday: 'short',
        hourCycle: 'h23'
    });
    const map = {};
    for (const part of fmt.formatToParts(date)) map[part.type] = part.value;
    return {
        year: Number(map.year),
        month: Number(map.month),
        day: Number(map.day),
        hour: Number(map.hour),
        minute: Number(map.minute),
        weekday: WEEKDAYS[map.weekday] ?? 0
    };
}

function parseClock(value, fallback = '18:00') {
    const match = String(value || fallback).match(/^(\d{1,2}):(\d{2})$/);
    if (!match) return { hour: 18, minute: 0 };
    return { hour: Math.min(23, Number(match[1])), minute: Math.min(59, Number(match[2])) };
}

function clockMinutes(parts) {
    return (parts.hour * 60) + parts.minute;
}

function isServiceDay(date, settings) {
    const days = settings?.serviceDays || [1, 2, 3, 4, 5, 6];
    return days.includes(zonedParts(date, settings?.timezone || 'America/Asuncion').weekday);
}

function afterCutoff(date, settings) {
    const tz = settings?.timezone || 'America/Asuncion';
    const parts = zonedParts(date, tz);
    const cutoff = parseClock(settings?.cutoffTime || settings?.departureTime || '18:00');
    return clockMinutes(parts) >= (cutoff.hour * 60 + cutoff.minute);
}

function addDays(date, days) {
    const next = new Date(date.getTime());
    next.setUTCDate(next.getUTCDate() + days);
    return next;
}

function nextServiceDate(from, settings) {
    let cursor = new Date(from.getTime());
    for (let i = 0; i < 14; i += 1) {
        if (isServiceDay(cursor, settings) && !afterCutoff(cursor, settings)) return cursor;
        cursor = addDays(cursor, 1);
        cursor.setUTCHours(12, 0, 0, 0);
    }
    return cursor;
}

const OPEN_FULFILLMENT = ['pagado', 'preparando', 'preparado'];
const CLOSED = ['entregado', 'cancelado', 'devuelto'];

function eligibleForDeparture(order, departure, settings = {}) {
    if (!order) return { ok: false, reason: 'sin_pedido' };
    if (CLOSED.includes(order.fulfillmentStatus) || order.status === 'cancelado' || order.logisticsStatus === 'cancelado') {
        return { ok: false, reason: 'cerrado' };
    }
    if (order.shippingMethod !== 'delivery_propio') return { ok: false, reason: 'otra_modalidad' };
    const zones = departure?.zones || [];
    if (zones.length) {
        const city = String(order.shippingCity || '');
        const zone = String(order.shippingZone || '');
        if (!zones.includes(city) && !zones.includes(zone)) return { ok: false, reason: 'fuera_de_zona' };
    }
    const requirePaid = settings.requirePaidBeforeDispatch !== false;
    const paid = order.paymentStatus === 'pagado' || order.financialStatus === 'confirmado';
    if (requirePaid && !paid) return { ok: false, reason: 'pago_no_confirmado' };
    const prepared = ['preparado', 'listo_despacho', 'programado'].includes(order.fulfillmentStatus)
        || ['listo_despacho', 'programado'].includes(order.logisticsStatus);
    if (!prepared) return { ok: false, reason: 'no_preparado' };
    if (departure?.cutoffAt && order.createdAt && new Date(order.createdAt) > new Date(departure.cutoffAt)) {
        return { ok: false, reason: 'despues_del_limite' };
    }
    return { ok: true, reason: 'elegible' };
}

function planDispatchNotifications(departure, orders, settings = {}) {
    const included = [];
    const skipped = [];
    for (const order of orders || []) {
        const verdict = eligibleForDeparture(order, departure, settings);
        const id = String(order.id || order._id || '');
        if (!verdict.ok) {
            skipped.push({ id, reason: verdict.reason, orderNumber: order.orderNumber || '' });
            continue;
        }
        included.push({ id, orderNumber: order.orderNumber || '', waFrom: order.waFrom || '' });
    }
    const sent = new Set((departure?.notified || []).filter((item) => item.status === 'sent').map((item) => String(item.orderId)));
    const pending = included.filter((item) => !sent.has(item.id));
    const already = included.filter((item) => sent.has(item.id));
    return {
        recipients: pending.length,
        pending,
        already,
        skipped,
        departureStatus: departure?.status || 'planificada'
    };
}

const DEPARTURE_STATES = ['planificada', 'reuniendo', 'en_preparacion', 'lista', 'despachada', 'finalizada', 'cancelada', 'retrasada'];

function canDispatch(departure) {
    if (!departure) return false;
    return !['despachada', 'finalizada', 'cancelada'].includes(departure.status);
}

module.exports = {
    zonedParts,
    parseClock,
    afterCutoff,
    isServiceDay,
    nextServiceDate,
    eligibleForDeparture,
    planDispatchNotifications,
    canDispatch,
    DEPARTURE_STATES,
    OPEN_FULFILLMENT
};
