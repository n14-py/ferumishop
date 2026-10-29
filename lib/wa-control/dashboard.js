'use strict';

function inRange(date, from, to) {
    if (!date) return false;
    const time = new Date(date).getTime();
    if (Number.isNaN(time)) return false;
    if (from && time < new Date(from).getTime()) return false;
    if (to && time > new Date(to).getTime()) return false;
    return true;
}

function matchesFilters(order, filters = {}) {
    if (filters.paymentMethod && order.paymentMethod !== filters.paymentMethod) return false;
    if (filters.shippingMethod && order.shippingMethod !== filters.shippingMethod) return false;
    if (filters.financialStatus && (order.financialStatus || order.paymentStatus) !== filters.financialStatus) return false;
    if (filters.status && order.fulfillmentStatus !== filters.status && order.logisticsStatus !== filters.status) return false;
    return true;
}

function money(order) {
    return Number(order.totalAmount) || 0;
}

function summarizeOperations({ orders = [], conversations = [], intents = [], outbounds = [], products = [], receipts = [], departures = [], filters = {}, now = new Date() }) {
    const from = filters.from || null;
    const to = filters.to || null;
    const rangedOrders = orders.filter((order) => matchesFilters(order, filters) && (!from && !to ? true : inRange(order.createdAt, from, to)));
    const paid = orders.filter((order) => {
        if (!matchesFilters(order, filters)) return false;
        if (order.paymentStatus !== 'pagado' && order.financialStatus !== 'confirmado') return false;
        const when = order.paidAt || null;
        if (when) return inRange(when, from, to);
        return inRange(order.createdAt, from, to);
    });
    const collected = paid.reduce((sum, order) => sum + (Number(order.amountPaid) || money(order)), 0);
    const registered = rangedOrders
        .filter((order) => order.status !== 'cancelado' && order.fulfillmentStatus !== 'cancelado')
        .reduce((sum, order) => sum + money(order), 0);
    const pendingCollection = rangedOrders
        .filter((order) => order.status !== 'cancelado' && order.paymentStatus !== 'pagado' && order.financialStatus !== 'confirmado')
        .reduce((sum, order) => sum + Math.max(0, money(order) - (Number(order.amountPaid) || 0)), 0);
    const count = (list, pred) => list.filter(pred).length;
    const methods = {};
    for (const order of rangedOrders) {
        const key = order.shippingMethod || 'sin_dato';
        methods[key] = (methods[key] || 0) + 1;
    }
    const lowStock = products.filter((product) => {
        if (product.aiVisible === false) return false;
        if (product.hasVariants) return (product.variants || []).some((variant) => (variant.stock || 0) <= 2);
        return (product.stock || 0) <= 2;
    }).map((product) => ({
        id: String(product.id || product._id || ''),
        name: product.name,
        stock: product.stock || 0
    }));
    const alerts = [];
    if (receipts.some((item) => item.status === 'en_verificacion' || item.status === 'diferencia')) {
        alerts.push({ level: 'warn', code: 'pago_en_verificacion', text: 'Hay un comprobante que requiere verificación.' });
    }
    if (conversations.some((item) => item.attentionStatus === 'human_requested')) {
        alerts.push({ level: 'warn', code: 'humano', text: 'Un cliente pidió atención humana.' });
    }
    if (outbounds.some((item) => item.status === 'failed')) {
        alerts.push({ level: 'danger', code: 'mensaje_fallido', text: 'Una notificación no pudo enviarse.' });
    }
    const activeDeparture = departures.find((item) => ['planificada', 'reuniendo', 'en_preparacion', 'lista'].includes(item.status));
    if (activeDeparture && (activeDeparture.unprepared || 0) > 0) {
        alerts.push({ level: 'warn', code: 'salida_sin_preparar', text: 'La próxima salida tiene pedidos sin preparar.' });
    }
    if (intents.some((item) => item.status === 'uncertain' || item.status === 'calling')) {
        alerts.push({ level: 'danger', code: 'pago_incierto', text: 'Hay una operación de pago sin resultado confirmado.' });
    }
    return {
        generatedAt: now,
        conversationsNew: count(conversations, (item) => inRange(item.createdAt || item.updatedAt, from, to)),
        conversationsActive: count(conversations, (item) => !['closed'].includes(item.attentionStatus || 'ai_active')),
        waitingHuman: count(conversations, (item) => ['human_requested', 'human_active', 'pending_resolution'].includes(item.attentionStatus)),
        ordersToday: rangedOrders.length,
        pendingConfirmation: count(rangedOrders, (order) => (order.commercialStatus || 'pendiente_confirmacion') === 'pendiente_confirmacion'),
        pendingPayment: count(rangedOrders, (order) => order.paymentStatus !== 'pagado' && order.financialStatus !== 'confirmado' && order.status !== 'cancelado'),
        transfersToVerify: count(receipts, (item) => item.status === 'en_verificacion' || item.status === 'diferencia'),
        paid: paid.length,
        preparing: count(rangedOrders, (order) => ['preparando', 'en_preparacion'].includes(order.fulfillmentStatus || order.logisticsStatus)),
        ready: count(rangedOrders, (order) => ['preparado', 'listo_despacho', 'esperando_retiro', 'esperando_motobolt'].includes(order.fulfillmentStatus || order.logisticsStatus)),
        inNextDeparture: count(rangedOrders, (order) => Boolean(order.departureId) && !['entregado', 'cancelado'].includes(order.fulfillmentStatus)),
        dispatched: count(rangedOrders, (order) => ['enviando', 'despachado', 'en_camino', 'esperando_motobolt'].includes(order.fulfillmentStatus || order.logisticsStatus)),
        delivered: count(rangedOrders, (order) => (order.fulfillmentStatus || order.logisticsStatus) === 'entregado'),
        delayed: count(rangedOrders, (order) => ['reprogramado', 'intento_fallido'].includes(order.fulfillmentStatus || order.logisticsStatus)),
        cancelled: count(rangedOrders, (order) => order.status === 'cancelado' || order.fulfillmentStatus === 'cancelado'),
        paymentLinks: count(intents, (item) => item.hash || item.payUrl),
        messageErrors: count(outbounds, (item) => item.status === 'failed'),
        integrationErrors: count(intents, (item) => item.status === 'failed' || item.status === 'uncertain'),
        lowStock,
        registeredSales: registered,
        collectedSales: collected,
        pendingCollection,
        deliveryMethods: methods,
        alerts,
        notes: [
            'Los pedidos registrados no son cobros. El cobro confirmado sale solo de pagos con estado pagado o confirmado.',
            'Los enlaces de PagoPar generados no se suman como dinero recibido.'
        ]
    };
}

module.exports = { summarizeOperations, inRange };
