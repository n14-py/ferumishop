'use strict';

const { detectIntent, wantsHuman } = require('./text');
const { evaluateRules, discountAllowed } = require('./rules');
const { quoteShipping } = require('./rates');
const { assessReceipt } = require('./payments');
const { situationIsLive, affectsNewOrder } = require('./situations');
const { afterCutoff } = require('./departures');
const { matchCatalogByDescription, visionStatus } = require('./vision');

const SCENARIOS = [
    { id: 'price', label: 'Solo pregunta un precio', text: '¿Cuánto sale el labial?' },
    { id: 'out_of_stock', label: 'Producto agotado', text: 'Quiero el labial negro' },
    { id: 'photo', label: 'Envía una foto', text: 'Te mando la foto', image: true },
    { id: 'similar', label: 'Producto similar', text: '¿Tienen algo parecido a un labial mate rojo?' },
    { id: 'discount', label: 'Pide descuento', text: '¿Me hacés un descuento?' },
    { id: 'deposit', label: 'Quiere pagar una seña', text: '¿Puedo dejar una seña?' },
    { id: 'receipt', label: 'Envía un comprobante', text: 'Ya te pagué, te mando el comprobante' },
    { id: 'receipt_dup', label: 'Reenvía el mismo comprobante', text: 'Te reenvío el mismo comprobante' },
    { id: 'wrong_amount', label: 'Pagó un importe incorrecto', text: 'Transferí 10000' },
    { id: 'motobolt', label: 'Pide MotoBolt', text: 'Quiero Motobolt en Asunción' },
    { id: 'carrier', label: 'Interior con transportadora', text: 'Estoy en Encarnación, ¿hay transportadora?' },
    { id: 'cash', label: 'Efectivo al recibir', text: '¿Puedo pagar en efectivo cuando llegue?' },
    { id: 'after_hours', label: 'Compra después de las 18:00', text: 'Quiero delivery propio hoy' },
    { id: 'rain', label: 'Afectado por reprogramación', text: '¿Sale hoy mi delivery?' },
    { id: 'human', label: 'Pide atención humana', text: 'Quiero hablar con una persona' },
    { id: 'cancel', label: 'Solicita cancelar', text: 'Quiero cancelar el pedido' },
    { id: 'address', label: 'Cambia de dirección', text: 'Quiero cambiar la dirección' },
    { id: 'previous', label: 'Pregunta por un pedido anterior', text: '¿Dónde está mi pedido FER-1?' },
    { id: 'burst', label: 'Varios mensajes seguidos', text: 'hola\nprecio del labial\nhay stock?' },
    { id: 'paylink', label: 'Pide de nuevo el mismo enlace', text: 'Pasame otra vez el link de pago' }
];

function simulateTurn({ text, buttonId, image, catalog = [], rules, rates = [], situations = [], settings, order, now = new Date(), receipt, openPayment, scenarioId }) {
    const scenario = SCENARIOS.find((item) => item.id === scenarioId);
    const message = text || scenario?.text || '';
    const withImage = Boolean(image || scenario?.image);
    let intent = withImage ? 'photo' : detectIntent(message, buttonId);
    if (scenarioId === 'out_of_stock') intent = 'stock';
    if (scenarioId === 'after_hours') intent = 'after_hours';
    if (scenarioId === 'receipt_dup') intent = 'receipt_dup';
    if (scenarioId === 'wrong_amount') intent = 'wrong_amount';
    if (scenarioId === 'paylink') intent = 'pay_link';
    if (scenarioId === 'photo') intent = 'photo';
    text = message;
    image = withImage;
    const context = {
        method: order?.shippingMethod || (intent === 'motobolt' ? 'motobolt' : intent === 'cash' ? 'motobolt' : ''),
        paymentMethods: order?.shippingMethod === 'retiro' ? ['pagopar', 'efectivo'] : ['pagopar', 'transferencia'],
        stockOk: intent !== 'out_of_stock',
        afterCutoff: afterCutoff(now, settings || { cutoffTime: '18:00', timezone: 'America/Asuncion' }),
        needsHuman: wantsHuman(text, buttonId) || intent === 'discount',
        requiresPayment: true,
        paymentConfirmed: order?.financialStatus === 'confirmado' || order?.paymentStatus === 'pagado'
    };
    if (intent === 'out_of_stock') context.stockOk = false;
    const evaluated = evaluateRules(rules, context, now);
    const tools = [];
    const missing = [];
    let reply = '';
    let handoff = false;
    let orderEffect = 'sin_cambios';

    if (intent === 'price' || intent === 'stock' || intent === 'similar') {
        tools.push('search_catalog');
        const found = (catalog || []).filter((item) => text.toLowerCase().includes(String(item.name || '').toLowerCase().split(' ')[0]) || intent === 'price');
        const product = catalog[0];
        if (intent === 'similar') {
            tools.push('match_catalog');
            const matches = matchCatalogByDescription(text, catalog);
            reply = matches.length
                ? `Encontré una coincidencia ${matches[0].confidence}: ${matches[0].name}. No es una confirmación de que sea idéntico.`
                : 'No tengo una coincidencia suficiente en el catálogo.';
        } else if (product && (product.stock || 0) <= 0) {
            reply = `${product.name} está agotado. Puedo buscar una alternativa real del catálogo.`;
        } else if (product) {
            reply = `${product.name}: ${product.price} Gs. Stock actual: ${product.stock}.`;
        } else {
            missing.push('producto');
            reply = 'Decime qué producto querés y lo busco en el catálogo.';
        }
        if (intent === 'stock' && found[0] && (found[0].stock || 0) <= 0) reply = `${found[0].name} está agotado.`;
    } else if (intent === 'discount') {
        const decision = discountAllowed(evaluated.decisions, 1000, order?.totalAmount || 100000);
        handoff = !decision.ok && evaluated.decisions.requireHuman;
        reply = decision.ok
            ? `Puedo aplicar hasta ${decision.cap} Gs.`
            : 'No tengo un descuento autorizado. Si hace falta una excepción, lo ve una persona.';
        orderEffect = 'sin_descuento';
    } else if (intent === 'partial' || intent === 'deposit') {
        reply = evaluated.decisions.allowPartial
            ? 'La seña está habilitada según la regla activa.'
            : 'La seña y el pago parcial no están habilitados. No reservo el producto por un mensaje.';
        orderEffect = evaluated.decisions.allowPartial ? 'parcial_permitido' : 'parcial_bloqueado';
        handoff = !evaluated.decisions.allowPartial;
    } else if (intent === 'receipt' || intent === 'receipt_dup' || intent === 'wrong_amount') {
        tools.push('register_receipt');
        const assessment = assessReceipt({
            expectedAmount: order?.totalAmount || 25000,
            declaredAmount: intent === 'wrong_amount' ? 10000 : (order?.totalAmount || 25000),
            duplicate: intent === 'receipt_dup' || receipt?.duplicate
        });
        reply = assessment.status === 'duplicado'
            ? 'Ese comprobante ya estaba registrado. No sumé otro pago.'
            : 'Dejé el comprobante en verificación. El pago no quedó confirmado.';
        orderEffect = 'comprobante_en_verificacion';
    } else if (intent === 'motobolt') {
        tools.push('calculate_shipping');
        const quote = quoteShipping(rates, { method: 'motobolt', city: 'Asunción', far: false }, now);
        reply = `MotoBolt: primero confirmamos productos y total, el pago se verifica y recién después se coordina el moto. El costo del conductor ${quote.priced ? 'no se carga en el pedido de Ferumi' : 'no está inventado'}. No digo que el moto ya fue pedido.`;
    } else if (intent === 'carrier') {
        tools.push('list_carriers');
        reply = 'Para el interior uso las transportadoras cargadas. Si no tienen tarifa cargada, no invento el precio ni el horario.';
        missing.push('transportadora_elegida');
    } else if (intent === 'cash') {
        const allowed = context.paymentMethods.includes('efectivo') && !evaluated.decisions.forbiddenPayments.includes('efectivo');
        reply = allowed
            ? 'El efectivo está habilitado para esta modalidad.'
            : 'El efectivo no está habilitado para esta modalidad. No lo ofrezco.';
    } else if (intent === 'after_hours' || (intent === 'chat' && /delivery propio/.test(String(text).toLowerCase()))) {
        tools.push('next_departure');
        reply = context.afterCutoff
            ? 'Ya pasó el horario límite de la salida de hoy. No prometo el reparto de hoy.'
            : 'Si el pedido está pago y preparado antes del límite, puede entrar en la salida configurada.';
    } else if (intent === 'human') {
        handoff = true;
        reply = 'Dejo tu consulta para una persona del equipo. No te prometo una respuesta inmediata.';
        orderEffect = 'atencion_humana';
    } else if (intent === 'cancel') {
        tools.push('order_status');
        reply = 'Puedo dejar la cancelación registrada si el pedido todavía no fue entregado. No la aplico sin confirmación.';
        missing.push('confirmacion_de_cancelacion');
    } else if (intent === 'address_change') {
        reply = '¿La dirección nueva es solo para este pedido o la querés dejar como habitual?';
        missing.push('alcance_de_la_direccion');
    } else if (intent === 'order_status') {
        tools.push('lookup_orders');
        reply = order ? `El pedido ${order.orderNumber} está en estado financiero ${order.financialStatus || order.paymentStatus}.` : 'No encontré un pedido asociado en este contexto de prueba.';
    } else if (intent === 'pay_link') {
        tools.push('get_payment_link');
        reply = openPayment?.payUrl
            ? 'Reutilizo el enlace vigente. No genero otro.'
            : 'No hay un enlace vigente en esta simulación. No llamo a PagoPar desde el simulador.';
        orderEffect = openPayment ? 'enlace_reutilizado' : 'sin_enlace';
    } else if (intent === 'photo' || image) {
        tools.push('vision_status');
        const vision = visionStatus();
        reply = vision.available
            ? 'Puedo analizar la foto con el modelo configurado y compararla con el catálogo real.'
            : vision.reason;
    } else {
        reply = 'Puedo consultar catálogo, envío y estado del pedido. No confirmo pagos ni invento precios.';
    }

    const liveSituations = (situations || []).filter((item) => situationIsLive(item, now) && affectsNewOrder(item, { method: 'delivery_propio', city: order?.shippingCity, now }));
    if (liveSituations.length && /delivery|sale hoy/.test(String(text).toLowerCase())) {
        reply = `${liveSituations[0].responseInstructions || liveSituations[0].title}. Aplico la situación solo a la modalidad afectada.`;
    }

    return {
        simulated: true,
        sideEffects: false,
        intent,
        tools,
        rules: evaluated.traces.filter((trace) => trace.matched).map((trace) => trace.name),
        reply,
        handoff,
        missing,
        orderEffect,
        paymentConfirmed: false
    };
}

module.exports = {
    SCENARIOS,
    simulateTurn
};
