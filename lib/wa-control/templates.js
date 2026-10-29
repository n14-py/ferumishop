'use strict';

const VARIABLE_RE = /\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g;

const ALLOWED_VARIABLES = [
    'customerName', 'orderNumber', 'items', 'total', 'shippingCost', 'confirmedDate',
    'method', 'payUrl', 'status', 'storeAddress', 'ticketCode', 'city', 'note'
];

const DEFAULT_TEMPLATES = [
    { key: 'greeting', name: 'Saludo inicial', channel: 'session', body: 'Hola. Te atiende Ferumi Shop. ¿En qué te puedo ayudar?' },
    { key: 'product_answer', name: 'Consulta de producto', channel: 'session', body: '{{items}}\nPrecio: {{total}}.\nSi querés, te muestro fotos reales del producto.' },
    { key: 'recommendation', name: 'Recomendación', channel: 'session', body: 'Por lo que me contás, esta opción encaja: {{items}}. El precio actual es {{total}}.' },
    { key: 'cart_confirm', name: 'Confirmación del carrito', channel: 'session', body: 'Quedó así:\n{{items}}\nTotal: {{total}}.\n¿Lo confirmamos?' },
    { key: 'order_summary', name: 'Resumen del pedido', channel: 'session', body: 'Pedido {{orderNumber}}\n{{items}}\nEnvío: {{shippingCost}}\nTotal: {{total}}\nModalidad: {{method}}' },
    { key: 'transfer_instructions', name: 'Instrucciones de transferencia', channel: 'session', body: 'Si vas a transferir, el comprobante queda para verificación humana. El pedido {{orderNumber}} no se marca pago solo con la foto.' },
    { key: 'payment_link', name: 'Enlace de PagoPar', channel: 'session', body: 'Tu pedido {{orderNumber}} está listo para pagar.\nTotal: {{total}}\nEnlace: {{payUrl}}\nCuando PagoPar acredite el pago, te aviso por acá.' },
    { key: 'payment_link_sent', name: 'Enlace ya enviado', channel: 'session', body: 'El enlace de pago del pedido {{orderNumber}} ya te lo envié y sigue siendo el mismo. No generé otro.' },
    { key: 'receipt_received', name: 'Recepción de comprobante', channel: 'session', body: 'Recibí el comprobante del pedido {{orderNumber}}. Queda pendiente de verificación. Todavía no está confirmado el pago.' },
    { key: 'receipt_duplicate', name: 'Comprobante duplicado', channel: 'session', body: 'Ese comprobante ya está cargado para el pedido {{orderNumber}}. No lo volví a registrar como un pago nuevo.' },
    { key: 'payment_pending', name: 'Pago pendiente de verificar', channel: 'session', body: 'El pago del pedido {{orderNumber}} sigue pendiente de verificación.' },
    { key: 'payment_confirmed', name: 'Pago confirmado', channel: 'session', body: 'El pago del pedido {{orderNumber}} quedó confirmado. Total acreditado: {{total}}.' },
    { key: 'amount_difference', name: 'Diferencia de importe', channel: 'session', body: 'El comprobante del pedido {{orderNumber}} no coincide con el total {{total}}. Lo dejé para revisión, sin confirmar el pago.' },
    { key: 'preparing', name: 'Pedido en preparación', channel: 'session', body: 'Tu pedido {{orderNumber}} está en preparación.' },
    { key: 'ready', name: 'Pedido listo', channel: 'session', body: 'Tu pedido {{orderNumber}} ya está listo. Modalidad: {{method}}.' },
    { key: 'shipped', name: 'Confirmación de envío', channel: 'session', body: 'Tu pedido {{orderNumber}} fue despachado. Estado: {{status}}.' },
    { key: 'departure', name: 'Delivery despachado', channel: 'session', body: 'El delivery de Ferumi ya salió con tu pedido {{orderNumber}}.' },
    { key: 'rescheduled', name: 'Reprogramación', channel: 'session', body: 'Tu pedido {{orderNumber}} se reprogramó. Fecha propuesta: {{confirmedDate}}.' },
    { key: 'delay', name: 'Retraso', channel: 'session', body: 'Hay una demora con el pedido {{orderNumber}}. {{note}}' },
    { key: 'customer_absent', name: 'Cliente ausente', channel: 'session', body: 'Pasamos con el pedido {{orderNumber}} y no encontramos a nadie en la dirección. Lo vamos a reprogramar.' },
    { key: 'delivered', name: 'Pedido entregado', channel: 'session', body: 'Tu pedido {{orderNumber}} figura como entregado. Gracias por comprar en Ferumi.' },
    { key: 'cancelled', name: 'Cancelación', channel: 'session', body: 'El pedido {{orderNumber}} quedó cancelado.' },
    { key: 'incident', name: 'Devolución o incidencia', channel: 'session', body: 'Registramos una incidencia en el pedido {{orderNumber}}. {{note}}' },
    { key: 'human_handoff', name: 'Atención humana', channel: 'session', body: 'Dejo tu consulta para una persona del equipo. No te puedo prometer que te responda en este momento.' },
    { key: 'conversation_closed', name: 'Cierre de conversación', channel: 'session', body: 'Cierro esta conversación. Cuando quieras, escribinos de nuevo.' },
    { key: 'after_hours', name: 'Fuera de horario', channel: 'session', body: 'Ahora estamos fuera del horario de atención. Tu mensaje queda registrado.' },
    { key: 'shipping_unavailable', name: 'Envío sin tarifa', channel: 'session', body: 'Todavía no tengo una tarifa cargada para {{city}} con la modalidad {{method}}. No te voy a inventar el precio.' },
    { key: 'partial_unavailable', name: 'Seña no habilitada', channel: 'session', body: 'Ahora no está habilitada la seña ni el pago parcial. Puedo armar el pedido con el pago completo o derivarlo para autorización.' }
];

function extractVariables(body) {
    const found = new Set();
    String(body || '').replace(VARIABLE_RE, (_, name) => {
        found.add(name);
        return '';
    });
    return [...found];
}

function validateTemplate(body) {
    const vars = extractVariables(body);
    const unknown = vars.filter((name) => !ALLOWED_VARIABLES.includes(name));
    return { ok: unknown.length === 0, variables: vars, unknown };
}

function renderTemplate(body, data = {}, { required = [] } = {}) {
    const check = validateTemplate(body);
    if (!check.ok) {
        return { ok: false, error: `Variables no permitidas: ${check.unknown.join(', ')}` };
    }
    const missing = [];
    for (const name of required) {
        if (data[name] == null || data[name] === '') missing.push(name);
    }
    for (const name of check.variables) {
        if (required.includes(name)) continue;
        if (data[name] == null || data[name] === '') missing.push(name);
    }
    if (missing.length) {
        return { ok: false, error: `Faltan datos: ${[...new Set(missing)].join(', ')}`, missing: [...new Set(missing)] };
    }
    const text = String(body || '').replace(VARIABLE_RE, (_, name) => String(data[name]));
    return { ok: true, text, variables: check.variables };
}

function templateByKey(templates, key) {
    return (templates || []).find((item) => item.key === key && item.active !== false) || null;
}

module.exports = {
    ALLOWED_VARIABLES,
    DEFAULT_TEMPLATES,
    extractVariables,
    validateTemplate,
    renderTemplate,
    templateByKey
};
