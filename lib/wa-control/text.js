'use strict';

function normalizeText(value) {
    return String(value || '')
        .normalize('NFC')
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/ñ/g, 'n')
        .trim();
}

function sanitizeOutgoingText(value) {
    let text = String(value || '').normalize('NFC');
    text = text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
    text = text.replace(/\*\*([^*\n]+)\*\*/g, '$1');
    text = text.replace(/(^|[\s(])\*([^*\n]+)\*(?=$|[\s).,!?;:])/g, '$1$2');
    text = text.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
    return text;
}

function wantsHuman(text, buttonId) {
    if (buttonId === 'request_human') return true;
    const t = normalizeText(text);
    if (!t) return false;
    return /(hablar con (una )?(persona|humana|humano|asesor|alguien)|atencion humana|persona real|quiero (un|una) (asesor|persona|humano)|no quiero (el )?bot|operador|derivame|pasame con)/.test(t);
}

function detectIntent(text, buttonId) {
    if (buttonId === 'confirm_order') return 'confirm_order';
    if (buttonId === 'request_human') return 'human';
    if (buttonId === 'resend_payment_link') return 'pay_link';
    const t = normalizeText(text);
    if (!t) return 'unknown';
    if (wantsHuman(text, buttonId)) return 'human';
    if (/(comprobante|transferencia|captura del pago|ya pague|ya te pague|te deposite)/.test(t)) return 'receipt';
    if (/(enlace de pago|link de pago|pasame el link|mandame el link|el link otra vez|link de pagopar)/.test(t)) return 'pay_link';
    if (/(seña|sena\b|anticipo|pago parcial|reservar con)/.test(t)) return 'partial';
    if (/(descuento|rebaja|mas barato|oferta|promocion)/.test(t)) return 'discount';
    if (/(cancelar|anular el pedido|quiero cancelar)/.test(t)) return 'cancel';
    if (/(efectivo|pago al recibir|contra entrega|pago contraentrega)/.test(t)) return 'cash';
    if (/(motobolt|moto bolt|delivery moto)/.test(t)) return 'motobolt';
    if (/(transportadora|encomienda|interior|tsi|jaraha)/.test(t)) return 'carrier';
    if (/(retiro|paso a buscar|buscar en el local)/.test(t)) return 'pickup';
    if (/(donde esta mi pedido|estado del pedido|mi pedido|tracking|seguimiento)/.test(t)) return 'order_status';
    if (/(cambiar (la )?direccion|otra direccion|nueva direccion)/.test(t)) return 'address_change';
    if (/(foto|imagen|parecido|similar|igual a esto)/.test(t)) return 'similar';
    if (/(precio|cuanto sale|cuánto|vale)/.test(t)) return 'price';
    if (/(stock|hay |tienen |queda )/.test(t)) return 'stock';
    return 'chat';
}

function guardCustomerReply(text, facts = {}) {
    let out = sanitizeOutgoingText(text);
    if (!out) return out;
    const plain = normalizeText(out);
    if (!facts.paymentConfirmed && /pago (ya )?(esta )?(confirmado|acreditado|recibido)|ya quedo pago|ya esta pago/.test(plain)) {
        out = facts.safePaymentText || 'Recibí el comprobante y queda pendiente de verificación. Todavía no está confirmado el pago.';
    }
    if (facts.maxDiscount === 0 && /te (aplico|dejo|hago|regalo) un descuento|\d+\s*%\s*(off|de descuento)/.test(plain)) {
        out = facts.safeDiscountText || 'No tengo un descuento autorizado para aplicar en este pedido.';
    }
    if (!facts.motoboltDispatched && /el motobolt ya (salio|fue pedido|esta en camino)|el repartidor ya (salio|va en camino)/.test(plain)) {
        out = facts.safeMotoboltText || 'Motobolt se pide cuando el pedido está preparado y el pago confirmado. Todavía no está solicitado.';
    }
    return out;
}

function previewText(value, max = 80) {
    const clean = String(value || '').replace(/\s+/g, ' ').trim();
    if (!clean) return '';
    return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

function redactSecrets(value) {
    if (value == null) return value;
    if (typeof value === 'string') {
        return value
            .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [redactado]')
            .replace(/(token|password|secret|api[_-]?key|authorization)(["']?\s*[:=]\s*["']?)[^"',\s}]+/gi, '$1$2[redactado]');
    }
    if (Array.isArray(value)) return value.map(redactSecrets);
    if (typeof value === 'object') {
        const out = {};
        for (const [key, item] of Object.entries(value)) {
            if (/token|password|secret|authorization|api[_-]?key|private/i.test(key)) out[key] = '[redactado]';
            else out[key] = redactSecrets(item);
        }
        return out;
    }
    return value;
}

module.exports = {
    normalizeText,
    sanitizeOutgoingText,
    wantsHuman,
    detectIntent,
    guardCustomerReply,
    previewText,
    redactSecrets
};
