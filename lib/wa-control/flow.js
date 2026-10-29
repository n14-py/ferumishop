'use strict';

const { normalizeText } = require('./text');

function looksLikeYes(text, buttonId) {
    if (buttonId === 'confirm_order') return true;
    const plain = normalizeText(text);
    return /^(si|ok|dale|ese|esa|es ese|es esa|confirmo|ese mismo|esa misma)$/.test(plain) || /^si\b/.test(plain);
}
const { transferMessage } = require('./transfer');

function clockLabel(value = '18:00') {
    const match = String(value || '18:00').match(/^(\d{1,2}):(\d{2})$/);
    const hour = match ? Number(match[1]) : 18;
    const minute = match ? match[2] : '00';
    const suffix = hour >= 12 ? 'pm' : 'am';
    const hour12 = hour % 12 || 12;
    return `${String(hour).padStart(2, '0')}:${minute} (${hour12}:${minute} ${suffix})`;
}

function cartIsClosed(text) {
    const plain = normalizeText(text);
    return /^(solo eso|solo esas|eso nomas|nada mas|listo|ya esta|eso es todo|con eso|asi nomas)$/.test(plain)
        || /(solo eso|nada mas|eso es todo|ya no quiero mas|con eso esta)/.test(plain);
}

function shippingChoice(text, buttonId) {
    if (buttonId === 'ship_motobolt') return 'motobolt';
    if (buttonId === 'ship_transportadora') return 'transportadora';
    if (buttonId === 'ship_retiro') return 'retiro';
    if (buttonId === 'ship_propio') return 'delivery_propio';
    const plain = normalizeText(text);
    if (/transportadora|encomienda|interior/.test(plain)) return 'transportadora';
    if (/motobolt|moto bolt|enseguida|urgente|ya mismo|para ahora/.test(plain)) return 'motobolt';
    if (/retiro|paso a buscar|busco en el local/.test(plain)) return 'retiro';
    if (/delivery propio|delivery|reparto|para hoy|a la tarde/.test(plain)) return 'delivery_propio';
    return '';
}

function alreadyClaimsReceipt(text) {
    const plain = normalizeText(text);
    return /ya (te )?(lo |la )?(mande|envie|pase)|ahi te (va|mande)|te adjunt|es el comprobante|esa es la captura|ya esta la captura|comprobante enviado/.test(plain);
}

function paymentChoice(text) {
    const plain = normalizeText(text);
    if (/efectivo|contra entrega|al recibir/.test(plain)) return 'efectivo';
    if (/transfer|alias|ueno|banco/.test(plain)) return 'transferencia';
    if (/pagopar|qr|tarjeta|tigo|giro|debito|credito/.test(plain)) return 'pagopar';
    return '';
}

function shippingMenu(departureTime) {
    const hour = clockLabel(departureTime);
    return `¿Cómo lo querés recibir?\n\nDelivery propio: sale todos los días a las ${hour}. Si me pasás la ubicación, te digo el precio de tu ciudad.\nMotobolt: si lo necesitás enseguida y estás en zona.\nTransportadora: si estás en el interior.`;
}

function paymentMenu(transfer) {
    const bank = transferMessage(transfer || {});
    const transferText = bank.ok
        ? bank.text
        : 'La transferencia la cargamos en un momento. Mientras, también podés pagar con PagoPar.';
    return `¿Cómo querés pagar?\n\nPrimero, transferencia bancaria:\n${transferText}\n\nTambién podés pagar con PagoPar: QR, tarjeta de crédito o débito, giros y Tigo Money. Si elegís PagoPar, ahí te pido los datos para el enlace.`;
}

function locationText({ place, quote, departureTime }) {
    if (!place?.label) return 'Pasame la ubicación de WhatsApp con el clip, así guardo la coordenada exacta.';
    const where = place.city
        ? `Queda en ${place.city}${place.distanceKm != null ? `, a ${place.distanceKm} km de Ferumi Shop` : ''}.`
        : 'Esa coordenada queda fuera de las ciudades de delivery. Lo vemos por transportadora.';
    const price = quote?.ok && quote.amount != null && place.city
        ? ` Delivery propio a ${place.city}: ${Number(quote.amount).toLocaleString('es-PY')} Gs. Sale a las ${clockLabel(departureTime)}.`
        : '';
    const pin = place.pinUrl ? `\nPin exacto, sin moverlo: ${place.pinUrl}` : '';
    return `Guardé el pin tal cual lo mandaste: ${place.label}.${pin}\n${where}${price}\nLa coordenada del pin no se cambia por la de la ciudad.\n${shippingMenu(departureTime)}`;
}

function nextMissingField(customer = {}) {
    if (!String(customer.name || '').trim()) return 'name';
    if (!String(customer.document || '').replace(/\D/g, '')) return 'document';
    if (!String(customer.email || '').includes('@')) return 'email';
    if (!String(customer.phone || '').replace(/\D/g, '')) return 'phone';
    return '';
}

function dataQuestion(field) {
    if (field === 'name') return 'Para el enlace de PagoPar, pasame tu nombre completo.';
    if (field === 'document') return 'Ahora tu cédula, solo números.';
    if (field === 'email') return 'Tu correo.';
    if (field === 'phone') return 'Tu teléfono, con el prefijo si lo tenés.';
    return '';
}

function absorbData(text, customer = {}) {
    const next = { ...customer };
    const field = nextMissingField(next);
    const raw = String(text || '').trim();
    if (!field || !raw) return next;
    if (field === 'name') next.name = raw.slice(0, 120);
    if (field === 'document') next.document = raw.replace(/\D/g, '').slice(0, 20);
    if (field === 'email') next.email = raw.toLowerCase().slice(0, 120);
    if (field === 'phone') next.phone = raw.slice(0, 30);
    return next;
}

function planTurn({
    text = '',
    buttonId = '',
    hasLocation = false,
    cart = [],
    stage = 'browsing',
    customer = {},
    place = null,
    quote = null,
    transfer = null,
    departureTime = '18:00',
    lastOffer = null,
    products = []
} = {}) {
    const current = stage || 'browsing';
    if (hasLocation && place?.label) {
        const method = shippingChoice(text, buttonId);
        return {
            handled: true,
            useModel: false,
            stage: method ? 'payment' : 'shipping',
            method,
            replies: method
                ? [locationText({ place, quote, departureTime }), paymentMenu(transfer)]
                : [locationText({ place, quote, departureTime })]
        };
    }
    if (current === 'browsing' && cartIsClosed(text) && cart.length) {
        return { handled: true, useModel: false, stage: 'shipping', replies: [shippingMenu(departureTime)] };
    }
    if (current === 'browsing' && lastOffer?.productId && looksLikeYes(text, buttonId)) {
        return {
            handled: true,
            useModel: false,
            stage: 'browsing',
            addOffer: true,
            replies: [`Sumé ${lastOffer.name}. ¿Querés agregar otro o con eso está?`]
        };
    }
    if (current === 'browsing' && products.length && !cartIsClosed(text)) {
        const first = products[0];
        return {
            handled: true,
            useModel: false,
            stage: 'browsing',
            showProduct: first,
            replies: [`Te muestro ${first.name}. Sale ${Number(first.price || 0).toLocaleString('es-PY')} Gs. ¿Es este?`]
        };
    }
    if (current === 'shipping' || (cart.length && shippingChoice(text, buttonId) && current === 'browsing')) {
        const method = shippingChoice(text, buttonId);
        if (!method && current === 'shipping') {
            return { handled: true, useModel: false, stage: 'shipping', replies: [shippingMenu(departureTime)] };
        }
        if (method === 'delivery_propio' && !place?.label) {
            return { handled: true, useModel: false, stage: 'shipping', method, replies: ['Delivery propio sale todos los días a las ' + clockLabel(departureTime) + '. Pasame tu ubicación de WhatsApp y te digo el precio de tu ciudad.'] };
        }
        if (method === 'delivery_propio' && place?.interior) {
            return { handled: true, useModel: false, stage: 'shipping', replies: ['Esa ubicación queda en el interior. Ahí enviamos por transportadora, no por el delivery de las ' + clockLabel(departureTime) + '. ¿Lo hacemos por transportadora?'] };
        }
        if (method === 'motobolt' && place?.interior) {
            return { handled: true, useModel: false, stage: 'shipping', replies: ['Motobolt no llega hasta el interior. Para ahí usamos transportadora. ¿Seguimos por transportadora?'] };
        }
        if (method) {
            const extra = method === 'delivery_propio' && quote?.ok
                ? `Delivery propio a ${place?.city || 'tu ciudad'}: ${Number(quote.amount).toLocaleString('es-PY')} Gs. Sale a las ${clockLabel(departureTime)}.`
                : method === 'motobolt'
                    ? 'Motobolt lo pedís vos cuando el pedido esté listo. El costo del moto se lo pagás al conductor.'
                    : method === 'transportadora'
                        ? 'Lo enviamos por transportadora. El precio de la transportadora se coordina, no lo invento.'
                        : 'Lo retirás en el local.';
            return { handled: true, useModel: false, stage: 'payment', method, replies: [`${extra}\n\n${paymentMenu(transfer)}`] };
        }
    }
    if ((current === 'payment' || current === 'receipt') && alreadyClaimsReceipt(text)) {
        return {
            handled: true,
            useModel: false,
            stage: 'receipt',
            replies: ['Si ya enviaste la foto, queda en revisión. No te vuelvo a pasar el alias.']
        };
    }
    if (current === 'payment') {
        const payment = paymentChoice(text);
        if (!payment && current === 'payment') {
            return { handled: true, useModel: false, stage: 'payment', replies: [paymentMenu(transfer)] };
        }
        if (payment === 'efectivo') {
            if (!place?.inZone) {
                return { handled: true, useModel: false, stage: 'payment', replies: ['El efectivo solo lo agendamos para el día siguiente si estás en zona de delivery. En el interior es transferencia o PagoPar, y el envío va por transportadora.'] };
            }
            return { handled: true, useModel: false, stage: 'scheduled_cash', payment, replies: [`El efectivo lo agendamos para el día siguiente, con la salida de las ${clockLabel(departureTime)}. ¿A qué nombre dejo el pedido?`] };
        }
        if (payment === 'transferencia') {
            return { handled: true, useModel: false, stage: 'receipt', payment, replies: [transferMessage(transfer).text, 'Cuando hagas la transferencia, enviame la foto del comprobante.'] };
        }
        if (payment === 'pagopar') {
            return { handled: true, useModel: false, stage: 'data', payment, replies: ['PagoPar acepta QR, tarjeta de crédito, débito, giros y Tigo Money. ' + dataQuestion('name')] };
        }
    }
    if (current === 'data' || current === 'scheduled_cash') {
        const updated = current === 'data' ? absorbData(text, customer) : { ...customer, name: customer.name || String(text || '').trim() };
        if (current === 'scheduled_cash') {
            return { handled: true, useModel: false, stage: 'done', customer: updated, createOrder: 'efectivo', replies: [`Listo, ${updated.name || 'el pedido'} queda agendado para el día siguiente. El efectivo se paga al recibir.`] };
        }
        const missing = nextMissingField(updated);
        if (missing) {
            return { handled: true, useModel: false, stage: 'data', customer: updated, replies: [dataQuestion(missing)] };
        }
        return { handled: true, useModel: false, stage: 'data', customer: updated, createOrder: 'pagopar', replies: [] };
    }
    return { handled: false, useModel: true, stage: current, replies: [] };
}

module.exports = {
    clockLabel,
    cartIsClosed,
    alreadyClaimsReceipt,
    shippingChoice,
    paymentChoice,
    shippingMenu,
    paymentMenu,
    planTurn,
    nextMissingField,
    absorbData
};
