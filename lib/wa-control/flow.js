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

function asksSchedule(text) {
    const plain = normalizeText(text);
    return /sale a las|a las 6|a las 18|a que hora|que hora sale|horario|cuando sale|6 de la tarde|18 horas/.test(plain);
}

function isComplaint(text) {
    const plain = normalizeText(text);
    return /no te pedi|no le pedi|no pedi|no te lo pedi|no quiero eso|no quiero fotos|no quiero productos|deja de|basta|no era eso|para que me (mandas|envias)|no mandes|no envies|ya te dije que no/.test(plain);
}

function shippingChoice(text, buttonId) {
    if (buttonId === 'ship_motobolt') return 'motobolt';
    if (buttonId === 'ship_transportadora') return 'transportadora';
    if (buttonId === 'ship_retiro') return 'retiro';
    if (buttonId === 'ship_propio') return 'delivery_propio';
    if (asksSchedule(text) || isComplaint(text)) return '';
    const plain = normalizeText(text);
    if (/transportadora|encomienda|interior/.test(plain)) return 'transportadora';
    if (/motobolt|moto bolt|enseguida|urgente|ya mismo|para ahora/.test(plain)) return 'motobolt';
    if (/retiro|paso a buscar|busco en el local/.test(plain)) return 'retiro';
    if (/delivery propio|delivery|reparto|para hoy|a la tarde/.test(plain)) return 'delivery_propio';
    return '';
}

function isProductSearch(text, buttonId) {
    if (!String(text || '').trim()) return false;
    if (asksSchedule(text) || isComplaint(text) || cartIsClosed(text) || looksLikeYes(text, buttonId)) return false;
    if (paymentChoice(text) || alreadyClaimsReceipt(text)) return false;
    const tokens = require('./catalog').queryTokens(text).filter((token) => !/^(delivery|propi|envi|envio|moto|motobolt|transport|repart|ubic|zon|horari|alias|transfer|comprob)/.test(token));
    if (!tokens.length) return false;
    if (shippingChoice(text, buttonId)) return false;
    return true;
}

function looksLikeGreeting(text) {
    const plain = normalizeText(text);
    if (!plain || plain.length > 80) return false;
    if (isProductSearch(text) || asksSchedule(text) || isComplaint(text) || shippingChoice(text) || paymentChoice(text)) return false;
    return /^(hola|buenas|buenos dias|buenas tardes|buenas noches|buen dia|hey|oli|ola|que tal|holi)\b/.test(plain);
}

function wantsToOrder(text) {
    const plain = normalizeText(text);
    return /quiero (hacer )?(un )?pedido|quiero comprar|quiero pedir|para encargar|quiero encargar|vengo a pedir/.test(plain);
}

function plausibleName(text) {
    const raw = String(text || '').trim().replace(/[!?.]+$/g, '');
    const plain = normalizeText(raw);
    if (raw.length < 2 || raw.length > 60 || /\d/.test(raw)) return '';
    if (looksLikeGreeting(text) || wantsToOrder(text) || asksSchedule(text) || isComplaint(text)) return '';
    if (shippingChoice(text) || paymentChoice(text) || cartIsClosed(text) || looksLikeYes(text)) return '';
    const words = plain.split(/\s+/).filter(Boolean);
    if (!words.length || words.length > 4) return '';
    if (/^(hola|buenas|ok|si|dale|gracias|bueno|listo)$/.test(plain)) return '';
    return raw;
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
    return [
        `Delivery propio: sale todos los días a las ${hour}.`,
        '',
        'Motobolt: si lo necesitás enseguida y estás en zona. El costo del moto se lo pagás al conductor.',
        '',
        'Transportadora: si estás en el interior. El precio se coordina.',
        '',
        '¿De dónde sos, o me pasás tu ubicación?'
    ].join('\n');
}

function paymentMenu() {
    return [
        '¿Cómo querés pagar?',
        '',
        'Transferencia bancaria.',
        '',
        'PagoPar: tarjeta de crédito o débito, QR, giros y Tigo Money.'
    ].join('\n');
}

function looksLikeQuestion(text) {
    const plain = normalizeText(text);
    return /\?/.test(String(text || '')) || /cuanto|como hago|donde|que es|puedo|sale a/.test(plain);
}

function money(amount) {
    return `${Number(amount).toLocaleString('es-PY')} Gs`;
}

function outsideZone(place) {
    return !place?.inZone || Boolean(place?.interior);
}

function locationText({ place, quote, departureTime, method = '' }) {
    if (!place?.label) return 'Pasame la ubicación de WhatsApp para decirte el costo del envío.';
    const outside = outsideZone(place);
    const city = place.city ? ` a ${place.city}` : '';
    const priced = quote?.ok && quote.amount != null
        ? `Delivery propio${city}: ${money(quote.amount)}. Sale todos los días a las ${clockLabel(departureTime)}.`
        : '';
    if (method === 'retiro') return 'El retiro es en el local. Guardé tu ubicación.';
    if (method === 'motobolt') {
        return outside
            ? 'Esa ubicación queda fuera de zona. Motobolt no llega; el envío es por transportadora.'
            : 'Estás en zona de Motobolt. El costo del moto se lo pagás al conductor.';
    }
    if (method === 'transportadora') {
        return outside
            ? 'Esa ubicación queda fuera de la zona de delivery. El envío es por transportadora. El precio se coordina.'
            : 'Lo enviamos por transportadora. El precio se coordina.';
    }
    if (outside) return 'Esa ubicación queda fuera de zona. El envío es por transportadora. El precio se coordina.';
    if (method === 'delivery_propio') {
        return priced || `Estás en zona de delivery${place.city ? ` (${place.city})` : ''}. Todavía no tengo una tarifa cargada para esa ciudad.`;
    }
    if (priced) return `Estás en zona de delivery y de Motobolt. ${priced}`;
    return `Estás en zona de delivery y de Motobolt${place.city ? ` (${place.city})` : ''}.`;
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
    products = [],
    chosenMethod = '',
    awaitingName = false,
    pendingQuestion = '',
    hasImage = false,
    totalLabel = ''
} = {}) {
    const current = stage || 'browsing';
    const knownName = String(customer.name || '').trim();
    if (isComplaint(text) && !hasLocation && !hasImage) {
        return {
            handled: true,
            useModel: false,
            stage: current,
            replies: ['Perdón, me fui de tema. No te mando más productos. Seguimos con lo que ya estabas viendo.']
        };
    }
    if (hasLocation && place?.label) {
        const picked = shippingChoice(text, buttonId) || chosenMethod || '';
        const outside = outsideZone(place);
        const invalid = (picked === 'delivery_propio' || picked === 'motobolt') && outside;
        let nextStage = current;
        if (invalid || !picked) {
            if (current === 'browsing' || current === 'shipping') nextStage = 'shipping';
        } else if (current === 'browsing' || current === 'shipping') {
            nextStage = 'payment';
        }
        const replies = [locationText({ place, quote, departureTime, method: invalid ? picked : picked })];
        if (!invalid && picked) replies.push(paymentMenu());
        else replies.push('¿Lo hacemos por delivery propio, Motobolt o transportadora?');
        if (!knownName) replies.push('¿Cómo es tu nombre?');
        return {
            handled: true,
            useModel: false,
            verbatim: true,
            stage: nextStage,
            askName: !knownName,
            method: invalid ? '' : picked,
            replies
        };
    }
    if (!knownName && !hasLocation && !hasImage && current === 'browsing') {
        if (awaitingName && !products.length) {
            const name = plausibleName(text);
            if (name) {
                const resume = String(pendingQuestion || '').trim();
                return {
                    handled: true,
                    useModel: false,
                    stage: 'browsing',
                    customer: { ...customer, name },
                    clearNameAsk: true,
                    resume,
                    replies: resume ? [] : [`Hola ${name}. Contame qué estás buscando y te lo muestro.`]
                };
            }
        }
        if (awaitingName && (products.length || asksSchedule(text))) {
            return {
                handled: true,
                useModel: false,
                stage: 'browsing',
                askName: true,
                holdQuestion: String(text || '').trim(),
                replies: ['Eso te lo respondo enseguida. Primero decime tu nombre.']
            };
        }
        if (!awaitingName) {
            const pureHello = looksLikeGreeting(text) && !isProductSearch(text, buttonId) && !asksSchedule(text);
            return {
                handled: true,
                useModel: false,
                stage: 'browsing',
                askName: true,
                holdQuestion: pureHello ? '' : String(text || '').trim(),
                replies: ['Hola, soy Ferumi. ¿Cómo es tu nombre?']
            };
        }
    }
    if (asksSchedule(text) && !hasLocation) {
        const bits = [`Sí. El delivery propio sale todos los días a las ${clockLabel(departureTime)}.`];
        const talkingDelivery = chosenMethod === 'delivery_propio' || /delivery/.test(normalizeText(text));
        if (talkingDelivery && quote?.ok && quote.amount != null && place?.city && !outsideZone(place)) {
            bits.push(`A ${place.city} son ${money(quote.amount)}.`);
        } else if (talkingDelivery && !place?.label) {
            bits.push('Pasame la ubicación y te digo el precio.');
        }
        return { handled: true, useModel: false, stage: current, replies: [bits.join(' ')] };
    }
    if (current === 'browsing' && cartIsClosed(text) && cart.length) {
        return { handled: true, useModel: false, verbatim: true, stage: 'shipping', replies: [shippingMenu(departureTime)] };
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
    if (current === 'browsing' && products.length && isProductSearch(text, buttonId)) {
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
        const picked = shippingChoice(text, buttonId);
        const method = picked || chosenMethod;
        if (!picked && current === 'shipping' && !chosenMethod) {
            return { handled: true, useModel: false, verbatim: true, stage: 'shipping', replies: [shippingMenu(departureTime)] };
        }
        if (!picked && chosenMethod && place?.label) {
            return {
                handled: true,
                useModel: false,
                verbatim: true,
                stage: 'payment',
                method: chosenMethod,
                replies: [paymentMenu()]
            };
        }
        if (method === 'delivery_propio' && !place?.label) {
            return { handled: true, useModel: false, verbatim: true, stage: 'shipping', method, replies: ['Delivery propio sale todos los días a las ' + clockLabel(departureTime) + '. ¿De dónde sos, o me pasás tu ubicación?'] };
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
            return { handled: true, useModel: false, verbatim: true, stage: 'payment', method, replies: [extra, paymentMenu()] };
        }
    }
    if (current === 'receipt' && !hasLocation && !hasImage && text && !alreadyClaimsReceipt(text) && !looksLikeQuestion(text) && !paymentChoice(text) && String(text).trim().length >= 4) {
        if (!knownName) {
            const name = plausibleName(text);
            if (name) {
                return {
                    handled: true,
                    useModel: false,
                    stage: 'receipt',
                    customer: { ...customer, name },
                    clearNameAsk: true,
                    replies: [`Listo, ${name}. Cuando hagas la transferencia, pasame la foto del comprobante.`]
                };
            }
        }
        return {
            handled: true,
            useModel: false,
            stage: 'receipt',
            reference: String(text).trim().slice(0, 180),
            replies: ['Anoté la referencia de tu casa. Cuando tengas el comprobante, pasame la foto.']
        };
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
            return { handled: true, useModel: false, verbatim: true, stage: 'payment', replies: [paymentMenu()] };
        }
        if (payment === 'efectivo') {
            if (!place?.inZone) {
                return { handled: true, useModel: false, stage: 'payment', replies: ['El efectivo solo lo agendamos para el día siguiente si estás en zona de delivery. En el interior es transferencia o PagoPar, y el envío va por transportadora.'] };
            }
            return { handled: true, useModel: false, stage: 'scheduled_cash', payment, replies: [`El efectivo lo agendamos para el día siguiente, con la salida de las ${clockLabel(departureTime)}. ¿A qué nombre dejo el pedido?`] };
        }
        if (payment === 'transferencia') {
            const bank = transferMessage(transfer, { total: totalLabel, onlyAlias: true });
            const bits = [bank.text];
            if (!knownName) bits.push('Decime tu nombre para el pedido.');
            if (!place?.label) bits.push('Pasame tu ubicación o una referencia de la casa.');
            else bits.push('Si tenés una referencia de la casa, pasamela. Y la foto del comprobante cuando la tengas.');
            return { handled: true, useModel: false, verbatim: true, stage: 'receipt', payment, askName: !knownName, replies: [bits.join('\n\n')] };
        }
        if (payment === 'pagopar') {
            const missing = nextMissingField(customer);
            if (!missing) {
                return { handled: true, useModel: false, stage: 'data', payment, customer, createOrder: 'pagopar', replies: [] };
            }
            return { handled: true, useModel: false, stage: 'data', payment, replies: ['PagoPar acepta QR, tarjeta de crédito, débito, giros y Tigo Money. ' + dataQuestion(missing)] };
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
    asksSchedule,
    isComplaint,
    isProductSearch,
    looksLikeGreeting,
    wantsToOrder,
    plausibleName,
    shippingChoice,
    paymentChoice,
    shippingMenu,
    paymentMenu,
    planTurn,
    nextMissingField,
    absorbData
};
