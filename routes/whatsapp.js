'use strict';

const wa = require('../lib/whatsapp');
const agent = require('../lib/wa-agent');
const slug = require('../lib/wa-slug');
const pagopar = require('../lib/pagopar');
const shop = require('../lib/orders');

function payPageLocals(order, siteConfig) {
    const paid = order.paymentStatus === 'pagado' || order.status === 'pagado';
    const cancelled = order.status === 'cancelado' || order.paymentStatus === 'cancelado';
    return {
        pageTitle: paid ? 'Pedido pagado' : 'Pagar pedido FERUMI',
        order: shop.publicOrderView(order),
        store: shop.storeFromConfig(siteConfig),
        payUrl: `/api/whatsapp/ir-a-pagar/${encodeURIComponent(order.checkoutSlug)}`,
        trackingUrl: slug.publicTrackingUrl(order.ticketCode),
        paid,
        cancelled
    };
}

async function renderPayPage(req, res, next, deps) {
    try {
        if (!slug.isPaySlug(req.params.slug)) return next();
        const order = await deps.WebOrder.findOne({
            checkoutSlug: String(req.params.slug).toLowerCase(),
            deletedAt: { $exists: false }
        });
        if (!order) return next();
        if (order.pagoparHash && order.paymentStatus !== 'pagado') {
            try {
                const result = await pagopar.consultarPedido(order.pagoparHash);
                const estado = pagopar.extractResultado(result);
                if (estado && deps.applyPaidOrder) {
                    await deps.applyPaidOrder(order, estado);
                }
            } catch (err) {
                console.warn('[whatsapp] sync pago en página', err.message);
            }
        }
        res.set('X-Robots-Tag', 'noindex, nofollow');
        res.render('public/wa-pagar', payPageLocals(order, res.locals.siteConfig));
    } catch (err) {
        next(err);
    }
}

async function goPay(req, res, next, deps) {
    try {
        const order = await deps.WebOrder.findOne({
            checkoutSlug: String(req.params.slug).toLowerCase(),
            deletedAt: { $exists: false }
        });
        if (!order) {
            return res.status(404).render('public/error', {
                pageTitle: 'Pedido',
                message: 'No encontramos ese enlace de pago.'
            });
        }
        if (order.status === 'cancelado' || order.paymentStatus === 'cancelado') {
            return res.status(410).render('public/error', {
                pageTitle: 'Pedido',
                message: 'Este enlace ya no está activo. Escribinos por WhatsApp y lo rearmamos 💖'
            });
        }
        if (order.paymentStatus === 'pagado') {
            return res.redirect(302, slug.publicTrackingUrl(order.ticketCode));
        }
        if (!order.pagoparHash) {
            const { result } = await pagopar.iniciarTransaccion({
                orderId: String(order._id),
                montoTotal: order.totalAmount,
                customer: {
                    name: order.customerName,
                    email: order.customerEmail,
                    document: order.customerDocument,
                    phone: order.customerPhone,
                    address: order.shippingAddress || '',
                    reference: order.shippingReference || '',
                    coords: order.shippingCoords?.lat != null
                        ? `${order.shippingCoords.lat},${order.shippingCoords.lng}`
                        : ''
                },
                items: order.items,
                descripcion: `FERUMI WA ${order.orderNumber}`
            });
            if (result.respuesta === true && result.resultado?.[0]?.data) {
                order.pagoparHash = result.resultado[0].data;
                await order.save();
            } else {
                return res.status(400).render('public/error', {
                    pageTitle: 'Pago',
                    message: 'Pagopar no pudo iniciar el pago. Escribinos por WhatsApp 💖'
                });
            }
        }
        return res.redirect(302, pagopar.checkoutUrl(order.pagoparHash));
    } catch (err) {
        next(err);
    }
}

function previewIncoming(text) {
    const clean = String(text || '').replace(/\s+/g, ' ').trim();
    if (!clean) return '';
    return clean.length > 80 ? `${clean.slice(0, 80)}…` : clean;
}

module.exports = function registerWhatsApp(app, deps) {
    app.get('/api/whatsapp/webhook', (req, res) => {
        const result = wa.challengeResponse(req.query);
        if (result.ok) {
            console.log('[whatsapp] Meta verificó el webhook.');
            return res.status(200).type('text/plain').send(result.challenge);
        }
        const hasToken = Boolean(wa.config().verifyToken);
        console.error('[whatsapp] Meta no pudo verificar el webhook.', hasToken
            ? 'El verify token no coincide con WHATSAPP_VERIFY_TOKEN.'
            : 'Falta WHATSAPP_VERIFY_TOKEN en el servidor.');
        return res.status(403).send('Verify token inválido');
    });

    app.post('/api/whatsapp/webhook', (req, res) => {
        res.status(200).json({ ok: true });
        try {
            const signature = req.get('X-Hub-Signature-256') || req.get('x-hub-signature-256');
            const raw = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));
            const sig = wa.verifySignature(raw, signature);
            if (!sig.ok) {
                console.error(
                    '[whatsapp] POST llegó pero la FIRMA es inválida. No respondo.',
                    `rawBody=${req.rawBody ? 'capturado' : 'NO capturado'}`,
                    `bytes=${raw.length}`,
                    `header=${signature ? 'sí' : 'no'}.`,
                    'Revisá que WHATSAPP_APP_SECRET sea el App Secret de la misma app de Meta.'
                );
                return;
            }

            const messages = wa.extractMessages(req.body || {});
            console.log(sig.skipped
                ? '[whatsapp] POST llegó. Firma no verificada (falta WHATSAPP_APP_SECRET).'
                : '[whatsapp] POST llegó. Firma OK.');
            if (!messages.length) {
                console.log('[whatsapp] No es un mensaje de clienta:', wa.summarizeWebhook(req.body));
                return;
            }

            const cfg = wa.config();
            for (const incoming of messages) {
                const text = previewIncoming(incoming.text);
                console.log(
                    `[whatsapp] SÍ llegó mensaje de ${incoming.from || '(sin número)'}`,
                    incoming.contactName ? `(${incoming.contactName})` : '',
                    `type=${incoming.type}`,
                    text ? `texto="${text}"` : '',
                    `phone_number_id=${incoming.phoneNumberId || '(vacío)'}`
                );
                if (!incoming.from) continue;
                if (incoming.phoneNumberId && cfg.phoneNumberId && incoming.phoneNumberId !== cfg.phoneNumberId) {
                    console.warn(
                        '[whatsapp] El mensaje entró por',
                        incoming.phoneNumberId,
                        'y el .env tiene',
                        `${cfg.phoneNumberId}.`,
                        'Respondo con el ID que recibió el mensaje.'
                    );
                }
                const phoneNumberId = incoming.phoneNumberId || cfg.phoneNumberId;
                wa.enqueue(incoming.from, async () => {
                    try {
                        await wa.markReadTyping(incoming.wamid, phoneNumberId);
                        const { outgoing, duplicate } = await agent.handleIncoming(incoming, deps);
                        if (duplicate) {
                            console.log('[whatsapp] Mensaje repetido de', incoming.from, '— no vuelvo a responder.');
                            return;
                        }
                        if (!outgoing?.length) {
                            console.warn('[whatsapp] Llegó el mensaje de', incoming.from, 'pero el agente no armó respuesta.');
                            return;
                        }
                        console.log(`[whatsapp] Respondiendo a ${incoming.from} (${outgoing.length} mensaje(s))`);
                        const result = await wa.sendReplies(incoming.from, outgoing, phoneNumberId);
                        console.log(`[whatsapp] Fin de envío a ${incoming.from}: enviados=${result?.sent || 0} fallidos=${result?.failed || 0}`);
                    } catch (err) {
                        console.error('[whatsapp] NO pude responder a', incoming.from, wa.explainGraphError(err));
                        try {
                            await wa.sendText(incoming.from, 'Ay linda, se me trabó un segundo 💖 Escribime de nuevo que ya te atiendo.', phoneNumberId);
                        } catch (e) {
                            console.error('[whatsapp] El aviso de error tampoco salió:', wa.explainGraphError(e));
                        }
                    }
                });
            }
        } catch (err) {
            console.error('[whatsapp] Error leyendo el webhook:', err);
        }
    });

    app.get('/api/whatsapp/ir-a-pagar/:slug', (req, res, next) => goPay(req, res, next, deps));
    app.post('/api/whatsapp/ir-a-pagar/:slug', (req, res, next) => goPay(req, res, next, deps));

    app.get('/:slug', (req, res, next) => renderPayPage(req, res, next, deps));
};

module.exports.payPageLocals = payPageLocals;
