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

module.exports = function registerWhatsApp(app, deps) {
    app.get('/api/whatsapp/webhook', (req, res) => {
        const result = wa.challengeResponse(req.query);
        if (result.ok) return res.status(200).send(result.challenge);
        return res.status(403).send('Verify token inválido');
    });

    app.post('/api/whatsapp/webhook', async (req, res) => {
        res.status(200).json({ ok: true });
        const signature = req.get('X-Hub-Signature-256') || req.get('x-hub-signature-256');
        const raw = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));
        const sig = wa.verifySignature(raw, signature);
        if (!sig.ok) {
            console.error('[whatsapp] firma inválida');
            return;
        }

        const messages = wa.extractMessages(req.body || {});
        if (!messages.length) return;

        for (const incoming of messages) {
            if (!incoming.from) continue;
            wa.enqueue(incoming.from, async () => {
                try {
                    await wa.markReadTyping(incoming.wamid);
                    const { outgoing, duplicate } = await agent.handleIncoming(incoming, deps);
                    if (duplicate || !outgoing?.length) return;
                    await wa.sendReplies(incoming.from, outgoing);
                } catch (err) {
                    console.error('[whatsapp] handle', incoming.from, err);
                    try {
                        await wa.sendText(incoming.from, 'Ay linda, se me trabó un segundo 💖 Escribime de nuevo que ya te atiendo.');
                    } catch (e) {
                        console.error('[whatsapp] fallback send', e.message);
                    }
                }
            });
        }
    });

    app.get('/api/whatsapp/ir-a-pagar/:slug', (req, res, next) => goPay(req, res, next, deps));
    app.post('/api/whatsapp/ir-a-pagar/:slug', (req, res, next) => goPay(req, res, next, deps));

    app.get('/:slug', (req, res, next) => renderPayPage(req, res, next, deps));
};

module.exports.payPageLocals = payPageLocals;
