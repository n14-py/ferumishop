'use strict';

const wa = require('../lib/whatsapp');
const agent = require('../lib/wa-agent');
const { createGather, mergeIncoming } = require('../lib/wa-control/gather');
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
            const ensured = await require('../lib/wa-control/checkout').ensurePagoparHash(order);
            if (ensured.ok && (ensured.hash || order.pagoparHash)) {
                return res.redirect(302, pagopar.checkoutUrl(ensured.hash || order.pagoparHash));
            }
            return res.status(ensured.uncertain ? 409 : 400).render('public/error', {
                pageTitle: 'Pago',
                message: ensured.message || 'Pagopar no pudo iniciar el pago. Escribinos por WhatsApp.'
            });
        }
        return res.redirect(302, pagopar.checkoutUrl(order.pagoparHash));
    } catch (err) {
        next(err);
    }
}

async function noteBusinessEcho(echo, models, mongoose) {
    if (!echo || !echo.to) return;
    if (echo.wamid) {
        const own = await models.WaOutbound.findOne({ providerId: echo.wamid }).lean();
        if (own) return;
    }
    const WaConversation = mongoose.models.WaConversation;
    if (!WaConversation) return;
    const conv = await WaConversation.findOne({ waId: echo.to });
    if (!conv) return;
    const recentOwn = (conv.history || []).slice(-6).some((item) => item.role === 'assistant' && echo.text && item.content === echo.text);
    if (recentOwn) return;
    conv.aiPaused = true;
    conv.attentionStatus = 'human_active';
    conv.pausedReason = 'mensaje_desde_el_celular';
    conv.updatedAt = new Date();
    await conv.save();
    await models.WaAudit.create({
        action: 'intervencion_celular',
        actor: 'whatsapp_celular',
        waId: echo.to,
        operationId: echo.wamid || '',
        result: 'IA pausada porque llegó un eco no enviado por el servidor'
    });
}

function previewIncoming(text) {
    const clean = String(text || '').replace(/\s+/g, ' ').trim();
    if (!clean) return '';
    return clean.length > 80 ? `${clean.slice(0, 80)}…` : clean;
}

module.exports = function registerWhatsApp(app, deps) {
    const configuredDelay = Number(process.env.WA_REPLY_DELAY_MS);
    const gather = createGather({
        delayMs: Number.isFinite(configuredDelay) && configuredDelay >= 0 ? configuredDelay : 10000
    });

    async function settleBurst(items) {
        const merged = mergeIncoming(items);
        const phoneNumberId = merged.phoneNumberId || wa.config().phoneNumberId;
        const models = require('../lib/wa-control/models').controlModels();
        await wa.enqueue(merged.from, async () => {
            try {
                const handled = await agent.handleIncoming(merged, deps);
                const claimedIds = merged.claimedIds || [];
                if (handled.duplicate) {
                    console.log('[whatsapp] Mensaje repetido de', merged.from, '— no vuelvo a responder.');
                    if (claimedIds.length) await models.WaInbound.updateMany({ _id: { $in: claimedIds } }, { $set: { status: 'processed', finishedAt: new Date() } });
                    return;
                }
                const { customerSafeText } = require('../lib/wa-control/text');
                const outgoing = (handled.outgoing || []).map((reply) => {
                    if (!reply || typeof reply !== 'object') return reply;
                    const next = { ...reply };
                    if (next.text) next.text = customerSafeText(next.text);
                    if (next.caption) next.caption = customerSafeText(next.caption);
                    return next;
                });
                if (!outgoing.length) {
                    if (claimedIds.length) await models.WaInbound.updateMany({ _id: { $in: claimedIds } }, { $set: { status: 'processed', finishedAt: new Date() } });
                    return;
                }
                console.log(`[whatsapp] Respondiendo a ${merged.from} (${outgoing.length} mensaje(s))`);
                const result = await wa.sendReplies(merged.from, outgoing, phoneNumberId);
                if (handled.sendPaymentLink && handled.paymentIntentKey && result.sent > 0) {
                    await require('../lib/wa-control/checkout').markPaymentLinkSent(handled.paymentIntentKey);
                }
                if (claimedIds.length) {
                    await models.WaInbound.updateMany({ _id: { $in: claimedIds } }, { $set: { status: result.failed ? 'error' : 'processed', finishedAt: new Date() } });
                }
                console.log(`[whatsapp] Fin de envío a ${merged.from}: enviados=${result?.sent || 0} fallidos=${result?.failed || 0}`);
            } catch (err) {
                console.error('[whatsapp] NO pude responder a', merged.from, wa.explainGraphError(err));
                const claimedIds = merged.claimedIds || [];
                if (claimedIds.length) {
                    await models.WaInbound.updateMany({ _id: { $in: claimedIds } }, { $set: { status: 'error', error: String(err.message || '').slice(0, 240), finishedAt: new Date() } }).catch(() => {});
                }
                const fallbackKey = `error:${merged.wamid || merged.from}`;
                try {
                    await models.WaOutbound.create({ key: fallbackKey, waId: merged.from, purpose: 'error', status: 'sending' });
                    await wa.sendText(merged.from, 'Se me complicó un segundo. Escribime de nuevo y lo retomo.', phoneNumberId);
                    await models.WaOutbound.updateOne({ key: fallbackKey }, { $set: { status: 'sent', sentAt: new Date() } });
                } catch (e) {
                    if (e && e.code !== 11000) console.error('[whatsapp] El aviso de error tampoco salió:', wa.explainGraphError(e));
                }
            }
        });
    }

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

    app.post('/api/whatsapp/webhook', async (req, res) => {
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
            const echoes = wa.extractEchoes(req.body || {});
            const statuses = wa.extractStatuses(req.body || {});
            console.log(sig.skipped
                ? '[whatsapp] POST llegó. Firma no verificada (falta WHATSAPP_APP_SECRET).'
                : '[whatsapp] POST llegó. Firma OK.');
            if (!messages.length) {
                console.log('[whatsapp] No es un mensaje de clienta:', wa.summarizeWebhook(req.body));
            }
            const mongoose = require('mongoose');
            const models = require('../lib/wa-control/models').controlModels();
            for (const status of statuses) {
                if (status.status !== 'failed') continue;
                models.WaAudit.create({
                    action: 'mensaje_fallido',
                    status: 'error',
                    actor: 'whatsapp',
                    waId: status.recipient || '',
                    operationId: status.wamid || '',
                    error: (status.errors || []).join('; ').slice(0, 300)
                }).catch(() => {});
            }
            for (const echo of echoes) {
                noteBusinessEcho(echo, models, mongoose).catch((err) => console.error('[whatsapp] echo', err.message));
            }
            if (!messages.length) return;

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
                let claimedId = '';
                try {
                    if (incoming.wamid) {
                        const claimed = await models.WaInbound.create({
                            wamid: incoming.wamid,
                            waId: incoming.from,
                            status: 'processing',
                            type: incoming.type || '',
                            preview: String(incoming.text || '').slice(0, 80)
                        });
                        claimedId = String(claimed._id);
                    }
                } catch (err) {
                    if (err && err.code === 11000) {
                        console.log('[whatsapp] Mensaje repetido de', incoming.from, '— no vuelvo a responder.');
                        continue;
                    }
                    console.error('[whatsapp] No pude registrar la deduplicación:', err.message);
                }
                wa.markReadTyping(incoming.wamid, phoneNumberId).catch(() => {});
                gather.push(incoming.from, { ...incoming, claimedId, phoneNumberId }, (batch) => {
                    settleBurst(batch).catch((err) => console.error('[whatsapp] tanda', err.message));
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
