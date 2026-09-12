'use strict';

const pagopar = require('../lib/pagopar');
const shop = require('../lib/orders');
const mongoose = require('mongoose');

function jsonResultado(res, body) {
    const resultado = Array.isArray(body?.resultado)
        ? body.resultado
        : (Array.isArray(body) ? body : (body ? [body] : [{ recibido: true }]));
    res.status(200).json(resultado);
}

async function applyPaidOrder(deps, order, pagoInfo) {
    const { Product, Transaction } = deps;
    if (!order) return order;
    const alreadyPaid = order.paymentStatus === 'pagado';

    if (pagoInfo) {
        if (pagoInfo.numero_pedido) order.pagoparNumero = String(pagoInfo.numero_pedido);
        if (pagoInfo.forma_pago) order.pagoparFormaPago = pagoInfo.forma_pago;
        if (pagoInfo.hash_pedido) order.pagoparHash = pagoInfo.hash_pedido;
        order.pagoparLastConsulta = pagoInfo;
    }

    const paid = pagoInfo?.pagado === true || pagoInfo?.pagado === 'true' || pagoInfo?.pagado === 1;
    const cancelled = pagoInfo?.cancelado === true;

    if (paid && order.paymentStatus !== 'pagado') {
        order.paymentStatus = 'pagado';
        order.status = 'pagado';
        order.paidAt = new Date();
        shop.appendEvent(order, shop.FULFILLMENT.PAGADO);
        shop.appendEvent(order, shop.FULFILLMENT.PREPARANDO, 'Pago confirmado. El equipo ya está preparando tu pedido.');
        await shop.deductStock(Product, order);

        if (!order.cashRegisterId) {
            let itemsCost = 0;
            for (const item of order.items || []) {
                if (!item.productId) continue;
                const product = await Product.findById(item.productId).select('costPrice');
                itemsCost += (product?.costPrice || 0) * (item.quantity || 1);
            }
            const split = shop.cajaSplit(order.totalAmount, itemsCost);
            const tx = await Transaction.create({
                type: 'ingreso',
                description: `Pedido ${order.source === 'whatsapp' ? 'WhatsApp' : 'web'} ${order.orderNumber} (${order.shippingMethod || 'envio'})`,
                amount: order.totalAmount,
                cost: split.cost,
                reinvestment: split.reinvestment,
                profitNando: split.profitNando,
                profitMayu: split.profitMayu,
                customerName: order.customerName,
                customerPhone: order.customerPhone,
                locationCoords: order.shippingCoords?.lat
                    ? `${order.shippingCoords.lat},${order.shippingCoords.lng}`
                    : ''
            });
            order.cashRegisterId = tx._id;
        }
    } else if (cancelled && order.paymentStatus !== 'pagado') {
        order.paymentStatus = 'cancelado';
        order.status = 'cancelado';
        shop.appendEvent(order, shop.FULFILLMENT.CANCELADO);
    }

    await order.save();
    if (paid && !alreadyPaid && order.paymentStatus === 'pagado' && typeof deps.onOrderPaid === 'function') {
        setImmediate(() => {
            Promise.resolve(deps.onOrderPaid(order)).catch((err) => {
                console.error('[whatsapp] onOrderPaid', err);
            });
        });
    }
    return order;
}

async function consultarYSincronizar(deps, orderOrHash) {
    const { WebOrder } = deps;
    let order = orderOrHash;
    let hash = typeof orderOrHash === 'string' ? orderOrHash : orderOrHash?.pagoparHash;
    if (!hash) return { order: typeof orderOrHash === 'object' ? orderOrHash : null, result: null };

    const result = await pagopar.consultarPedido(hash);
    const estado = pagopar.extractResultado(result);

    if (!order || typeof order === 'string') {
        order = await WebOrder.findOne({ pagoparHash: hash });
    }
    if (order && estado) {
        await applyPaidOrder(deps, order, estado);
    }
    return { order, result, estado };
}

module.exports = function registerEcommerce(app, deps) {
    const { WebOrder, Product, Transaction, SiteConfig, Gift, requireAdmin, upload, purify } = deps;

    const handleWebhook = async (req, res) => {
        const body = req.body || {};
        if (typeof body.resultado === 'string') {
            try { body.resultado = JSON.parse(body.resultado); } catch (e) { /* ignore */ }
        }
        const pagoInfo = pagopar.extractResultado(body);

        // Pagopar Paso 2: devolver YA el JSON. Si tardamos, no marca el check.
        jsonResultado(res, body.resultado ? body : { resultado: pagoInfo ? [pagoInfo] : [{ ok: true }] });

        setImmediate(async () => {
            try {
                if (!pagoInfo || !pagoInfo.hash_pedido) {
                    console.log('Pagopar webhook sin hash_pedido. Body:', JSON.stringify(body).slice(0, 500));
                    return;
                }

                const expected = pagopar.tokenWebhook(pagoInfo.hash_pedido);
                const incoming = pagoInfo.token;
                if (incoming && !pagopar.timingSafeEqual(expected, incoming)) {
                    console.error('Pagopar webhook: token no coincide para', pagoInfo.hash_pedido);
                    // Igual consultamos estado (Paso 3) — el simulador de Starting a veces manda token de prueba.
                }

                let order = await WebOrder.findOne({ pagoparHash: pagoInfo.hash_pedido });
                if (!order && pagoInfo.id_pedido_comercio) {
                    order = await WebOrder.findById(pagoInfo.id_pedido_comercio).catch(() => null);
                    if (order) {
                        order.pagoparHash = pagoInfo.hash_pedido;
                    }
                }

                if (order) {
                    await applyPaidOrder(deps, order, pagoInfo);
                } else {
                    console.warn('Pagopar webhook: pedido local no encontrado', pagoInfo.hash_pedido);
                }

                // Paso 3 obligatorio: el comercio DEBE consultar el estado en Pagopar.
                const consulta = await pagopar.consultarPedido(pagoInfo.hash_pedido);
                console.log('Pagopar Paso 3 consulta estado:', pagoInfo.hash_pedido, consulta?.respuesta, consulta?.resultado?.[0]?.pagado);
                const estado = pagopar.extractResultado(consulta);
                if (order && estado) {
                    await applyPaidOrder(deps, order, estado);
                }
            } catch (err) {
                console.error('Error procesando webhook Pagopar:', err);
            }
        });
    };

    const pingWebhook = (req, res) => {
        res.status(200).json({
            ok: true,
            servicio: 'FERUMI URL de respuesta Pagopar',
            metodo: req.method
        });
    };

    app.post('/api/pagopar/webhook', handleWebhook);
    app.post('/pagopar/webhook', handleWebhook);
    app.post('/pagopar/respuesta', handleWebhook);
    app.post('/tienda/pagopar/respuesta', handleWebhook);
    app.get('/api/pagopar/webhook', pingWebhook);
    app.get('/pagopar/webhook', pingWebhook);
    app.get('/pagopar/respuesta', pingWebhook);

    app.get(['/checkout', '/tienda/checkout'], (req, res) => {
        res.render('public/checkout', {
            pageTitle: 'Finalizar compra',
            store: shop.storeFromConfig(res.locals.siteConfig)
        });
    });

    app.get('/tracking', (req, res) => {
        res.render('public/tracking', {
            pageTitle: 'Tracking de pedidos'
        });
    });

    app.get('/ticket/:code', async (req, res) => {
        res.redirect(302, `/compra-ok/${encodeURIComponent(req.params.code)}`);
    });

    app.get('/compra-ok/:code', async (req, res, next) => {
        try {
            const order = await WebOrder.findOne({
                $or: [
                    { ticketCode: req.params.code },
                    { orderNumber: req.params.code }
                ]
            });
            if (!order) {
                return res.status(404).render('public/error', { pageTitle: 'Pedido', message: 'No encontramos ese pedido.' });
            }
            res.render('public/compra-ok', {
                pageTitle: 'Pedido recibido',
                order: shop.publicOrderView(order),
                store: shop.storeFromConfig(res.locals.siteConfig)
            });
        } catch (err) {
            next(err);
        }
    });

    app.post('/api/checkout/shipping-options', (req, res) => {
        const { lat, lng, city } = req.body || {};
        const info = shop.shippingOptions({
            lat, lng, city,
            siteConfig: res.locals.siteConfig
        });
        res.json({ success: true, ...info });
    });

    app.post('/api/checkout/place-order', upload.single('housePhoto'), async (req, res) => {
        try {
            const body = req.body || {};
            const customerName = purify.sanitize(String(body.customerName || '').trim());
            const customerEmail = purify.sanitize(String(body.customerEmail || '').trim().toLowerCase());
            const customerDocument = purify.sanitize(String(body.customerDocument || '').replace(/\D/g, ''));
            const customerPhone = purify.sanitize(String(body.customerPhone || '').trim());
            const shippingMethod = String(body.shippingMethod || '');
            const paymentMethod = String(body.paymentMethod || 'pagopar');
            const idempotencyKey = String(body.idempotencyKey || '').slice(0, 80);

            let cartItems = body.cartItems;
            if (typeof cartItems === 'string') {
                try { cartItems = JSON.parse(cartItems); } catch { cartItems = []; }
            }
            if (!Array.isArray(cartItems) || cartItems.length === 0) {
                return res.status(400).json({ success: false, message: 'El carrito está vacío.' });
            }
            if (!customerName || !customerEmail || !customerDocument || !customerPhone) {
                return res.status(400).json({ success: false, message: 'Completá nombre, cédula, correo y teléfono (los pide Pagopar).' });
            }
            if (!['motobolt', 'transportadora', 'retiro'].includes(shippingMethod)) {
                return res.status(400).json({ success: false, message: 'Elegí un método de envío.' });
            }
            if (paymentMethod === 'efectivo_retiro' && shippingMethod !== 'retiro') {
                return res.status(400).json({ success: false, message: 'El efectivo solo está disponible si retirás en Ferumishop.' });
            }

            if (idempotencyKey) {
                const existing = await WebOrder.findOne({ idempotencyKey });
                if (existing) {
                    if (existing.pagoparHash && existing.paymentMethod === 'pagopar' && existing.paymentStatus !== 'pagado' && existing.status !== 'cancelado') {
                        return res.json({
                            success: true,
                            duplicate: true,
                            orderNumber: existing.orderNumber,
                            ticketCode: existing.ticketCode,
                            redirectUrl: pagopar.checkoutUrl(existing.pagoparHash),
                            trackingUrl: `/tracking?q=${encodeURIComponent(existing.ticketCode)}`
                        });
                    }
                    if (existing.paymentMethod === 'efectivo_retiro' && existing.status !== 'cancelado') {
                        return res.json({
                            success: true,
                            duplicate: true,
                            orderNumber: existing.orderNumber,
                            ticketCode: existing.ticketCode,
                            redirectUrl: `/compra-ok/${existing.ticketCode}`,
                            trackingUrl: `/tracking?q=${encodeURIComponent(existing.ticketCode)}`
                        });
                    }
                    existing.idempotencyKey = `${idempotencyKey}-old-${Date.now()}`;
                    await existing.save();
                }
            }

            const normalizedItems = cartItems.map((item) => {
                const rawId = item.productId || item.id || null;
                return {
                    productId: rawId && mongoose.Types.ObjectId.isValid(rawId) ? rawId : null,
                    variantName: item.variantName || '',
                    name: item.name,
                    quantity: parseInt(item.quantity, 10) || 1,
                    price: shop.parsePrice(item.price),
                    image: item.image || ''
                };
            });

            if (!normalizedItems.every((i) => i.productId)) {
                return res.status(400).json({ success: false, message: 'Hay productos inválidos en el carrito. Volvé a agregarlos desde la tienda.' });
            }
            await shop.ensureStockAvailable(Product, normalizedItems);

            let subtotal = 0;
            for (const item of normalizedItems) {
                subtotal += item.price * item.quantity;
            }

            let discountAmount = 0;
            const couponCode = String(body.couponCode || '').trim();
            if (couponCode) {
                const gift = await Gift.findOne({ giftCardCode: couponCode, isRedeemed: false, status: 'aprobado' });
                if (gift && gift.giftCardAmount) {
                    discountAmount = Math.min(subtotal, gift.giftCardAmount);
                }
            }

            const lat = body.lat ? Number(body.lat) : null;
            const lng = body.lng ? Number(body.lng) : null;
            const city = purify.sanitize(String(body.city || '').trim());
            const address = purify.sanitize(String(body.address || '').trim());
            const reference = purify.sanitize(String(body.reference || '').trim());
            const ship = shop.shippingOptions({ lat, lng, city, siteConfig: res.locals.siteConfig });

            if (shippingMethod === 'motobolt' && ship.far) {
                return res.status(400).json({ success: false, message: 'Motobolt no llega a esa distancia. Elegí transportadora o retiro.' });
            }

            if (shippingMethod !== 'retiro' && !address && (lat == null || lng == null)) {
                return res.status(400).json({ success: false, message: 'Necesitamos tu ubicación o dirección para el envío.' });
            }

            const totalAmount = Math.max(0, subtotal - discountAmount);
            if (totalAmount < 1000 && paymentMethod === 'pagopar') {
                return res.status(400).json({ success: false, message: 'El total es demasiado bajo para Pagopar.' });
            }

            const order = new WebOrder({
                orderNumber: shop.makeOrderNumber(),
                ticketCode: shop.makeTicketCode(),
                idempotencyKey: idempotencyKey || undefined,
                customerName,
                customerEmail,
                customerDocument,
                customerPhone,
                items: normalizedItems,
                subtotal,
                shippingCost: 0,
                discountAmount,
                couponCode: couponCode || '',
                totalAmount,
                status: 'pendiente',
                paymentMethod,
                paymentStatus: 'pendiente',
                shippingMethod,
                shippingAddress: address,
                shippingCity: city,
                shippingReference: reference,
                shippingCoords: (lat != null && lng != null) ? { lat, lng } : undefined,
                shippingDistanceKm: ship.distanceKm,
                housePhotoUrl: req.file ? req.file.path : '',
                fulfillmentStatus: shop.FULFILLMENT.PENDIENTE_PAGO,
                trackingEvents: []
            });
            shop.appendEvent(order, shop.FULFILLMENT.PENDIENTE_PAGO, 'Pedido creado. Completá el pago para que lo preparemos.');
            await order.save();

            if (paymentMethod === 'efectivo_retiro') {
                shop.appendEvent(order, shop.FULFILLMENT.PREPARANDO, 'Pedido recibido. Vas a pagar en efectivo al retirar. Ya lo estamos preparando.');
                await shop.deductStock(Product, order);
                await order.save();
                return res.json({
                    success: true,
                    orderNumber: order.orderNumber,
                    ticketCode: order.ticketCode,
                    redirectUrl: `/compra-ok/${order.ticketCode}`,
                    trackingUrl: `/tracking?q=${encodeURIComponent(order.ticketCode)}`
                });
            }

            const { result } = await pagopar.iniciarTransaccion({
                orderId: String(order._id),
                montoTotal: totalAmount,
                customer: {
                    name: customerName,
                    email: customerEmail,
                    document: customerDocument,
                    phone: customerPhone,
                    address,
                    reference,
                    coords: (lat != null && lng != null) ? `${lat},${lng}` : ''
                },
                items: normalizedItems,
                descripcion: `FERUMI ${order.orderNumber}`
            });

            if (result.respuesta === true && result.resultado?.[0]?.data) {
                order.pagoparHash = result.resultado[0].data;
                await order.save();
                return res.json({
                    success: true,
                    orderNumber: order.orderNumber,
                    ticketCode: order.ticketCode,
                    redirectUrl: pagopar.checkoutUrl(order.pagoparHash),
                    trackingUrl: `/tracking?q=${encodeURIComponent(order.ticketCode)}`
                });
            }

            console.error('Pagopar rechazó iniciar-transaccion:', result.resultado);
            order.status = 'cancelado';
            shop.appendEvent(order, shop.FULFILLMENT.CANCELADO, 'Pagopar rechazó la transacción. Intentá de nuevo.');
            await order.save();
            return res.status(400).json({ success: false, details: result.resultado, message: 'Pagopar rechazó la transacción.' });
        } catch (err) {
            console.error('Error place-order:', err);
            return res.status(500).json({ success: false, message: err.message || 'Error interno al crear el pedido.' });
        }
    });

    // Compatibilidad con el botón viejo de producto-detalle
    app.post('/tienda/checkout', async (req, res) => {
        try {
            const { customerName, customerEmail, customerDocument, customerPhone, cartItems } = req.body || {};
            if (!cartItems || !cartItems.length) {
                return res.status(400).json({ success: false, message: 'El carrito está vacío.' });
            }
            const items = cartItems.map((item) => ({
                productId: item.productId || item.id || null,
                name: item.name,
                quantity: parseInt(item.quantity, 10) || 1,
                price: shop.parsePrice(item.price),
                image: item.image || ''
            }));
            let totalAmount = 0;
            items.forEach((i) => { totalAmount += i.price * i.quantity; });

            const order = new WebOrder({
                orderNumber: shop.makeOrderNumber(),
                ticketCode: shop.makeTicketCode(),
                customerName,
                customerEmail,
                customerDocument,
                customerPhone,
                items,
                subtotal: totalAmount,
                totalAmount,
                status: 'pendiente',
                paymentMethod: 'pagopar',
                paymentStatus: 'pendiente',
                shippingMethod: 'retiro',
                fulfillmentStatus: shop.FULFILLMENT.PENDIENTE_PAGO
            });
            shop.appendEvent(order, shop.FULFILLMENT.PENDIENTE_PAGO);
            await order.save();

            const { result } = await pagopar.iniciarTransaccion({
                orderId: String(order._id),
                montoTotal: totalAmount,
                customer: { name: customerName, email: customerEmail, document: customerDocument, phone: customerPhone },
                items,
                descripcion: `FERUMI ${order.orderNumber}`
            });

            if (result.respuesta === true && result.resultado?.[0]?.data) {
                order.pagoparHash = result.resultado[0].data;
                await order.save();
                return res.json({ success: true, redirectUrl: pagopar.checkoutUrl(order.pagoparHash) });
            }
            return res.status(400).json({ success: false, details: result.resultado });
        } catch (err) {
            console.error('Error Checkout compat:', err);
            return res.status(500).json({ success: false, message: 'Error interno del servidor.' });
        }
    });

    const renderResultado = async (req, res, next) => {
        try {
            const hashPedido = req.params.hash || req.query.hash || req.body?.hash_pedido;
            if (!hashPedido) {
                return res.status(400).render('public/error', {
                    pageTitle: 'Pago',
                    message: 'No recibimos el hash del pedido de Pagopar.'
                });
            }

            const { order, result, estado } = await consultarYSincronizar(deps, hashPedido);
            if (!result?.respuesta || !estado) {
                return res.status(400).render('public/error', {
                    pageTitle: 'Error de Pago',
                    message: 'No pudimos verificar el estado de la transacción en Pagopar.'
                });
            }

            res.render('public/pago-resultado', {
                pageTitle: 'Resultado del Pago',
                estado,
                orderLocal: order,
                orderView: order ? shop.publicOrderView(order) : null,
                store: shop.storeFromConfig(res.locals.siteConfig)
            });
        } catch (err) {
            console.error('Error consultando estado en Pagopar:', err);
            next(err);
        }
    };

    app.get('/tienda/resultado/:hash', renderResultado);
    app.get('/pagopar/resultado/:hash', renderResultado);
    app.get('/tienda/resultado', renderResultado);
    app.get('/pagopar/resultado', renderResultado);

    app.post('/api/tracking/search', async (req, res) => {
        try {
            const q = String(req.body?.q || req.query?.q || '').trim();
            if (!q || q.length < 3) {
                return res.status(400).json({ success: false, message: 'Ingresá teléfono, correo, cédula o número de pedido.' });
            }
            const email = q.toLowerCase();
            const doc = q.replace(/\D/g, '');
            const orders = await WebOrder.find({
                deletedAt: { $exists: false },
                $or: [
                    { customerEmail: email },
                    { customerDocument: doc || q },
                    { ticketCode: q.toUpperCase() },
                    { orderNumber: q.toUpperCase() },
                    { customerPhone: { $regex: doc || q, $options: 'i' } }
                ]
            }).sort({ createdAt: -1 }).limit(30);

            const filtered = orders.filter((o) => {
                if (o.customerEmail === email) return true;
                if (doc && o.customerDocument === doc) return true;
                if (o.ticketCode === q.toUpperCase() || o.orderNumber === q.toUpperCase()) return true;
                return shop.phonesMatch(o.customerPhone, q);
            });

            res.json({
                success: true,
                orders: filtered.map(shop.publicOrderView)
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ success: false, message: 'No pudimos buscar tus pedidos.' });
        }
    });

    app.get('/admin/despacho', requireAdmin, async (req, res, next) => {
        try {
            const filter = req.query.estado || 'activos';
            const q = {};
            if (filter === 'preparar') q.fulfillmentStatus = { $in: ['pagado', 'preparando', 'pendiente_pago'] };
            else if (filter === 'listos') q.fulfillmentStatus = { $in: ['preparado', 'esperando_motobolt', 'enviando', 'esperando_retiro'] };
            else if (filter === 'entregados') q.fulfillmentStatus = 'entregado';
            else if (filter === 'activos') q.fulfillmentStatus = { $nin: ['entregado', 'cancelado', 'devuelto'] };

            q.deletedAt = { $exists: false };
            const orders = await WebOrder.find(q).sort({ createdAt: -1 }).limit(200);
            const counts = {
                preparar: await WebOrder.countDocuments({ deletedAt: { $exists: false }, fulfillmentStatus: { $in: ['pagado', 'preparando'] } }),
                listos: await WebOrder.countDocuments({ deletedAt: { $exists: false }, fulfillmentStatus: { $in: ['preparado', 'esperando_motobolt', 'enviando', 'esperando_retiro'] } }),
                activos: await WebOrder.countDocuments({ deletedAt: { $exists: false }, fulfillmentStatus: { $nin: ['entregado', 'cancelado', 'devuelto'] } })
            };
            res.render('admin/despacho', {
                pageTitle: 'Despachar compras',
                orders,
                filter,
                counts,
                store: shop.storeFromConfig(res.locals.siteConfig),
                success: req.session.success,
                error: req.session.error
            });
            delete req.session.success;
            delete req.session.error;
        } catch (err) {
            next(err);
        }
    });

    app.post('/admin/despacho/:id/status', requireAdmin, async (req, res) => {
        try {
            const order = await WebOrder.findById(req.params.id);
            if (!order) return res.status(404).json({ success: false, message: 'Pedido no encontrado' });
            const action = String(req.body?.action || '');
            const siteConfig = res.locals.siteConfig;

            if (action === 'preparando') {
                const canPrepare = ['pendiente_pago', 'pagado', 'preparando'].includes(order.fulfillmentStatus);
                if (!canPrepare) {
                    const msg = `El pedido ${order.orderNumber} ya avanzó. No se vuelve a marcar en preparando.`;
                    if (req.headers.accept && req.headers.accept.includes('application/json')) {
                        return res.json({ success: true, alreadyDone: true, message: msg, order: shop.publicOrderView(order) });
                    }
                    req.session.success = msg;
                    return res.redirect('/admin/despacho');
                }
                shop.appendEvent(order, shop.FULFILLMENT.PREPARANDO);
            } else if (action === 'preparado' || action === 'scan') {
                const outcome = shop.scanQrOutcome(order);
                if (!outcome.apply) {
                    if (req.headers.accept && req.headers.accept.includes('application/json')) {
                        return res.json({
                            success: true,
                            alreadyDone: true,
                            message: outcome.message,
                            order: shop.publicOrderView(order)
                        });
                    }
                    req.session.success = outcome.message;
                    return res.redirect('/admin/despacho');
                }
                const next = shop.nextAfterPrepared(order);
                shop.appendEvent(order, shop.FULFILLMENT.PREPARADO, 'Pedido armado y verificado.');
                shop.appendEvent(order, next);
                order.preparedAt = new Date();
            } else if (action === 'entregado') {
                if (order.fulfillmentStatus === shop.FULFILLMENT.ENTREGADO) {
                    const msg = `El pedido ${order.orderNumber} ya fue entregado. No se vuelve a marcar.`;
                    if (req.headers.accept && req.headers.accept.includes('application/json')) {
                        return res.json({ success: true, alreadyDone: true, message: msg, order: shop.publicOrderView(order) });
                    }
                    req.session.success = msg;
                    return res.redirect('/admin/despacho');
                }
                shop.appendEvent(order, shop.FULFILLMENT.ENTREGADO);
                order.deliveredAt = new Date();
                if (order.paymentMethod === 'efectivo_retiro' && order.paymentStatus !== 'pagado') {
                    order.paymentStatus = 'pagado';
                    order.status = 'pagado';
                    order.paidAt = new Date();
                    if (!order.cashRegisterId) {
                        const split = shop.cajaSplit(order.totalAmount, 0);
                        const tx = await Transaction.create({
                            type: 'ingreso',
                            description: `Retiro en efectivo ${order.orderNumber}`,
                            amount: order.totalAmount,
                            cost: split.cost,
                            reinvestment: split.reinvestment,
                            profitNando: split.profitNando,
                            profitMayu: split.profitMayu,
                            customerName: order.customerName,
                            customerPhone: order.customerPhone
                        });
                        order.cashRegisterId = tx._id;
                    }
                }
            } else {
                return res.status(400).json({ success: false, message: 'Acción inválida' });
            }
            await order.save();

            if (typeof deps.onOrderFulfillment === 'function') {
                setImmediate(() => {
                    Promise.resolve(deps.onOrderFulfillment(order, action)).catch((err) => {
                        console.error('[whatsapp] onOrderFulfillment', err);
                    });
                });
            }

            let waKind = 'preparado_envio';
            if (order.shippingMethod === 'motobolt') waKind = 'preparado_motobolt';
            if (order.shippingMethod === 'retiro') waKind = 'preparado_retiro';
            const waText = shop.customerWhatsAppText(order, siteConfig, waKind);

            if (req.headers.accept && req.headers.accept.includes('application/json')) {
                return res.json({
                    success: true,
                    order: shop.publicOrderView(order),
                    whatsappUrl: shop.whatsappLink(order.customerPhone, waText)
                });
            }
            req.session.success = 'Estado actualizado.';
            return res.redirect('/admin/despacho');
        } catch (err) {
            console.error(err);
            if (req.headers.accept && req.headers.accept.includes('application/json')) {
                return res.status(500).json({ success: false, message: err.message });
            }
            req.session.error = err.message;
            return res.redirect('/admin/despacho');
        }
    });

    app.post('/admin/despacho/scan', requireAdmin, async (req, res) => {
        try {
            let code = shop.extractScanCode(req.body?.code);
            const validObjectId = mongoose.Types.ObjectId.isValid(code) && String(new mongoose.Types.ObjectId(code)) === code;
            const orderQuery = {
                $or: [
                    { ticketCode: code.toUpperCase() },
                    { orderNumber: code.toUpperCase() }
                ]
            };
            if (validObjectId) orderQuery.$or.push({ _id: code });
            const order = await WebOrder.findOne(orderQuery);
            if (!order) return res.status(404).json({ success: false, message: 'Ticket no encontrado' });

            const outcome = shop.scanQrOutcome(order);
            if (!outcome.apply) {
                return res.json({
                    success: true,
                    alreadyDone: true,
                    message: outcome.message,
                    order: shop.publicOrderView(order)
                });
            }

            const next = shop.nextAfterPrepared(order);
            shop.appendEvent(order, shop.FULFILLMENT.PREPARADO, 'Marcado preparado al escanear el QR del ticket.');
            shop.appendEvent(order, next);
            order.preparedAt = new Date();
            await order.save();

            if (typeof deps.onOrderFulfillment === 'function') {
                setImmediate(() => {
                    Promise.resolve(deps.onOrderFulfillment(order, 'scan')).catch((err) => {
                        console.error('[whatsapp] onOrderFulfillment scan', err);
                    });
                });
            }

            const waKind = order.shippingMethod === 'motobolt' ? 'preparado_motobolt'
                : order.shippingMethod === 'retiro' ? 'preparado_retiro' : 'preparado_envio';
            const waText = shop.customerWhatsAppText(order, res.locals.siteConfig, waKind);
            res.json({
                success: true,
                order: shop.publicOrderView(order),
                whatsappUrl: shop.whatsappLink(order.customerPhone, waText)
            });
        } catch (err) {
            res.status(500).json({ success: false, message: err.message });
        }
    });

    app.post('/admin/despacho/:id/delete', requireAdmin, async (req, res) => {
        try {
            const order = await WebOrder.findById(req.params.id);
            if (!order) throw new Error('Pedido no encontrado');
            const reason = purify.sanitize(String(req.body?.reason || '').trim());
            const deleteType = String(req.body?.deleteType || 'error');
            if (!reason) throw new Error('Indicá por qué se borra el pedido.');

            order.deleteReason = reason;
            order.deleteType = ['error', 'cancelacion', 'devolucion'].includes(deleteType) ? deleteType : 'error';
            order.deletedAt = new Date();

            if (deleteType === 'devolucion') {
                await shop.restoreStock(Product, order);
                shop.appendEvent(order, shop.FULFILLMENT.DEVUELTO, reason);
                if (order.cashRegisterId) {
                    await Transaction.create({
                        type: 'egreso',
                        description: `Devolución ${order.orderNumber}: ${reason}`,
                        amount: order.totalAmount,
                        customerName: order.customerName,
                        customerPhone: order.customerPhone
                    });
                } else {
                    await Transaction.create({
                        type: 'egreso',
                        description: `Devolución ${order.orderNumber}: ${reason}`,
                        amount: order.totalAmount,
                        customerName: order.customerName,
                        customerPhone: order.customerPhone
                    });
                }
            } else {
                if (order.stockDeducted) await shop.restoreStock(Product, order);
                shop.appendEvent(order, shop.FULFILLMENT.CANCELADO, reason);
            }
            await order.save();
            req.session.success = deleteType === 'devolucion'
                ? 'Pedido anulado como devolución. Se revirtió stock y se registró el dinero en caja.'
                : 'Pedido anulado.';
            res.redirect('/admin/despacho');
        } catch (err) {
            req.session.error = err.message;
            res.redirect('/admin/despacho');
        }
    });

    app.get('/admin/despacho/:id/ticket', requireAdmin, async (req, res, next) => {
        try {
            const order = await WebOrder.findById(req.params.id);
            if (!order) return res.status(404).render('admin/error', { message: 'Pedido no encontrado', pageTitle: 'Error' });
            res.render('public/cola-impresion', {
                pedido: shop.thermalPedidoFromWebOrder(order),
                autoPrint: true
            });
        } catch (err) {
            next(err);
        }
    });

    // Al arrancar: consultar pedidos Pagopar pendientes → completa Paso 3 del circuito Starting.
    setTimeout(async () => {
        try {
            const pending = await WebOrder.find({
                pagoparHash: { $nin: [null, ''] },
                $or: [
                    { paymentStatus: 'pendiente' },
                    { paymentStatus: { $exists: false } },
                    { status: 'pendiente' }
                ]
            }).sort({ createdAt: -1 }).limit(15);
            for (const order of pending) {
                try {
                    await consultarYSincronizar(deps, order);
                    console.log('Pagopar sync pendiente:', order.orderNumber, order.pagoparHash);
                } catch (e) {
                    console.error('Pagopar sync error:', e.message);
                }
            }
        } catch (err) {
            console.error('Pagopar sync inicial:', err.message);
        }
    }, 7000);
};

module.exports.applyPaidOrder = applyPaidOrder;
