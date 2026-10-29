'use strict';

const mongoose = require('mongoose');
const { requirePermission, publicAdmin, permissionFlags, ROLES } = require('../lib/wa-control/permissions');
const service = require('../lib/wa-control/service');
const { controlModels } = require('../lib/wa-control/models');
const { DEFAULT_AI } = require('../lib/wa-control/prompt');
const { ATTENTION_LABELS, FINANCIAL, LOGISTICS } = require('../lib/wa-control/states');
const { CATEGORIES, SCOPES } = require('../lib/wa-control/situations');
const { DEPARTURE_STATES } = require('../lib/wa-control/departures');

const NAV = [
    ['dashboard', 'Resumen', 'fa-gauge'],
    ['conversaciones', 'Conversaciones', 'fa-comments'],
    ['clientes', 'Clientes', 'fa-user'],
    ['pedidos', 'Pedidos', 'fa-receipt'],
    ['pagos', 'Pagos', 'fa-money-check'],
    ['catalogo', 'Catálogo IA', 'fa-box'],
    ['delivery', 'Delivery', 'fa-motorcycle'],
    ['tarifas', 'Tarifas', 'fa-map'],
    ['transportadoras', 'Transportadoras', 'fa-truck'],
    ['ia', 'Configuración IA', 'fa-robot'],
    ['reglas', 'Reglas', 'fa-scale-balanced'],
    ['plantillas', 'Plantillas', 'fa-message'],
    ['automatizaciones', 'Automatizaciones', 'fa-clock'],
    ['situaciones', 'Situaciones', 'fa-cloud-rain'],
    ['atencion', 'Atención humana', 'fa-headset'],
    ['simulador', 'Simulador', 'fa-flask'],
    ['actividad', 'Actividad', 'fa-list'],
    ['errores', 'Errores', 'fa-triangle-exclamation'],
    ['integraciones', 'Integraciones', 'fa-plug'],
    ['permisos', 'Permisos', 'fa-user-shield']
];

function flash(req) {
    const success = req.session.success || null;
    const error = req.session.error || null;
    delete req.session.success;
    delete req.session.error;
    return { success, error };
}

function back(res, section, extra) {
    const params = new URLSearchParams(extra || {});
    const suffix = params.toString() ? `?${params}` : '';
    return res.redirect(`/admin/whatsapp/${section}${suffix}`);
}

async function loadSection(section, query) {
    const models = controlModels();
    if (section === 'dashboard') return service.dashboardData(query);
    if (section === 'conversaciones' || section === 'atencion') {
        const list = await service.listConversations({
            ...query,
            status: query.status || (section === 'atencion' ? 'humanos' : '')
        });
        const detail = query.id ? await service.getConversation(query.id) : null;
        const admins = await mongoose.model('AdminUser').find().select('username email role').lean();
        return { ...list, detail, labels: ATTENTION_LABELS, admins };
    }
    if (section === 'clientes') {
        const list = await service.listConversations(query);
        return list;
    }
    if (section === 'pedidos') {
        const list = await service.listOrders(query);
        const detail = query.id ? await service.getOrder(query.id) : null;
        return { ...list, detail, financial: FINANCIAL, logistics: LOGISTICS };
    }
    if (section === 'pagos') {
        const receipts = await models.WaReceipt.find({}).sort({ createdAt: -1 }).limit(80).lean();
        const intents = await models.WaPaymentIntent.find({}).sort({ updatedAt: -1 }).limit(40).lean();
        const settings = await models.WaSettings.findOne({ key: 'main' }).lean();
        return { receipts, intents, transfer: settings?.transfer || {} };
    }
    if (section === 'catalogo') {
        const q = query.q ? new RegExp(String(query.q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') : null;
        const filter = q ? { name: q } : {};
        const products = await mongoose.model('Product').find(filter).select('name price stock aiVisible aiNotes aiUsage isForSale').sort({ name: 1 }).limit(80).lean();
        return { products };
    }
    if (section === 'delivery') {
        const settings = await models.WaSettings.findOne({ key: 'main' }).lean();
        const departures = await models.WaDeparture.find({}).sort({ createdAt: -1 }).limit(30).lean();
        const orders = await mongoose.model('WebOrder').find({
            shippingMethod: 'delivery_propio',
            deletedAt: { $exists: false },
            status: { $ne: 'cancelado' }
        }).sort({ createdAt: -1 }).limit(40).lean();
        return { settings: settings || service.DEFAULT_SETTINGS, departures, orders, states: DEPARTURE_STATES };
    }
    if (section === 'tarifas') {
        const rates = await models.WaRate.find({}).sort({ method: 1, priority: -1 }).lean();
        const places = await models.WaPlace.find({}).sort({ kind: 1, name: 1 }).lean();
        const quote = query.probar ? await service.quote(query) : null;
        return { rates, places, quote };
    }
    if (section === 'transportadoras') {
        const carriers = await models.WaCarrier.find({}).lean();
        const settings = await models.WaSettings.findOne({ key: 'main' }).lean();
        return { carriers, settings: settings || service.DEFAULT_SETTINGS };
    }
    if (section === 'ia') {
        const published = await models.WaAiProfile.findOne({ key: 'published' }).lean();
        const draft = await models.WaAiProfile.findOne({ key: 'draft' }).lean();
        const revisions = await models.WaAiRevision.find({}).sort({ version: -1 }).limit(20).lean();
        return { published: published?.snapshot || DEFAULT_AI, draft: draft?.snapshot || null, version: published?.version || 0, revisions };
    }
    if (section === 'reglas') return { rules: await models.WaRule.find({}).sort({ priority: -1 }).lean() };
    if (section === 'plantillas') return { templates: await models.WaTemplate.find({}).sort({ name: 1 }).lean() };
    if (section === 'automatizaciones') return { jobs: await models.WaAutomation.find({}).lean() };
    if (section === 'situaciones') {
        const situations = await models.WaSituation.find({}).sort({ createdAt: -1 }).limit(40).lean();
        return { situations, categories: CATEGORIES, scopes: SCOPES, conflicts: service.situationConflicts(situations) };
    }
    if (section === 'simulador') return { scenarios: service.SCENARIOS, result: null };
    if (section === 'actividad' || section === 'errores') {
        const filter = section === 'errores' ? { $or: [{ status: 'error' }, { status: 'uncertain' }] } : {};
        const events = await models.WaAudit.find(filter).sort({ at: -1 }).limit(80).lean();
        return { events };
    }
    if (section === 'integraciones') return { status: await service.integrationStatus() };
    if (section === 'permisos') {
        const users = await mongoose.model('AdminUser').find().select('username email role').lean();
        return { users, roles: ROLES };
    }
    return {};
}

module.exports = function registerWaAdmin(app, deps) {
    const view = async (req, res, section, data, flashes) => {
        res.render('admin/whatsapp/index', {
            pageTitle: 'WhatsApp AI',
            path: '/admin/whatsapp',
            section,
            nav: NAV,
            data: data || {},
            admin: publicAdmin(req.user),
            perms: permissionFlags(req.user),
            labels: ATTENTION_LABELS,
            success: flashes?.success || null,
            error: flashes?.error || null,
            query: req.query || {}
        });
    };

    app.get(['/admin/whatsapp', '/admin/whatsapp/:section'], requirePermission('wa.view'), async (req, res, next) => {
        try {
            await service.ensureDefaults();
            const section = req.params.section || 'dashboard';
            if (!NAV.some((item) => item[0] === section)) return next();
            const data = await loadSection(section, req.query || {});
            return view(req, res, section, data, flash(req));
        } catch (err) {
            return next(err);
        }
    });

    app.post('/admin/whatsapp/conversaciones/:id/estado', requirePermission('wa.handoff'), async (req, res, next) => {
        try {
            const result = await service.setAttention(req.params.id, req.body.action, req.user, {
                id: req.body.ownerId,
                name: req.body.ownerName
            });
            req.session[result.ok ? 'success' : 'error'] = result.ok ? 'Estado de atención actualizado.' : result.message;
            return back(res, 'conversaciones', { id: req.params.id });
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/conversaciones/:id/nota', requirePermission('wa.reply'), async (req, res, next) => {
        try {
            const result = await service.addInternalNote(req.params.id, req.body.text, req.user);
            req.session[result.ok ? 'success' : 'error'] = result.ok ? 'Nota interna guardada. No se envió al cliente.' : result.message;
            return back(res, 'conversaciones', { id: req.params.id });
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/conversaciones/:id/mensaje', requirePermission('wa.reply'), async (req, res, next) => {
        try {
            const result = await service.sendManualMessage(req.params.id, req.body.text, req.user);
            req.session[result.ok ? 'success' : 'error'] = result.ok ? 'Mensaje enviado. La IA quedó pausada en esta conversación.' : result.message;
            return back(res, 'conversaciones', { id: req.params.id });
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/pedidos/:id', requirePermission('wa.orders.write'), async (req, res, next) => {
        try {
            const result = await service.changeOrder(req.params.id, req.body, req.user);
            req.session[result.ok ? 'success' : 'error'] = result.ok ? 'Pedido actualizado con registro.' : result.message;
            return back(res, 'pedidos', { id: req.params.id });
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/pagos/:id', requirePermission('wa.payments.approve'), async (req, res, next) => {
        try {
            if (req.body.action === 'confirm' && req.body.confirm !== 'CONFIRMAR') {
                req.session.error = 'Para confirmar el pago escribí CONFIRMAR.';
                return back(res, 'pagos');
            }
            const result = await service.reviewReceipt(req.params.id, req.body.action, req.user, req.body);
            req.session[result.ok ? 'success' : 'error'] = result.ok ? 'Comprobante actualizado.' : result.message;
            return back(res, 'pagos');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/transferencia', requirePermission('wa.payments.approve'), async (req, res, next) => {
        try {
            await controlModels().WaSettings.updateOne({ key: 'main' }, {
                $set: {
                    transfer: {
                        alias: String(req.body.alias || '').trim(),
                        bank: String(req.body.bank || '').trim(),
                        holderName: String(req.body.holderName || '').trim(),
                        note: String(req.body.note || '').trim()
                    },
                    updatedAt: new Date(),
                    updatedBy: req.user.username || req.user.email
                }
            }, { upsert: true });
            req.session.success = 'Datos de transferencia guardados. La IA va a usar exactamente esos datos.';
            return back(res, 'pagos');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/pagos/:id/reintentar', requirePermission('wa.payments.approve'), async (req, res, next) => {
        try {
            if (req.body.confirm !== 'REINTENTAR') {
                req.session.error = 'Escribí REINTENTAR para autorizar otro intento. No se generó un enlace.';
                return back(res, 'pagos');
            }
            const intent = await controlModels().WaPaymentIntent.findById(req.params.id);
            if (!intent || intent.status !== 'uncertain') {
                req.session.error = 'Solo se puede autorizar un reintento si la operación está incierta.';
                return back(res, 'pagos');
            }
            intent.status = 'retry_authorized';
            await intent.save();
            if (intent.orderId) {
                await mongoose.model('WebOrder').updateOne({ _id: intent.orderId }, { $set: { pagoparAttemptStatus: 'retry_authorized' } });
            }
            req.session.success = 'Reintento autorizado. El próximo cobro usará la misma operación y no uno paralelo automático.';
            return back(res, 'pagos');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/catalogo/:id', requirePermission('wa.catalog'), async (req, res, next) => {
        try {
            await mongoose.model('Product').updateOne({ _id: req.params.id }, {
                $set: {
                    aiVisible: req.body.aiVisible === 'true',
                    aiNotes: String(req.body.aiNotes || '').slice(0, 1000),
                    aiUsage: String(req.body.aiUsage || '').slice(0, 1000)
                }
            });
            req.session.success = 'Visibilidad del producto actualizada.';
            return back(res, 'catalogo');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/delivery', requirePermission('wa.delivery'), async (req, res, next) => {
        try {
            const days = String(req.body.serviceDays || '1,2,3,4,5,6').split(',').map((item) => Number(item)).filter((item) => item >= 0 && item <= 6);
            await controlModels().WaSettings.updateOne({ key: 'main' }, {
                $set: {
                    departureTime: req.body.departureTime || '18:00',
                    cutoffTime: req.body.cutoffTime || '17:30',
                    timezone: 'America/Asuncion',
                    serviceDays: days,
                    requirePaidBeforeDispatch: req.body.requirePaidBeforeDispatch === 'true',
                    updatedAt: new Date(),
                    updatedBy: req.user.username || req.user.email
                }
            }, { upsert: true });
            req.session.success = 'Horario de delivery guardado.';
            return back(res, 'delivery');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/salidas', requirePermission('wa.delivery'), async (req, res, next) => {
        try {
            const orderIds = String(req.body.orderIds || '').split(',').map((item) => item.trim()).filter(Boolean);
            await controlModels().WaDeparture.create({
                businessDate: req.body.businessDate,
                departAt: req.body.departAt ? new Date(req.body.departAt) : undefined,
                cutoffAt: req.body.cutoffAt ? new Date(req.body.cutoffAt) : undefined,
                zones: String(req.body.zones || '').split(',').map((item) => item.trim()).filter(Boolean),
                status: 'planificada',
                notes: req.body.notes || '',
                orderIds,
                responsible: req.user.username || req.user.email
            });
            req.session.success = 'Salida planificada.';
            return back(res, 'delivery');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/salidas/:id/despachar', requirePermission('wa.notify.bulk'), async (req, res, next) => {
        try {
            const result = await service.dispatchDeparture(req.params.id, req.user, req.body.confirm);
            req.session[result.ok ? 'success' : 'error'] = result.ok
                ? `Salida despachada. Avisos nuevos: ${result.sent}. Fallidos: ${result.failed.length}.`
                : result.message;
            return back(res, 'delivery');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/tarifas', requirePermission('wa.prices'), async (req, res, next) => {
        try {
            const result = await service.saveRate(req.body, req.user, req.body.id || null);
            req.session[result.ok ? 'success' : 'error'] = result.ok ? 'Tarifa guardada.' : result.message;
            return back(res, 'tarifas');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/lugares', requirePermission('wa.delivery'), async (req, res, next) => {
        try {
            await controlModels().WaPlace.create({
                kind: req.body.kind || 'city',
                name: req.body.name,
                parent: req.body.parent || '',
                aliases: String(req.body.aliases || '').split(',').map((item) => item.trim()).filter(Boolean),
                active: true,
                notes: req.body.notes || ''
            });
            req.session.success = 'Lugar guardado.';
            return back(res, 'tarifas');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/transportadoras', requirePermission('wa.delivery'), async (req, res, next) => {
        try {
            const payload = {
                name: req.body.name,
                active: req.body.active === 'true',
                coverage: req.body.coverage || '',
                tariffMode: req.body.tariffMode || 'unknown',
                ratesNote: req.body.ratesNote || '',
                paymentTerms: req.body.paymentTerms || '',
                hours: req.body.hours || '',
                notes: req.body.notes || ''
            };
            if (req.body.id) await controlModels().WaCarrier.findByIdAndUpdate(req.body.id, payload);
            else await controlModels().WaCarrier.create({ ...payload, key: String(req.body.name || 'carrier').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40) });
            req.session.success = 'Transportadora guardada. No se inventaron tarifas.';
            return back(res, 'transportadoras');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/ia', requirePermission('wa.ai.edit'), async (req, res, next) => {
        try {
            const snapshot = { ...DEFAULT_AI, ...req.body, allowAffectionate: req.body.allowAffectionate === 'true' };
            delete snapshot.action;
            if (req.body.action === 'publicar') {
                const draft = await service.saveAiDraft(snapshot, req.user);
                const published = await service.publishAi(draft.version, req.user);
                req.session[published.ok ? 'success' : 'error'] = published.ok ? `Configuración publicada, versión ${published.version}.` : published.message;
            } else {
                await service.saveAiDraft(snapshot, req.user);
                req.session.success = 'Borrador guardado. Todavía no está publicado.';
            }
            return back(res, 'ia');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/ia/restaurar', requirePermission('wa.ai.edit'), async (req, res, next) => {
        try {
            const result = await service.publishAi(req.body.version, req.user);
            req.session[result.ok ? 'success' : 'error'] = result.ok ? `Versión ${result.version} publicada de nuevo.` : result.message;
            return back(res, 'ia');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/reglas', requirePermission('wa.ai.edit'), async (req, res, next) => {
        try {
            const rule = await controlModels().WaRule.findById(req.body.id);
            if (!rule) {
                req.session.error = 'Regla no encontrada.';
                return back(res, 'reglas');
            }
            const before = rule.active;
            if (req.body.active != null) rule.active = req.body.active === 'true';
            if (req.body.priority != null) rule.priority = Number(req.body.priority) || 0;
            rule.history = rule.history || [];
            rule.history.push({ at: new Date(), by: req.user.username || req.user.email, change: `activo ${before} -> ${rule.active}` });
            await rule.save();
            req.session.success = 'Regla actualizada.';
            return back(res, 'reglas');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/plantillas', requirePermission('wa.ai.edit'), async (req, res, next) => {
        try {
            const { validateTemplate } = require('../lib/wa-control/templates');
            const check = validateTemplate(req.body.body || '');
            if (!check.ok) {
                req.session.error = `Plantilla inválida: ${check.unknown.join(', ')}`;
                return back(res, 'plantillas');
            }
            await controlModels().WaTemplate.updateOne({ key: req.body.key }, {
                $set: { body: req.body.body, name: req.body.name || req.body.key, author: req.user.username || req.user.email }
            });
            req.session.success = 'Plantilla guardada.';
            return back(res, 'plantillas');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/automatizaciones/:key', requirePermission('wa.ai.edit'), async (req, res, next) => {
        try {
            await controlModels().WaAutomation.updateOne({ key: req.params.key }, {
                $set: { enabled: req.body.enabled === 'true', intervalMinutes: Number(req.body.intervalMinutes) || 15 }
            });
            req.session.success = 'Automatización actualizada.';
            return back(res, 'automatizaciones');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/situaciones', requirePermission('wa.delivery'), async (req, res, next) => {
        try {
            await controlModels().WaSituation.create({
                title: req.body.title,
                description: req.body.description || '',
                category: req.body.category || 'otra',
                priority: Number(req.body.priority) || 0,
                startsAt: req.body.startsAt ? new Date(req.body.startsAt) : new Date(),
                endsAt: req.body.endsAt ? new Date(req.body.endsAt) : undefined,
                status: req.body.status || 'active',
                scope: req.body.scope || 'not_prepared',
                cities: String(req.body.cities || '').split(',').map((item) => item.trim()).filter(Boolean),
                methods: String(req.body.methods || '').split(',').map((item) => item.trim()).filter(Boolean),
                responseInstructions: req.body.responseInstructions || '',
                authorizedActions: String(req.body.actions || '').split(',').map((item) => item.trim()).filter(Boolean),
                responsible: req.user.username || req.user.email,
                history: [{ at: new Date(), by: req.user.username || req.user.email, change: 'creada' }]
            });
            req.session.success = 'Situación guardada.';
            return back(res, 'situaciones');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/situaciones/:id/avisar', requirePermission('wa.notify.bulk'), async (req, res, next) => {
        try {
            if (!req.body.token) {
                const preview = await service.previewBulk({ situationId: req.params.id, shippingMethod: req.body.shippingMethod }, req.body.text, req.user);
                if (!preview.ok) {
                    req.session.error = preview.message;
                    return back(res, 'situaciones');
                }
                return view(req, res, 'situaciones', { ...(await loadSection('situaciones', {})), bulk: preview }, { success: null, error: null });
            }
            const result = await service.confirmBulk(req.body.token, req.user);
            req.session[result.ok ? 'success' : 'error'] = result.ok ? `Avisos enviados: ${result.sent}. Fallidos: ${result.failed.length}.` : result.message;
            return back(res, 'situaciones');
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/simulador', requirePermission('wa.view'), async (req, res, next) => {
        try {
            const models = controlModels();
            const [rules, rates, situations, settings] = await Promise.all([
                models.WaRule.find({ active: true }).lean(),
                models.WaRate.find({ active: true }).lean(),
                models.WaSituation.find({ status: 'active' }).lean(),
                models.WaSettings.findOne({ key: 'main' }).lean()
            ]);
            const catalog = await mongoose.model('Product').find({ isForSale: true }).select('name price stock description').limit(8).lean();
            const result = service.simulateTurn({
                text: req.body.text,
                image: req.body.image === 'true',
                catalog,
                rules,
                rates,
                situations,
                settings,
                now: req.body.afterCutoff === 'true' ? new Date('2026-10-28T22:30:00Z') : new Date(),
                openPayment: req.body.hasLink === 'true' ? { payUrl: 'https://www.ferumi.shop/ejemplo' } : null
            });
            const data = await loadSection('simulador', {});
            data.result = result;
            return view(req, res, 'simulador', data, { success: 'Simulación terminada. No se envió nada ni se cobró.', error: null });
        } catch (err) { return next(err); }
    });

    app.post('/admin/whatsapp/permisos/:id', requirePermission('wa.users'), async (req, res, next) => {
        try {
            if (!ROLES.includes(req.body.role)) {
                req.session.error = 'Rol inválido.';
                return back(res, 'permisos');
            }
            const User = mongoose.model('AdminUser');
            if (req.body.role !== 'owner') {
                const owners = await User.countDocuments({
                    _id: { $ne: req.params.id },
                    $or: [{ role: 'owner' }, { role: { $exists: false } }, { role: null }]
                });
                const current = await User.findById(req.params.id).select('role');
                const currentRole = current?.role || 'owner';
                if (currentRole === 'owner' && owners === 0) {
                    req.session.error = 'Tiene que quedar al menos un propietario.';
                    return back(res, 'permisos');
                }
            }
            await User.updateOne({ _id: req.params.id }, { $set: { role: req.body.role } });
            req.session.success = 'Rol actualizado.';
            return back(res, 'permisos');
        } catch (err) { return next(err); }
    });
};
