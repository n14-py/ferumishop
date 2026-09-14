'use strict';

const videoBot = require('../lib/video-bot');
const scenes = require('../lib/video-scenes');

function requireVideoKey(req, res, next) {
    const expected = String(process.env.VIDEO_BOT_KEY || process.env.ADMIN_API_KEY || process.env.BOT_API_TOKEN || '').trim();
    if (!expected) {
        return res.status(503).json({ success: false, message: 'Falta VIDEO_BOT_KEY / BOT_API_TOKEN.' });
    }
    const got = String(req.get('x-api-key') || req.get('X-Bot-Token') || req.query.token || '').trim();
    if (!got || got !== expected) {
        return res.status(401).json({ success: false, message: 'Token inválido.' });
    }
    next();
}

function truthy(value) {
    return value === true || value === '1' || value === 'on' || value === 'true';
}

async function adminPageLocals(Product) {
    const dash = await videoBot.dashboard({ Product });
    const eligible = await videoBot.listEligibleProducts(Product, { limit: 80 });
    const jobs = await videoBot.VideoJob.find().sort({ createdAt: -1 }).limit(80);
    const logs = await videoBot.listLogs({ limit: 80 });
    const pings = dash.bot.ok ? await videoBot.pingBots() : [];
    return {
        pageTitle: 'Videos Shorts',
        eligible,
        jobs: jobs.map(videoBot.publicJob),
        logs,
        pings,
        settings: dash.settings,
        quota: dash.quota,
        gemmaOk: dash.gemma.ok,
        gemmaModel: dash.gemma.model,
        gemmaKeys: dash.gemma.keys,
        botUrl: dash.bot.url,
        botReady: dash.bot.ok,
        r2Ok: dash.r2.ok,
        r2Base: dash.r2.publicBase,
        scheduler: dash.scheduler,
        counts: dash.counts,
        buffer: dash.buffer || { ready: 0, limit: 15 },
        batchRunning: dash.scheduler.batchRunning || dash.scheduler.ticking
    };
}

function registerVideos(app, deps) {
    const { Product, SiteConfig, requireAdmin } = deps;
    const { VideoJob } = videoBot;

    app.get('/admin/videos', requireAdmin, async (req, res, next) => {
        try {
            const locals = await adminPageLocals(Product);
            locals.success = req.session.success;
            locals.error = req.session.error;
            res.render('admin/videos', locals);
            delete req.session.success;
            delete req.session.error;
        } catch (err) {
            next(err);
        }
    });

    app.get('/admin/videos/estado.json', requireAdmin, async (req, res, next) => {
        try {
            const dash = await videoBot.dashboard({ Product });
            const logs = await videoBot.listLogs({ limit: 40 });
            const jobs = await VideoJob.find().sort({ createdAt: -1 }).limit(40);
            res.json({
                success: true,
                ...dash,
                logs,
                jobs: jobs.map(videoBot.publicJob)
            });
        } catch (err) {
            next(err);
        }
    });

    app.post('/admin/videos/toggle', requireAdmin, async (req, res) => {
        try {
            const current = await videoBot.getSettings();
            const enabled = !current.enabled;
            await videoBot.saveSettings({ enabled });
            req.session.success = enabled
                ? 'Bot ENCENDIDO. Junta 15 JSON, insiste con Gemma y despacha solo cuando el VPS acepta.'
                : 'Bot APAGADO. No va a generar más JSON hasta que lo enciendas.';
        } catch (err) {
            req.session.error = err.message;
        }
        req.session.save(() => res.redirect('/admin/videos'));
    });

    app.post('/admin/videos/config', requireAdmin, async (req, res) => {
        try {
            const saved = await videoBot.saveSettings({
                dailyQuota: req.body.dailyQuota,
                keepDays: req.body.keepDays,
                autoDispatch: truthy(req.body.autoDispatch)
            });
            req.session.success = `Guardado: ${saved.dailyQuota} videos aceptados por día, se borran a los ${saved.keepDays} días.`;
        } catch (err) {
            req.session.error = err.message;
        }
        req.session.save(() => res.redirect('/admin/videos'));
    });

    app.post('/admin/videos/tick', requireAdmin, async (req, res) => {
        try {
            const out = await videoBot.runTick({ Product, SiteConfig, force: true });
            req.session.success = out.skipped
                ? `No corrió: ${out.reason}. ${out.purged ? `JSON viejos borrados: ${out.purged.purged}.` : ''}`
                : (out.dispatched?.sent
                    ? `El bot aceptó un JSON. Buffer ${out.ready || 0}/15. Cuota ${out.quota?.used || 0}/${out.quota?.quota || 0}.`
                    : (out.batch
                        ? `Buffer ${out.ready || 0}/15. Lote: ${out.batch.generated} JSON, ${out.batch.failed} errores. Despacho: ${out.dispatched?.reason || 'no'}.`
                        : (out.error || 'Tick listo.')));
            if (out.error) req.session.error = out.error;
        } catch (err) {
            req.session.error = err.message;
        }
        req.session.save(() => res.redirect('/admin/videos'));
    });

    app.post('/admin/videos/purgar', requireAdmin, async (req, res) => {
        try {
            const out = await videoBot.purgeOldJson();
            req.session.success = out.purged
                ? `Se borraron ${out.purged} JSON de más de ${out.keepDays} día(s).`
                : `No había JSON viejos para borrar (se guardan ${out.keepDays} días).`;
        } catch (err) {
            req.session.error = err.message;
        }
        req.session.save(() => res.redirect('/admin/videos'));
    });

    app.post('/admin/videos/generar', requireAdmin, async (req, res, next) => {
        try {
            const productId = String(req.body.productId || '').trim();
            const count = videoBot.clampBatch(req.body.count || videoBot.TICK_CHUNK);
            const settings = videoBot.publicSettings(await videoBot.getSettings());
            const dispatch = truthy(req.body.dispatch) || (settings.autoDispatch && videoBot.botConfig().ok);
            if (productId) {
                const out = await videoBot.generateForProduct({
                    Product, SiteConfig, productId, dispatch, source: 'admin'
                });
                req.session.success = out.skipped
                    ? `No se pudo armar el video de ${out.job.productName}: ${out.job.error}`
                    : `JSON listo para ${out.job.productName} (${out.payload.scenes.length} escenas).`;
                return req.session.save(() => res.redirect(`/admin/videos?ver=${out.job._id}`));
            }
            const state = videoBot.schedulerState();
            if (state.batchRunning || state.ticking) {
                req.session.error = 'Ya hay un lote de Gemma en curso. Esperá que termine y recargá.';
                return req.session.save(() => res.redirect('/admin/videos'));
            }
            setImmediate(() => {
                videoBot.generateBatch({ Product, SiteConfig, count, dispatch, source: 'admin' })
                    .then((batch) => {
                        console.log(`[videos] Lote listo: ${batch.generated} JSON, ${batch.failed} errores.`);
                    })
                    .catch((err) => console.error('[videos] Lote falló:', err.message));
            });
            req.session.success = `Gemma arrancó un lote de ${count} videos. Recargá esta página para ver logs y JSON.`;
            req.session.save(() => res.redirect('/admin/videos'));
        } catch (err) {
            req.session.error = err.message;
            req.session.save(() => res.redirect('/admin/videos'));
        }
    });

    app.get('/admin/videos/:id.json', requireAdmin, async (req, res, next) => {
        try {
            const job = await VideoJob.findById(req.params.id);
            if (!job) return res.status(404).json({ success: false, message: 'Trabajo no encontrado' });
            if (!job.escenasJSON) {
                return res.json({
                    error: job.error || 'Sin JSON. Ya se borró automáticamente o todavía no se generó.',
                    jsonPurgedAt: job.jsonPurgedAt,
                    status: job.status,
                    videoUrlsUsed: job.videoUrlsUsed || []
                });
            }
            res.json(job.escenasJSON);
        } catch (err) {
            next(err);
        }
    });

    app.post('/admin/videos/:id/enviar', requireAdmin, async (req, res, next) => {
        try {
            const job = await VideoJob.findById(req.params.id);
            if (!job) throw new Error('Trabajo no encontrado.');
            const sent = await videoBot.dispatchJob(job);
            req.session.success = sent.sent
                ? `JSON enviado al VPS ${sent.url}`
                : `JSON no enviado: ${sent.reason}. Quedó guardado para cuando el bot esté vivo.`;
            req.session.save(() => res.redirect('/admin/videos'));
        } catch (err) {
            req.session.error = err.message;
            req.session.save(() => res.redirect('/admin/videos'));
        }
    });

    app.post('/admin/videos/:id/regenerar', requireAdmin, async (req, res) => {
        try {
            const old = await VideoJob.findById(req.params.id);
            if (!old) throw new Error('Trabajo no encontrado.');
            const settings = videoBot.publicSettings(await videoBot.getSettings());
            const out = await videoBot.generateForProduct({
                Product,
                SiteConfig,
                productId: old.product,
                dispatch: settings.autoDispatch && videoBot.botConfig().ok,
                source: 'admin'
            });
            req.session.success = `JSON regenerado para ${out.job.productName}.`;
        } catch (err) {
            req.session.error = err.message;
        }
        req.session.save(() => res.redirect('/admin/videos'));
    });

    app.get('/api/bot/videos/elegibles', requireVideoKey, async (req, res, next) => {
        try {
            const eligible = await videoBot.listEligibleProducts(Product, { limit: 80 });
            res.json({
                success: true,
                count: eligible.length,
                products: eligible.map((p) => ({
                    ...scenes.productBrief(p),
                    videos: scenes.usableVideos(p).map((v) => ({ url: v.url, key: v.key || '', originalName: v.originalName || '' }))
                }))
            });
        } catch (err) {
            next(err);
        }
    });

    app.post('/api/bot/videos/generar', requireVideoKey, async (req, res, next) => {
        try {
            const productId = String(req.body.productId || '').trim();
            const dispatch = req.body.dispatch !== false;
            if (productId) {
                const out = await videoBot.generateForProduct({
                    Product, SiteConfig, productId, dispatch, source: 'api'
                });
                return res.json({
                    success: true,
                    skipped: Boolean(out.skipped),
                    job: videoBot.publicJob(out.job),
                    json: out.payload || out.job.escenasJSON
                });
            }
            const count = videoBot.clampBatch(req.body.count || videoBot.TICK_CHUNK);
            const batch = await videoBot.generateBatch({
                Product, SiteConfig, count, dispatch, source: 'api'
            });
            res.json({ success: true, ...batch });
        } catch (err) {
            next(err);
        }
    });

    app.get('/api/bot/videos/:id', requireVideoKey, async (req, res, next) => {
        try {
            const job = await VideoJob.findById(req.params.id);
            if (!job) return res.status(404).json({ success: false, message: 'Trabajo no encontrado' });
            res.json({ success: true, job: videoBot.publicJob(job), json: job.escenasJSON });
        } catch (err) {
            next(err);
        }
    });

    async function onVideoComplete(req, res, next) {
        try {
            const id = req.body.articleId || req.body.article_id || req.body.jobId;
            const job = await videoBot.markComplete(id, {
                youtubeId: req.body.youtubeId,
                videoUrl: req.body.videoUrl
            });
            if (!job) return res.status(404).json({ success: false, message: 'Trabajo no encontrado' });
            res.json({ success: true, job: videoBot.publicJob(job) });
        } catch (err) {
            next(err);
        }
    }

    async function onVideoFailed(req, res, next) {
        try {
            const id = req.body.articleId || req.body.article_id || req.body.jobId;
            const job = await videoBot.markComplete(id, { error: req.body.error || 'video_failed' });
            if (!job) return res.status(404).json({ success: false, message: 'Trabajo no encontrado' });
            res.json({ success: true, job: videoBot.publicJob(job) });
        } catch (err) {
            next(err);
        }
    }

    // ferumishopvideos notifica /api/articles/* (mismo contrato que Noticias LAT).
    app.post('/api/videos/video_complete', requireVideoKey, onVideoComplete);
    app.post('/api/articles/video_complete', requireVideoKey, onVideoComplete);
    app.post('/api/videos/video_failed', requireVideoKey, onVideoFailed);
    app.post('/api/articles/video_failed', requireVideoKey, onVideoFailed);
}

module.exports = registerVideos;
module.exports.requireVideoKey = requireVideoKey;
