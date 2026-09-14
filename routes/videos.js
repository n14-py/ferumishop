'use strict';

const videoBot = require('../lib/video-bot');
const gemma = require('../lib/gemma');
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

let batchRunning = false;

function registerVideos(app, deps) {
    const { Product, SiteConfig, requireAdmin } = deps;
    const { VideoJob } = videoBot;

    app.get('/admin/videos', requireAdmin, async (req, res, next) => {
        try {
            const eligible = await videoBot.listEligibleProducts(Product, { limit: 60 });
            const jobs = await VideoJob.find().sort({ createdAt: -1 }).limit(40);
            const gemmaCfg = gemma.config();
            const botCfg = videoBot.botConfig();
            res.render('admin/videos', {
                pageTitle: 'Videos Shorts',
                eligible,
                jobs: jobs.map(videoBot.publicJob),
                gemmaOk: gemmaCfg.ok,
                gemmaModel: gemmaCfg.model,
                gemmaKeys: gemmaCfg.keyCount,
                botUrl: botCfg.urls[0] || '',
                botReady: botCfg.ok,
                batchRunning,
                success: req.session.success,
                error: req.session.error
            });
            delete req.session.success;
            delete req.session.error;
        } catch (err) {
            next(err);
        }
    });

    app.post('/admin/videos/generar', requireAdmin, async (req, res, next) => {
        try {
            const productId = String(req.body.productId || '').trim();
            const count = videoBot.clampBatch(req.body.count || 20);
            const dispatch = req.body.dispatch === '1' || req.body.dispatch === true;
            if (productId) {
                const out = await videoBot.generateForProduct({
                    Product, SiteConfig, productId, dispatch
                });
                req.session.success = out.skipped
                    ? `No se pudo armar el video de ${out.job.productName}: ${out.job.error}`
                    : `JSON listo para ${out.job.productName} (${out.payload.scenes.length} escenas).`;
                return req.session.save(() => res.redirect(`/admin/videos?ver=${out.job._id}`));
            }
            if (batchRunning) {
                req.session.error = 'Ya hay un lote de Gemma en curso. Esperá que termine.';
                return req.session.save(() => res.redirect('/admin/videos'));
            }
            batchRunning = true;
            setImmediate(() => {
                videoBot.generateBatch({ Product, SiteConfig, count, dispatch })
                    .then((batch) => {
                        console.log(`[videos] Lote listo: ${batch.generated} JSON, ${batch.failed} errores.`);
                    })
                    .catch((err) => console.error('[videos] Lote falló:', err.message))
                    .finally(() => { batchRunning = false; });
            });
            req.session.success = `Gemma arrancó un lote de ${count} videos. Cada uno tarda un rato. Recargá esta página para ver los JSON.`;
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
            res.json(job.escenasJSON || { error: job.error || 'Sin JSON todavía' });
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
            const out = await videoBot.generateForProduct({
                Product, SiteConfig, productId: old.product, dispatch: false
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
                const out = await videoBot.generateForProduct({ Product, SiteConfig, productId, dispatch });
                return res.json({
                    success: true,
                    skipped: Boolean(out.skipped),
                    job: videoBot.publicJob(out.job),
                    json: out.payload || out.job.escenasJSON
                });
            }
            const count = videoBot.clampBatch(req.body.count || 20);
            const batch = await videoBot.generateBatch({ Product, SiteConfig, count, dispatch });
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

    app.post('/api/videos/video_complete', requireVideoKey, async (req, res, next) => {
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
    });

    app.post('/api/videos/video_failed', requireVideoKey, async (req, res, next) => {
        try {
            const id = req.body.articleId || req.body.article_id || req.body.jobId;
            const job = await videoBot.markComplete(id, { error: req.body.error || 'video_failed' });
            if (!job) return res.status(404).json({ success: false, message: 'Trabajo no encontrado' });
            res.json({ success: true, job: videoBot.publicJob(job) });
        } catch (err) {
            next(err);
        }
    });
}

module.exports = registerVideos;
module.exports.requireVideoKey = requireVideoKey;
