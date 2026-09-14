'use strict';

const mongoose = require('mongoose');
const scenes = require('./video-scenes');
const gemma = require('./gemma');
const r2 = require('./r2');
const shop = require('./orders');

const STATUSES = [
    'pending',
    'json_ready',
    'sending',
    'processing',
    'completed',
    'failed',
    'skipped_nostock',
    'skipped_novideo'
];

const COUNTED_STATUSES = ['pending', 'json_ready', 'sending', 'processing', 'completed'];
const DEFAULT_DAILY_QUOTA = 50;
const DEFAULT_KEEP_DAYS = 2;
const BATCH_HARD_MAX = 80;
const TICK_MS = 10 * 60 * 1000;
const TICK_CHUNK = 5;
const MEMORY_LOG_MAX = 150;

function jobSchema() {
    return new mongoose.Schema({
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
        productName: { type: String, default: '' },
        categoryName: { type: String, default: '' },
        status: { type: String, enum: STATUSES, default: 'pending' },
        escenasJSON: { type: mongoose.Schema.Types.Mixed, default: null },
        youtubeTitle: { type: String, default: '' },
        youtubeId: { type: String, default: '' },
        generatedVideoUrl: { type: String, default: '' },
        error: { type: String, default: '' },
        stockSnapshot: { type: Number, default: 0 },
        videoUrlsUsed: [{ type: String }],
        dispatchedTo: { type: String, default: '' },
        dispatchedAt: { type: Date },
        completedAt: { type: Date },
        jsonPurgedAt: { type: Date },
        source: { type: String, default: 'manual' }
    }, { timestamps: true });
}

function settingsSchema() {
    return new mongoose.Schema({
        key: { type: String, default: 'main', unique: true },
        enabled: { type: Boolean, default: true },
        dailyQuota: { type: Number, default: DEFAULT_DAILY_QUOTA },
        keepDays: { type: Number, default: DEFAULT_KEEP_DAYS },
        autoDispatch: { type: Boolean, default: true },
        lastTickAt: { type: Date },
        lastTickResult: { type: String, default: '' },
        lastError: { type: String, default: '' }
    }, { timestamps: true });
}

function logSchema() {
    return new mongoose.Schema({
        level: { type: String, enum: ['info', 'warn', 'error'], default: 'info' },
        event: { type: String, default: '' },
        message: { type: String, default: '' },
        productName: { type: String, default: '' },
        jobId: { type: String, default: '' },
        meta: { type: mongoose.Schema.Types.Mixed, default: null }
    }, { timestamps: true });
}

const VideoJob = mongoose.models.VideoJob || mongoose.model('VideoJob', jobSchema());
const VideoBotSettings = mongoose.models.VideoBotSettings || mongoose.model('VideoBotSettings', settingsSchema());
const VideoLog = mongoose.models.VideoLog || mongoose.model('VideoLog', logSchema());

const memoryLogs = [];
const scheduler = {
    started: false,
    timer: null,
    ticking: false,
    batchRunning: false,
    lastTick: null
};

function botConfig() {
    const urls = String(process.env.VIDEO_BOT_URL || process.env.VIDEO_BOT_URLS || '')
        .split(',')
        .map((u) => u.trim().replace(/\/$/, ''))
        .filter(Boolean);
    const key = String(process.env.VIDEO_BOT_KEY || process.env.ADMIN_API_KEY || process.env.BOT_API_TOKEN || '').trim();
    return {
        urls,
        key,
        ok: urls.length > 0
    };
}

function clampBatch(n, fallback = TICK_CHUNK) {
    const num = Number(n);
    if (!Number.isFinite(num) || num <= 0) return fallback;
    return Math.min(BATCH_HARD_MAX, Math.max(1, Math.round(num)));
}

function clampQuota(n) {
    const num = Number(n);
    if (!Number.isFinite(num) || num <= 0) return DEFAULT_DAILY_QUOTA;
    return Math.min(200, Math.max(1, Math.round(num)));
}

function clampKeepDays(n) {
    const num = Number(n);
    if (!Number.isFinite(num) || num <= 0) return DEFAULT_KEEP_DAYS;
    return Math.min(14, Math.max(1, Math.round(num)));
}

function publicSettings(doc) {
    return {
        enabled: doc?.enabled !== false,
        dailyQuota: clampQuota(doc?.dailyQuota),
        keepDays: clampKeepDays(doc?.keepDays),
        autoDispatch: doc?.autoDispatch !== false,
        lastTickAt: doc?.lastTickAt || null,
        lastTickResult: doc?.lastTickResult || '',
        lastError: doc?.lastError || ''
    };
}

async function getSettings() {
    let doc = await VideoBotSettings.findOne({ key: 'main' });
    if (!doc) doc = await VideoBotSettings.create({ key: 'main' });
    return doc;
}

async function saveSettings(patch = {}) {
    const doc = await getSettings();
    if (patch.enabled !== undefined) doc.enabled = Boolean(patch.enabled);
    if (patch.dailyQuota !== undefined) doc.dailyQuota = clampQuota(patch.dailyQuota);
    if (patch.keepDays !== undefined) doc.keepDays = clampKeepDays(patch.keepDays);
    if (patch.autoDispatch !== undefined) doc.autoDispatch = Boolean(patch.autoDispatch);
    await doc.save();
    await logEvent({
        level: 'info',
        event: 'settings',
        message: `Config: ${doc.enabled ? 'ENCENDIDO' : 'APAGADO'} · ${doc.dailyQuota} JSON/día · borrar a los ${doc.keepDays} días · envío VPS ${doc.autoDispatch ? 'sí' : 'no'}`
    });
    return doc;
}

function rememberLog(entry) {
    memoryLogs.unshift(entry);
    if (memoryLogs.length > MEMORY_LOG_MAX) memoryLogs.pop();
}

async function logEvent({ level = 'info', event = '', message = '', productName = '', jobId = '', meta = null } = {}) {
    const entry = {
        level,
        event,
        message: String(message || '').slice(0, 2000),
        productName: String(productName || ''),
        jobId: String(jobId || ''),
        meta,
        createdAt: new Date()
    };
    rememberLog(entry);
    const line = `[videos][${level}] ${event || 'log'} ${entry.message}`.trim();
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
    try {
        await VideoLog.create(entry);
    } catch (err) {
        console.warn('[videos] No se pudo guardar el log:', err.message);
    }
    return entry;
}

async function listLogs({ limit = 80 } = {}) {
    try {
        const docs = await VideoLog.find().sort({ createdAt: -1 }).limit(limit).lean();
        if (docs.length) return docs;
    } catch {
        // fall through to memory
    }
    return memoryLogs.slice(0, limit);
}

function startOfAsuncionDay(now = new Date()) {
    return shop.paraguayDayBounds(now).start;
}

async function countToday() {
    return VideoJob.countDocuments({
        createdAt: { $gte: startOfAsuncionDay() },
        status: { $in: COUNTED_STATUSES }
    });
}

async function remainingToday(settings) {
    const quota = clampQuota(settings?.dailyQuota);
    const used = await countToday();
    return { quota, used, remaining: Math.max(0, quota - used) };
}

async function videoUrlAlive(url) {
    if (!url) return false;
    try {
        const head = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(8000) });
        if (head.ok) return true;
        if (head.status === 403 || head.status === 405 || head.status === 400) {
            const get = await fetch(url, {
                method: 'GET',
                headers: { Range: 'bytes=0-1' },
                signal: AbortSignal.timeout(8000)
            });
            return get.ok || get.status === 206;
        }
        return false;
    } catch {
        return false;
    }
}

async function verifyProductVideos(product, { maxCheck = 12 } = {}) {
    const shuffled = scenes.shuffleArray(scenes.usableVideos(product));
    if (!shuffled.length) return [];
    const toCheck = shuffled.slice(0, Math.min(shuffled.length, Math.max(1, maxCheck)));
    const alive = [];
    for (const video of toCheck) {
        const ok = await videoUrlAlive(video.url);
        if (ok) alive.push(video);
        else console.warn(`[videos] Clip R2 caído: ${video.url}`);
    }
    return scenes.shuffleArray(alive);
}

function eligibleQuery() {
    return {
        isForSale: { $ne: false },
        $or: [
            { hasVariants: true, 'variants.stock': { $gt: 0 } },
            { hasVariants: { $ne: true }, stock: { $gt: 0 } }
        ],
        videos: { $elemMatch: { url: { $regex: /^https?:\/\// } } }
    };
}

async function listEligibleProducts(Product, { limit = 80 } = {}) {
    const found = await Product.find(eligibleQuery())
        .populate('category')
        .sort({ isFeatured: -1, views: -1, updatedAt: -1 })
        .limit(limit);
    return found.filter((p) => scenes.isEligibleProduct(p));
}

async function pickProducts(Product, { count = TICK_CHUNK, excludeIds = [] } = {}) {
    const wanted = clampBatch(count);
    const candidates = scenes.shuffleArray(await listEligibleProducts(Product, { limit: 200 }));
    const exclude = new Set((excludeIds || []).map(String));
    const picked = [];

    for (const product of candidates) {
        if (picked.length >= wanted) break;
        if (exclude.has(String(product._id))) continue;

        const stock = scenes.productStock(product);
        if (stock <= 0) continue;

        const alive = await verifyProductVideos(product);
        if (!alive.length) continue;
        product.videos = alive;
        picked.push(product);
    }
    return picked;
}

async function recentProductIds(sinceHours = 48) {
    const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000);
    const jobs = await VideoJob.find({
        createdAt: { $gte: since },
        status: { $in: COUNTED_STATUSES }
    }).select('product').lean();
    return jobs.map((j) => String(j.product));
}

async function generateForProduct({ Product, SiteConfig, product, productId, dispatch = false, source = 'manual' }) {
    const doc = product || await Product.findById(productId).populate('category');
    if (!doc) throw new Error('Producto no encontrado.');

    const stock = scenes.productStock(doc);
    if (stock <= 0) {
        const job = await VideoJob.create({
            product: doc._id,
            productName: doc.name,
            categoryName: doc.category?.name || '',
            status: 'skipped_nostock',
            stockSnapshot: stock,
            error: 'Sin stock.',
            source
        });
        await logEvent({
            level: 'warn',
            event: 'skipped_nostock',
            message: `${doc.name} no tiene stock.`,
            productName: doc.name,
            jobId: String(job._id)
        });
        return { job, skipped: true };
    }

    const alive = await verifyProductVideos(doc);
    if (!alive.length) {
        const job = await VideoJob.create({
            product: doc._id,
            productName: doc.name,
            categoryName: doc.category?.name || '',
            status: 'skipped_novideo',
            stockSnapshot: stock,
            error: 'No hay clips vivos en Cloudflare R2.',
            source
        });
        await logEvent({
            level: 'warn',
            event: 'skipped_novideo',
            message: `${doc.name} no tiene clips R2 vivos.`,
            productName: doc.name,
            jobId: String(job._id)
        });
        return { job, skipped: true };
    }
    doc.videos = alive;

    const siteConfig = await SiteConfig.findOne({ configKey: 'main_config' }).lean();
    const job = await VideoJob.create({
        product: doc._id,
        productName: doc.name,
        categoryName: doc.category?.name || '',
        status: 'pending',
        stockSnapshot: stock,
        source
    });

    try {
        const payload = await scenes.generateProductVideoScenesJSON(doc, siteConfig, { jobId: job._id });
        job.escenasJSON = payload;
        job.youtubeTitle = payload.youtube_title;
        job.videoUrlsUsed = payload.video_urls_used || alive.map((v) => v.url);
        job.status = 'json_ready';
        await job.save();
        await logEvent({
            level: 'info',
            event: 'json_ready',
            message: `JSON listo para ${doc.name}: ${payload.scenes.length} escenas, clips ${job.videoUrlsUsed.length}.`,
            productName: doc.name,
            jobId: String(job._id),
            meta: { videos: job.videoUrlsUsed, sceneCount: payload.scenes.length }
        });

        if (dispatch) {
            await dispatchJob(job);
        }
        return { job, skipped: false, payload };
    } catch (err) {
        job.status = 'failed';
        job.error = err.message || String(err);
        await job.save();
        await logEvent({
            level: 'error',
            event: 'json_failed',
            message: `${doc.name}: ${job.error}`,
            productName: doc.name,
            jobId: String(job._id)
        });
        throw err;
    }
}

async function generateBatch({ Product, SiteConfig, count = TICK_CHUNK, dispatch = false, source = 'manual' }) {
    if (scheduler.batchRunning) {
        return { requested: 0, generated: 0, skipped: 0, failed: 0, results: [], busy: true };
    }
    scheduler.batchRunning = true;
    try {
        const settings = await getSettings();
        const hours = clampKeepDays(settings.keepDays) * 24;
        const recent = await recentProductIds(hours);
        const products = await pickProducts(Product, { count, excludeIds: recent });
        const results = [];
        if (!products.length) {
            await logEvent({
                level: 'warn',
                event: 'no_products',
                message: 'No hay productos con stock + video R2 vivo que no se hayan usado recién.'
            });
        }
        for (const product of products) {
            try {
                const out = await generateForProduct({ Product, SiteConfig, product, dispatch, source });
                results.push({
                    ok: true,
                    skipped: Boolean(out.skipped),
                    jobId: String(out.job._id),
                    productId: String(product._id),
                    productName: product.name,
                    status: out.job.status
                });
            } catch (err) {
                results.push({
                    ok: false,
                    productId: String(product._id),
                    productName: product.name,
                    error: err.message
                });
            }
        }
        return {
            requested: clampBatch(count),
            generated: results.filter((r) => r.ok && !r.skipped).length,
            skipped: results.filter((r) => r.skipped).length,
            failed: results.filter((r) => !r.ok).length,
            results
        };
    } finally {
        scheduler.batchRunning = false;
    }
}

async function wakeBot(url) {
    try {
        await fetch(url, { method: 'GET', signal: AbortSignal.timeout(4000) });
        return true;
    } catch (err) {
        if (String(err.message || '').includes('429')) return true;
        return false;
    }
}

async function pingBots() {
    const cfg = botConfig();
    const results = [];
    for (const url of cfg.urls) {
        const started = Date.now();
        try {
            const response = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(5000) });
            results.push({
                url,
                ok: response.status < 500,
                status: response.status,
                ms: Date.now() - started
            });
        } catch (err) {
            results.push({
                url,
                ok: false,
                status: 0,
                ms: Date.now() - started,
                error: err.message || String(err)
            });
        }
    }
    return results;
}

async function dispatchJob(job) {
    const cfg = botConfig();
    if (!cfg.ok) {
        job.status = 'json_ready';
        job.error = 'VIDEO_BOT_URL todavía no está configurada. JSON listo para cuando el VPS viva.';
        await job.save();
        await logEvent({
            level: 'warn',
            event: 'no_vps',
            message: job.error,
            productName: job.productName,
            jobId: String(job._id)
        });
        return { sent: false, reason: 'no_url', job };
    }
    if (!job.escenasJSON?.scenes?.length) {
        throw new Error('El trabajo no tiene JSON de escenas.');
    }

    const payload = { ...job.escenasJSON, article_id: String(job._id) };
    job.status = 'sending';
    await job.save();

    let lastError = 'Ningún bot aceptó el video.';
    for (const url of cfg.urls) {
        try {
            await wakeBot(url);
            console.log(`[VideoBot] Enviando ${payload.scenes.length} escenas a ${url} (job ${job._id})...`);
            const response = await fetch(`${url}/generate_video`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': cfg.key
                },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(15000)
            });
            if (response.status === 200 || response.status === 202) {
                job.status = 'processing';
                job.dispatchedTo = url;
                job.dispatchedAt = new Date();
                job.error = '';
                await job.save();
                await logEvent({
                    level: 'info',
                    event: 'sent_vps',
                    message: `Enviado a ${url} (${payload.scenes.length} escenas).`,
                    productName: job.productName,
                    jobId: String(job._id)
                });
                return { sent: true, url, job };
            }
            lastError = `Bot ${url} respondió ${response.status}`;
        } catch (err) {
            lastError = err.message || String(err);
            console.warn(`[VideoBot] Fallo en ${url}: ${lastError}`);
        }
    }

    job.status = 'json_ready';
    job.error = lastError;
    await job.save();
    await logEvent({
        level: 'error',
        event: 'dispatch_failed',
        message: lastError,
        productName: job.productName,
        jobId: String(job._id)
    });
    return { sent: false, reason: lastError, job };
}

async function markComplete(jobId, { youtubeId, videoUrl, error } = {}) {
    const job = await VideoJob.findById(jobId);
    if (!job) return null;
    if (error) {
        job.status = 'failed';
        job.error = error;
        await logEvent({
            level: 'error',
            event: 'video_failed',
            message: error,
            productName: job.productName,
            jobId: String(job._id)
        });
    } else {
        job.status = 'completed';
        job.youtubeId = youtubeId || job.youtubeId;
        job.generatedVideoUrl = videoUrl || job.generatedVideoUrl;
        job.completedAt = new Date();
        job.error = '';
        await logEvent({
            level: 'info',
            event: 'video_complete',
            message: `Video listo${job.youtubeId ? ` · YouTube ${job.youtubeId}` : ''}.`,
            productName: job.productName,
            jobId: String(job._id)
        });
    }
    await job.save();
    return job;
}

async function purgeOldJson({ keepDays } = {}) {
    const settings = keepDays ? { keepDays } : await getSettings();
    const days = clampKeepDays(settings.keepDays);
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const old = await VideoJob.find({
        createdAt: { $lt: cutoff },
        escenasJSON: { $ne: null }
    }).limit(200);
    let purged = 0;
    for (const job of old) {
        job.escenasJSON = null;
        job.jsonPurgedAt = new Date();
        await job.save();
        purged += 1;
    }
    try {
        await VideoLog.deleteMany({ createdAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } });
    } catch {
        // ignore
    }
    if (purged) {
        await logEvent({
            level: 'info',
            event: 'json_purged',
            message: `Se borraron ${purged} JSON de más de ${days} día(s) para dejar lugar a videos nuevos.`
        });
    }
    return { purged, keepDays: days };
}

function publicJob(job) {
    const json = job.escenasJSON || null;
    return {
        id: String(job._id),
        productId: String(job.product?._id || job.product || ''),
        productName: job.productName,
        categoryName: job.categoryName,
        status: job.status,
        youtubeTitle: job.youtubeTitle,
        youtubeId: job.youtubeId,
        generatedVideoUrl: job.generatedVideoUrl,
        error: job.error,
        stockSnapshot: job.stockSnapshot,
        videoUrlsUsed: job.videoUrlsUsed || [],
        dispatchedTo: job.dispatchedTo,
        dispatchedAt: job.dispatchedAt,
        completedAt: job.completedAt,
        createdAt: job.createdAt,
        source: job.source || 'manual',
        jsonPurgedAt: job.jsonPurgedAt || null,
        hasJson: Boolean(json && json.scenes),
        metrics: json?.metrics || null,
        sceneCount: json?.scenes?.length || 0
    };
}

async function statusCounts() {
    const rows = await VideoJob.aggregate([
        { $group: { _id: '$status', n: { $sum: 1 } } }
    ]);
    const out = {};
    STATUSES.forEach((s) => { out[s] = 0; });
    rows.forEach((r) => { out[r._id] = r.n; });
    return out;
}

async function dashboard({ Product } = {}) {
    const settings = publicSettings(await getSettings());
    const quota = await remainingToday(settings);
    const gemmaCfg = gemma.config();
    const botCfg = botConfig();
    const r2Cfg = r2.r2Config();
    let eligibleCount = 0;
    if (Product) {
        eligibleCount = (await listEligibleProducts(Product, { limit: 200 })).length;
    }
    return {
        settings,
        quota,
        gemma: {
            ok: gemmaCfg.ok,
            model: gemmaCfg.model,
            keys: gemmaCfg.keyCount
        },
        bot: {
            ok: botCfg.ok,
            urls: botCfg.urls,
            url: botCfg.urls[0] || ''
        },
        r2: { ok: r2Cfg.ok, publicBase: r2Cfg.publicBase || '' },
        eligibleCount,
        scheduler: {
            started: scheduler.started,
            ticking: scheduler.ticking,
            batchRunning: scheduler.batchRunning,
            lastTick: scheduler.lastTick
        },
        counts: await statusCounts()
    };
}

async function runTick({ Product, SiteConfig, force = false } = {}) {
    if (scheduler.ticking) {
        return { skipped: true, reason: 'already_running' };
    }
    scheduler.ticking = true;
    const settingsDoc = await getSettings();
    const settings = publicSettings(settingsDoc);
    try {
        const purged = await purgeOldJson({ keepDays: settings.keepDays });
        if (!settings.enabled && !force) {
            const result = 'Bot apagado. No se generan JSON.';
            settingsDoc.lastTickAt = new Date();
            settingsDoc.lastTickResult = result;
            await settingsDoc.save();
            scheduler.lastTick = { at: settingsDoc.lastTickAt, result, skipped: true };
            return { skipped: true, reason: 'off', purged };
        }
        if (!gemma.config().ok) {
            const result = 'Falta GEMINI_API_KEY. Gemma no puede armar el JSON.';
            settingsDoc.lastTickAt = new Date();
            settingsDoc.lastTickResult = result;
            settingsDoc.lastError = result;
            await settingsDoc.save();
            await logEvent({ level: 'error', event: 'tick', message: result });
            scheduler.lastTick = { at: settingsDoc.lastTickAt, result, skipped: true };
            return { skipped: true, reason: 'no_gemma', purged };
        }

        const quota = await remainingToday(settings);
        if (quota.remaining <= 0 && !force) {
            const result = `Cuota del día completa: ${quota.used}/${quota.quota} JSON.`;
            settingsDoc.lastTickAt = new Date();
            settingsDoc.lastTickResult = result;
            settingsDoc.lastError = '';
            await settingsDoc.save();
            scheduler.lastTick = { at: settingsDoc.lastTickAt, result, skipped: true };
            return { skipped: true, reason: 'quota', quota, purged };
        }

        const want = force ? Math.min(TICK_CHUNK, settings.dailyQuota) : Math.min(TICK_CHUNK, quota.remaining);
        const dispatch = settings.autoDispatch && botConfig().ok;
        await logEvent({
            level: 'info',
            event: 'tick',
            message: `Arranca lote automático de ${want} (hoy ${quota.used}/${quota.quota}, envío VPS ${dispatch ? 'sí' : 'no'}).`
        });
        const batch = await generateBatch({
            Product,
            SiteConfig,
            count: want,
            dispatch,
            source: force ? 'admin' : 'scheduler'
        });
        const result = `Lote: ${batch.generated} JSON, ${batch.skipped} saltados, ${batch.failed} errores. Hoy ${quota.used + batch.generated}/${quota.quota}.`;
        settingsDoc.lastTickAt = new Date();
        settingsDoc.lastTickResult = result;
        settingsDoc.lastError = batch.failed ? `${batch.failed} JSON fallaron en el lote.` : '';
        await settingsDoc.save();
        scheduler.lastTick = { at: settingsDoc.lastTickAt, result, batch };
        await logEvent({
            level: batch.failed ? 'warn' : 'info',
            event: 'tick_done',
            message: result
        });
        return { skipped: false, batch, quota, purged };
    } catch (err) {
        const result = err.message || String(err);
        settingsDoc.lastTickAt = new Date();
        settingsDoc.lastTickResult = result;
        settingsDoc.lastError = result;
        await settingsDoc.save();
        await logEvent({ level: 'error', event: 'tick_error', message: result });
        scheduler.lastTick = { at: settingsDoc.lastTickAt, result, error: result };
        return { skipped: false, error: result };
    } finally {
        scheduler.ticking = false;
    }
}

function startScheduler(deps) {
    if (scheduler.started) return scheduler;
    scheduler.started = true;
    const first = setTimeout(() => {
        runTick(deps).catch((err) => console.error('[videos] primer tick:', err.message));
    }, 20 * 1000);
    scheduler.timer = setInterval(() => {
        runTick(deps).catch((err) => console.error('[videos] tick:', err.message));
    }, TICK_MS);
    if (typeof scheduler.timer.unref === 'function') scheduler.timer.unref();
    if (typeof first.unref === 'function') first.unref();
    console.log(`[videos] Scheduler automático cada ${TICK_MS / 60000} min · cuota diaria ${DEFAULT_DAILY_QUOTA} JSON.`);
    logEvent({
        level: 'info',
        event: 'scheduler_start',
        message: `Bot de Shorts en marcha. Revisa cada ${TICK_MS / 60000} min y apunta a ${DEFAULT_DAILY_QUOTA} JSON por día (se puede cambiar en el admin).`
    }).catch(() => {});
    return scheduler;
}

function stopScheduler() {
    if (scheduler.timer) clearInterval(scheduler.timer);
    scheduler.timer = null;
    scheduler.started = false;
}

function schedulerState() {
    return {
        started: scheduler.started,
        ticking: scheduler.ticking,
        batchRunning: scheduler.batchRunning,
        lastTick: scheduler.lastTick
    };
}

module.exports = {
    VideoJob,
    VideoLog,
    VideoBotSettings,
    STATUSES,
    COUNTED_STATUSES,
    DEFAULT_DAILY_QUOTA,
    DEFAULT_KEEP_DAYS,
    TICK_MS,
    TICK_CHUNK,
    botConfig,
    clampBatch,
    clampQuota,
    clampKeepDays,
    getSettings,
    saveSettings,
    publicSettings,
    logEvent,
    listLogs,
    startOfAsuncionDay,
    countToday,
    remainingToday,
    videoUrlAlive,
    verifyProductVideos,
    eligibleQuery,
    listEligibleProducts,
    pickProducts,
    generateForProduct,
    generateBatch,
    dispatchJob,
    markComplete,
    publicJob,
    purgeOldJson,
    pingBots,
    dashboard,
    runTick,
    startScheduler,
    stopScheduler,
    schedulerState,
    gemmaReady: () => gemma.config().ok
};
