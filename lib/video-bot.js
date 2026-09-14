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

const COUNTED_STATUSES = ['processing', 'completed'];
const READY_STATUSES = ['json_ready'];
const DEFAULT_DAILY_QUOTA = 50;
const DEFAULT_KEEP_DAYS = 2;
const BATCH_HARD_MAX = 80;
const BUFFER_SIZE_LIMIT = 15;
const JSON_ATTEMPTS = 5;
const DISPATCH_MS = 60 * 1000;
const GENERATE_PAUSE_MS = 2000;
const BUFFER_FULL_SLEEP_MS = 10 * 1000;
const ZOMBIE_MINUTES = 30;
const TICK_MS = DISPATCH_MS;
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
        jsonAttempts: { type: Number, default: 0 },
        dispatchAttempts: { type: Number, default: 0 },
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
    workerTimer: null,
    ticking: false,
    dispatching: false,
    batchRunning: false,
    lastTick: null,
    deps: null
};

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function botAccepted(status) {
    return status === 200 || status === 202;
}

function botBusy(status) {
    return status === 503 || status === 429;
}

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
        message: `Config: ${doc.enabled ? 'ENCENDIDO' : 'APAGADO'} · ${doc.dailyQuota} videos/día (cuando el bot acepta) · buffer ${BUFFER_SIZE_LIMIT} JSON · borrar a los ${doc.keepDays} días · envío VPS ${doc.autoDispatch ? 'sí' : 'no'}`
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
        dispatchedAt: { $gte: startOfAsuncionDay() }
    });
}

async function readyBufferCount() {
    return VideoJob.countDocuments({
        status: { $in: READY_STATUSES },
        'escenasJSON.scenes.0': { $exists: true }
    });
}

async function resetZombies({ forceAll = false } = {}) {
    const filtro = { status: { $in: ['processing', 'sending'] } };
    if (!forceAll) {
        filtro.updatedAt = { $lt: new Date(Date.now() - ZOMBIE_MINUTES * 60 * 1000) };
    }
    const result = await VideoJob.updateMany(filtro, {
        $set: {
            status: 'json_ready',
            error: 'El bot no contestó a tiempo. El JSON sigue listo y se reenvía solo.'
        }
    });
    const n = result.modifiedCount || 0;
    if (n) {
        await logEvent({
            level: 'warn',
            event: 'zombie',
            message: `Se liberaron ${n} video(s) colgado(s). El JSON queda en cola para reenviar.`
        });
    }
    return n;
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
    const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const jobs = await VideoJob.find({
        $or: [
            { createdAt: { $gte: since }, status: { $in: ['pending', 'json_ready', 'sending', 'processing', 'completed'] } },
            { createdAt: { $gte: hourAgo }, status: 'failed' }
        ]
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
        let lastError;
        for (let attempt = 1; attempt <= JSON_ATTEMPTS; attempt += 1) {
            try {
                const payload = await scenes.generateProductVideoScenesJSON(doc, siteConfig, { jobId: job._id });
                job.escenasJSON = payload;
                job.youtubeTitle = payload.youtube_title;
                job.videoUrlsUsed = payload.video_urls_used || alive.map((v) => v.url);
                job.status = 'json_ready';
                job.jsonAttempts = attempt;
                job.error = '';
                await job.save();
                await logEvent({
                    level: 'info',
                    event: 'json_ready',
                    message: `JSON listo para ${doc.name}: ${payload.scenes.length} escenas, clips ${job.videoUrlsUsed.length} (intento ${attempt}/${JSON_ATTEMPTS}).`,
                    productName: doc.name,
                    jobId: String(job._id),
                    meta: { videos: job.videoUrlsUsed, sceneCount: payload.scenes.length, attempt }
                });

                if (dispatch) {
                    await dispatchJob(job);
                }
                return { job, skipped: false, payload };
            } catch (err) {
                lastError = err;
                job.jsonAttempts = attempt;
                job.error = `Intento ${attempt}/${JSON_ATTEMPTS}: ${err.message || String(err)}`;
                await job.save();
                await logEvent({
                    level: 'warn',
                    event: 'json_retry',
                    message: `${doc.name}: Gemma falló (${attempt}/${JSON_ATTEMPTS}). ${job.error}`,
                    productName: doc.name,
                    jobId: String(job._id)
                });
                gemma.rotateKey();
                if (attempt < JSON_ATTEMPTS) await sleep(1500 * attempt);
            }
        }

        job.status = 'failed';
        job.error = lastError?.message || String(lastError || 'Gemma no armó JSON.');
        await job.save();
        await logEvent({
            level: 'error',
            event: 'json_failed',
            message: `${doc.name}: se cambia de producto después de ${JSON_ATTEMPTS} intentos. ${job.error}`,
            productName: doc.name,
            jobId: String(job._id)
        });
        return { job, skipped: true, failed: true };
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
        return { job, skipped: true, failed: true };
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
                const out = await generateForProduct({ Product, SiteConfig, product, dispatch: false, source });
                results.push({
                    ok: Boolean(out.ok !== false && !out.failed),
                    skipped: Boolean(out.skipped),
                    failed: Boolean(out.failed),
                    jobId: out.job ? String(out.job._id) : '',
                    productId: String(product._id),
                    productName: product.name,
                    status: out.job ? out.job.status : 'failed',
                    error: out.failed ? out.job.error : undefined
                });
            } catch (err) {
                results.push({
                    ok: false,
                    failed: true,
                    productId: String(product._id),
                    productName: product.name,
                    error: err.message
                });
            }
        }
        if (dispatch) {
            await dispatchNextReady();
        }
        return {
            requested: clampBatch(count),
            generated: results.filter((r) => r.ok && !r.skipped).length,
            skipped: results.filter((r) => r.skipped && !r.failed).length,
            failed: results.filter((r) => r.failed || !r.ok).length,
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
    job.dispatchAttempts = (job.dispatchAttempts || 0) + 1;
    await job.save();

    let lastError = 'Ningún bot aceptó el video.';
    let busy = false;
    for (const url of cfg.urls) {
        try {
            await wakeBot(url);
            console.log(`[VideoBot] Enviando ${payload.scenes.length} escenas a ${url} (job ${job._id}, intento ${job.dispatchAttempts})...`);
            const response = await fetch(`${url}/generate_video`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': cfg.key
                },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(15000)
            });
            if (botAccepted(response.status)) {
                job.status = 'processing';
                job.dispatchedTo = url;
                job.dispatchedAt = job.dispatchedAt || new Date();
                job.error = '';
                await job.save();
                await logEvent({
                    level: 'info',
                    event: 'sent_vps',
                    message: `El bot ACEPTÓ el JSON (${url}, ${payload.scenes.length} escenas). Suma 1 a la cuota del día.`,
                    productName: job.productName,
                    jobId: String(job._id)
                });
                return { sent: true, url, job };
            }
            if (botBusy(response.status)) {
                busy = true;
                lastError = `Bot ocupado en ${url} (${response.status}). El JSON sigue guardado.`;
                console.warn(`[VideoBot] ${lastError}`);
                continue;
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
        level: busy ? 'warn' : 'error',
        event: busy ? 'bot_busy' : 'dispatch_failed',
        message: lastError,
        productName: job.productName,
        jobId: String(job._id)
    });
    return { sent: false, reason: lastError, busy, job };
}

async function dispatchNextReady() {
    if (scheduler.dispatching) {
        return { sent: false, reason: 'already_dispatching' };
    }
    const cfg = botConfig();
    if (!cfg.ok) return { sent: false, reason: 'no_url' };

    const settings = await getSettings();
    if (settings.autoDispatch === false) return { sent: false, reason: 'auto_off' };

    const quota = await remainingToday(settings);
    if (quota.remaining <= 0) {
        return { sent: false, reason: 'quota', quota };
    }

    scheduler.dispatching = true;
    try {
        const job = await VideoJob.findOneAndUpdate(
            {
                status: 'json_ready',
                'escenasJSON.scenes.0': { $exists: true }
            },
            { $set: { status: 'sending' } },
            { sort: { createdAt: 1 }, new: true }
        );
        if (!job) return { sent: false, reason: 'empty' };
        try {
            return await dispatchJob(job);
        } catch (err) {
            job.status = 'json_ready';
            job.error = err.message || String(err);
            await job.save().catch(() => {});
            return { sent: false, reason: job.error, job };
        }
    } finally {
        scheduler.dispatching = false;
    }
}

async function markComplete(jobId, { youtubeId, videoUrl, error } = {}) {
    const job = await VideoJob.findById(jobId);
    if (!job) return null;
    if (error) {
        if ((job.dispatchAttempts || 0) < JSON_ATTEMPTS && job.escenasJSON?.scenes?.length) {
            job.status = 'json_ready';
            job.error = `El bot falló al renderizar. Se reenvía el mismo JSON (${job.dispatchAttempts}/${JSON_ATTEMPTS}). ${error}`;
            await logEvent({
                level: 'warn',
                event: 'video_retry',
                message: job.error,
                productName: job.productName,
                jobId: String(job._id)
            });
        } else {
            job.status = 'failed';
            job.error = error;
            await logEvent({
                level: 'error',
                event: 'video_failed',
                message: error,
                productName: job.productName,
                jobId: String(job._id)
            });
        }
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
    setImmediate(() => {
        dispatchNextReady().catch((err) => console.warn('[videos] despacho post-bot:', err.message));
    });
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
        jsonAttempts: job.jsonAttempts || 0,
        dispatchAttempts: job.dispatchAttempts || 0,
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
        buffer: {
            ready: await readyBufferCount(),
            limit: BUFFER_SIZE_LIMIT
        },
        scheduler: {
            started: scheduler.started,
            ticking: scheduler.ticking,
            dispatching: scheduler.dispatching,
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
        const ready = await readyBufferCount();
        const zombies = await resetZombies({ forceAll: force });

        let batch = { requested: 0, generated: 0, skipped: 0, failed: 0, results: [] };
        const room = Math.max(0, BUFFER_SIZE_LIMIT - ready);
        const quotaRoom = force ? Math.max(room, 1) : Math.min(room, quota.remaining);
        const canGenerate = gemma.config().ok && quotaRoom > 0 && (force || room > 0);

        if (quota.remaining <= 0 && !force && ready <= 0) {
            const result = `Cuota del día completa: ${quota.used}/${quota.quota} videos aceptados por el bot.`;
            settingsDoc.lastTickAt = new Date();
            settingsDoc.lastTickResult = result;
            settingsDoc.lastError = '';
            await settingsDoc.save();
            scheduler.lastTick = { at: settingsDoc.lastTickAt, result, skipped: true, ready };
            return { skipped: true, reason: 'quota', quota, purged, ready };
        }

        if (ready >= BUFFER_SIZE_LIMIT && !force) {
            await logEvent({
                level: 'info',
                event: 'buffer_full',
                message: `Buffer lleno: ${ready}/${BUFFER_SIZE_LIMIT} JSON listos. Solo despachando al bot.`
            });
        } else if (canGenerate) {
            const want = force ? Math.min(TICK_CHUNK, quotaRoom) : 1;
            await logEvent({
                level: 'info',
                event: 'tick',
                message: `Armando JSON ${want} (buffer ${ready}/${BUFFER_SIZE_LIMIT}, cuota ${quota.used}/${quota.quota} aceptados).`
            });
            batch = await generateBatch({
                Product,
                SiteConfig,
                count: want,
                dispatch: false,
                source: force ? 'admin' : 'scheduler'
            });
        }

        let dispatched = { sent: false, reason: 'off' };
        if (settings.autoDispatch && botConfig().ok) {
            dispatched = await dispatchNextReady();
        }

        const readyAfter = await readyBufferCount();
        const quotaAfter = await remainingToday(settings);
        const result = dispatched.sent
            ? `Bot aceptó 1 video. Buffer ${readyAfter}/${BUFFER_SIZE_LIMIT}. Cuota ${quotaAfter.used}/${quotaAfter.quota}.`
            : `Buffer ${readyAfter}/${BUFFER_SIZE_LIMIT} JSON listos. Despacho: ${dispatched.reason || 'no'}. Cuota ${quotaAfter.used}/${quotaAfter.quota} aceptados.`;
        settingsDoc.lastTickAt = new Date();
        settingsDoc.lastTickResult = result;
        settingsDoc.lastError = batch.failed ? `${batch.failed} JSON fallaron (se cambia de producto).` : '';
        await settingsDoc.save();
        scheduler.lastTick = { at: settingsDoc.lastTickAt, result, batch, dispatched, ready: readyAfter };
        await logEvent({
            level: batch.failed ? 'warn' : 'info',
            event: 'tick_done',
            message: result
        });
        return {
            skipped: false,
            batch,
            quota: quotaAfter,
            purged,
            zombies,
            ready: readyAfter,
            dispatched
        };
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
    scheduler.deps = deps;

    const first = setTimeout(() => {
        workerLoop(deps).catch((err) => console.error('[videos] worker loop:', err.message));
    }, 20 * 1000);

    scheduler.timer = setInterval(() => {
        dispatchNextReady().catch((err) => console.error('[videos] despacho min:', err.message));
    }, DISPATCH_MS);

    if (typeof scheduler.timer.unref === 'function') scheduler.timer.unref();
    if (typeof first.unref === 'function') first.unref();
    console.log(`[videos] Worker autónomo: junta ${BUFFER_SIZE_LIMIT} JSON, Gemma x${JSON_ATTEMPTS}, despacho cada ${DISPATCH_MS / 1000}s.`);
    logEvent({
        level: 'info',
        event: 'scheduler_start',
        message: `Bot autónomo tipo Noticias LAT: junta ${BUFFER_SIZE_LIMIT} JSON listos, insiste ${JSON_ATTEMPTS} veces con Gemma y si no cambia de producto. Cada minuto intenta mandar uno al VPS; si está ocupado el JSON queda. Recién cuando el bot ACEPTA suma 1 a la cuota (${DEFAULT_DAILY_QUOTA}/día). Cuando el bot avisa que terminó, manda el siguiente.`
    }).catch(() => {});
    return scheduler;
}

async function workerLoop(deps) {
    while (scheduler.started) {
        try {
            const out = await runTick(deps);
            if (out?.reason === 'off' || out?.reason === 'no_gemma') {
                await sleep(20 * 1000);
                continue;
            }
            if (out?.reason === 'quota' || (out?.quota && out.quota.remaining <= 0 && !out.dispatched?.sent)) {
                await sleep(5 * 60 * 1000);
                continue;
            }
            const ready = typeof out?.ready === 'number' ? out.ready : await readyBufferCount();
            await sleep(ready >= BUFFER_SIZE_LIMIT ? BUFFER_FULL_SLEEP_MS : GENERATE_PAUSE_MS);
        } catch (err) {
            console.error('[videos] worker:', err.message);
            await sleep(10 * 1000);
        }
    }
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
        dispatching: scheduler.dispatching,
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
    BUFFER_SIZE_LIMIT,
    JSON_ATTEMPTS,
    DISPATCH_MS,
    DEFAULT_DAILY_QUOTA,
    DEFAULT_KEEP_DAYS,
    TICK_MS,
    TICK_CHUNK,
    botConfig,
    botAccepted,
    botBusy,
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
    readyBufferCount,
    resetZombies,
    videoUrlAlive,
    verifyProductVideos,
    eligibleQuery,
    listEligibleProducts,
    pickProducts,
    generateForProduct,
    generateBatch,
    dispatchJob,
    dispatchNextReady,
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
