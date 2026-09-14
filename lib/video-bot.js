'use strict';

const mongoose = require('mongoose');
const scenes = require('./video-scenes');
const gemma = require('./gemma');

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
        completedAt: { type: Date }
    }, { timestamps: true });
}

const VideoJob = mongoose.models.VideoJob || mongoose.model('VideoJob', jobSchema());

function botConfig() {
    const urls = String(process.env.VIDEO_BOT_URL || process.env.VIDEO_BOT_URLS || '')
        .split(',')
        .map((u) => u.trim().replace(/\/$/, ''))
        .filter(Boolean);
    const key = String(process.env.VIDEO_BOT_KEY || process.env.ADMIN_API_KEY || process.env.BOT_API_TOKEN || '').trim();
    return {
        urls,
        key,
        ok: urls.length > 0,
        batchMin: 20,
        batchMax: 30
    };
}

function clampBatch(n) {
    const cfg = botConfig();
    const num = Number(n);
    if (!Number.isFinite(num) || num <= 0) return cfg.batchMin;
    return Math.min(cfg.batchMax, Math.max(1, Math.round(num)));
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

async function verifyProductVideos(product) {
    const list = scenes.usableVideos(product);
    const alive = [];
    for (const video of list) {
        const ok = await videoUrlAlive(video.url);
        if (ok) alive.push(video);
        else console.warn(`[videos] Clip R2 caído: ${video.url}`);
    }
    return alive;
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

async function pickProducts(Product, { count = 20, excludeIds = [] } = {}) {
    const wanted = clampBatch(count);
    const candidates = await listEligibleProducts(Product, { limit: 120 });
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
        status: { $in: ['json_ready', 'sending', 'processing', 'completed'] }
    }).select('product').lean();
    return jobs.map((j) => String(j.product));
}

async function generateForProduct({ Product, SiteConfig, product, productId, dispatch = false }) {
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
            error: 'Sin stock.'
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
            error: 'No hay clips vivos en Cloudflare R2.'
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
        stockSnapshot: stock
    });

    try {
        const payload = await scenes.generateProductVideoScenesJSON(doc, siteConfig, { jobId: job._id });
        job.escenasJSON = payload;
        job.youtubeTitle = payload.youtube_title;
        job.videoUrlsUsed = payload.video_urls_used || alive.map((v) => v.url);
        job.status = 'json_ready';
        await job.save();

        if (dispatch) {
            await dispatchJob(job);
        }
        return { job, skipped: false, payload };
    } catch (err) {
        job.status = 'failed';
        job.error = err.message || String(err);
        await job.save();
        throw err;
    }
}

async function generateBatch({ Product, SiteConfig, count = 20, dispatch = false }) {
    const recent = await recentProductIds(36);
    const products = await pickProducts(Product, { count, excludeIds: recent });
    const results = [];
    for (const product of products) {
        try {
            const out = await generateForProduct({ Product, SiteConfig, product, dispatch });
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

async function dispatchJob(job) {
    const cfg = botConfig();
    if (!cfg.ok) {
        job.status = 'json_ready';
        job.error = 'VIDEO_BOT_URL todavía no está configurada. JSON listo para cuando el VPS viva.';
        await job.save();
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
    return { sent: false, reason: lastError, job };
}

async function markComplete(jobId, { youtubeId, videoUrl, error } = {}) {
    const job = await VideoJob.findById(jobId);
    if (!job) return null;
    if (error) {
        job.status = 'failed';
        job.error = error;
    } else {
        job.status = 'completed';
        job.youtubeId = youtubeId || job.youtubeId;
        job.generatedVideoUrl = videoUrl || job.generatedVideoUrl;
        job.completedAt = new Date();
        job.error = '';
    }
    await job.save();
    return job;
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
        createdAt: job.createdAt,
        metrics: json?.metrics || null,
        sceneCount: json?.scenes?.length || 0
    };
}

module.exports = {
    VideoJob,
    STATUSES,
    botConfig,
    clampBatch,
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
    gemmaReady: () => gemma.config().ok
};
