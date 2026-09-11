'use strict';

/**
 * Cloudflare R2 (S3 compatible) for product videos.
 * Env:
 *   R2_ACCOUNT_ID
 *   R2_ACCESS_KEY_ID
 *   R2_SECRET_ACCESS_KEY
 *   R2_BUCKET
 *   R2_PUBLIC_BASE_URL  (ej. https://videos.ferumi.shop o https://pub-xxxx.r2.dev)
 */

const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

function r2Config() {
    const accountId = String(process.env.R2_ACCOUNT_ID || '').trim();
    const accessKeyId = String(process.env.R2_ACCESS_KEY_ID || '').trim();
    const secretAccessKey = String(process.env.R2_SECRET_ACCESS_KEY || '').trim();
    const bucket = String(process.env.R2_BUCKET || '').trim();
    const publicBase = String(process.env.R2_PUBLIC_BASE_URL || '').trim().replace(/\/$/, '');
    return {
        accountId,
        accessKeyId,
        secretAccessKey,
        bucket,
        publicBase,
        ok: Boolean(accountId && accessKeyId && secretAccessKey && bucket && publicBase)
    };
}

function client() {
    const cfg = r2Config();
    return new S3Client({
        region: 'auto',
        endpoint: `https://${cfg.accountId}.r2.cloudflarestorage.com`,
        credentials: {
            accessKeyId: cfg.accessKeyId,
            secretAccessKey: cfg.secretAccessKey
        },
        requestChecksumCalculation: 'WHEN_REQUIRED',
        responseChecksumValidation: 'WHEN_REQUIRED'
    });
}

function safeName(name) {
    return String(name || 'video')
        .replace(/[^\w.\-]+/g, '_')
        .slice(0, 80);
}

async function uploadProductVideo({ productId, buffer, filename, contentType }) {
    const cfg = r2Config();
    if (!cfg.ok) {
        throw new Error('Falta configurar Cloudflare R2 (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_PUBLIC_BASE_URL).');
    }
    const key = `productos/${productId}/${Date.now()}-${safeName(filename)}`;
    await client().send(new PutObjectCommand({
        Bucket: cfg.bucket,
        Key: key,
        Body: buffer,
        ContentType: contentType || 'video/mp4'
    }));
    return {
        key,
        url: `${cfg.publicBase}/${key}`,
        originalName: filename || '',
        createdAt: new Date()
    };
}

async function deleteProductVideo(key) {
    const cfg = r2Config();
    if (!cfg.ok || !key) return { skipped: true };
    await client().send(new DeleteObjectCommand({
        Bucket: cfg.bucket,
        Key: key
    }));
    return { ok: true };
}

function shopVideos(product, limit = 2) {
    const list = Array.isArray(product?.videos) ? product.videos : [];
    return list.filter((v) => v && v.url).slice(0, limit);
}

function botProductJson(product) {
    const variants = (product.variants || []).map((v) => ({
        name: v.name,
        stock: v.stock || 0
    }));
    const description = String(product.description || '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    return {
        id: String(product._id),
        name: product.name,
        description,
        price: product.price || 0,
        stock: product.stock || 0,
        hasVariants: Boolean(product.hasVariants),
        variants,
        photos: product.photos || [],
        videos: (product.videos || []).map((v) => ({
            url: v.url,
            key: v.key || '',
            originalName: v.originalName || ''
        }))
    };
}

module.exports = {
    r2Config,
    uploadProductVideo,
    deleteProductVideo,
    shopVideos,
    botProductJson
};
