'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const ejs = require('ejs');
const gemma = require('../lib/gemma');
const scenes = require('../lib/video-scenes');
const videoBot = require('../lib/video-bot');

function sampleProduct(extra = {}) {
    return {
        _id: '65f0000000000000000000aa',
        name: 'Pestañas 30D racimo',
        description: '<p>Libro de pestañas en racimo para look DIY en casa. Volumen 30D.</p>',
        price: 45000,
        stock: 12,
        hasVariants: false,
        variants: [],
        photos: ['https://img.ferumi.shop/pestanias.jpg'],
        videos: [
            { url: 'https://videos.ferumi.shop/productos/1/clip-a.mp4', key: 'a', originalName: 'a.mp4' },
            { url: 'https://videos.ferumi.shop/productos/1/clip-b.mp4', key: 'b', originalName: 'b.mp4' }
        ],
        category: { name: 'Pestañas' },
        isForSale: true,
        ...extra
    };
}

const siteConfig = {
    whatsappNumber: '595987301591',
    storeAddress: 'Ferumishop, Asunción - Paraguay',
    motoboltMaxKm: 40,
    instagramUrl: 'https://instagram.com/ferumishop',
    tiktokUrl: 'https://tiktok.com/@ferumishop'
};

test('formatPyPhone and eligibility', () => {
    assert.equal(scenes.formatPyPhone('595987301591'), '0987 301 591');
    assert.equal(scenes.isEligibleProduct(sampleProduct()), true);
    assert.equal(scenes.isEligibleProduct(sampleProduct({ stock: 0 })), false);
    assert.equal(scenes.isEligibleProduct(sampleProduct({ videos: [] })), false);
    assert.equal(scenes.isEligibleProduct(sampleProduct({ isForSale: false })), false);
    assert.equal(scenes.productStock(sampleProduct({
        hasVariants: true,
        variants: [{ name: '30D', stock: 2 }, { name: '40D', stock: 3 }]
    })), 5);
});

test('extractJsonObject strips markdown fences', () => {
    const raw = '```json\n{"youtube_title":"Hola","scenes":[]}\n```';
    const parsed = gemma.extractJsonObject(raw);
    assert.equal(parsed.youtube_title, 'Hola');
});

test('finalizePayload injects R2 clips, Paraguay, Motobolt and WhatsApp', () => {
    const product = sampleProduct();
    const shop = scenes.shopContext(siteConfig);
    const payload = scenes.finalizePayload({
        youtube_title: 'Pestañas 30D que parecen tiras de salón',
        youtube_tags: ['pestañas'],
        scenes: [
            {
                type: 'intro',
                text: '¡Estas pestañas te dejan mirada de muñeca en dos minutos!',
                layout_category: 'sin_presentador',
                voice: 'mujer_1',
                bgm_mood: 'urgencia',
                sfx_type: 'impactos'
            },
            {
                type: 'product_video',
                video_url: 'VIDEO_1',
                text: 'Mirá el racimo de cerca, es un libro de pestañas para un look DIY en casa.',
                voice: 'mujer_1',
                layout_category: 'mujer',
                bgm_mood: 'analisis',
                sfx_type: 'transiciones'
            },
            {
                type: 'product_video',
                video_url: 'VIDEO_2',
                text: 'El volumen 30D queda divino y el precio es accesible para usarlo todos los días.',
                voice: 'mujer_1',
                layout_category: 'mujer'
            }
        ]
    }, { shop, product, jobId: 'job1' });

    assert.equal(payload.article_id, 'job1');
    assert.equal(payload.product_id, '65f0000000000000000000aa');
    assert.equal(payload.shop, 'ferumishop');
    assert.equal(payload.kind, 'ferumishop_short');
    assert.ok(payload.scenes.some((s) => s.type === 'mapa'));
    assert.ok(payload.scenes.some((s) => s.type === 'product_video' && s.video_url.includes('clip-a.mp4')));
    assert.ok(payload.scenes.some((s) => s.type === 'product_video' && s.video_url.includes('clip-b.mp4')));
    const allText = payload.scenes.map((s) => s.text || '').join(' ');
    assert.match(allText, /Motobolt/i);
    assert.match(allText, /0987 301 591/);
    assert.match(payload.youtube_description, /wa\.me\/595987301591/);
    assert.match(payload.youtube_description, /Paraguay/);
    payload.scenes.filter((s) => s.type === 'product_video').forEach((s) => {
        assert.ok(s.video_url.startsWith('https://'));
        assert.equal(s.video_url, s.ad_media_url);
        assert.ok(!s.text.includes('\n'));
    });
});

test('generateProductVideoScenesJSON uses Gemma mock and 1 clip per scene', async () => {
    const original = gemma.generateContentWithRetry;
    gemma.generateContentWithRetry = async () => JSON.stringify({
        youtube_title: 'Pestañas racimo DIY Ferumishop',
        youtube_tags: ['ferumishop', 'pestañas', 'diy'],
        scenes: [
            { type: 'intro', text: 'Linda, estas pestañas parecen de salón y las ponés vos.', layout_category: 'sin_presentador', voice: 'mujer_1', bgm_mood: 'urgencia', sfx_type: 'impactos' },
            { type: 'product_video', video_url: 'VIDEO_1', text: 'Es un libro de pestañas en racimo, ideal para un look DIY en casa sin ir al centro.', layout_category: 'mujer', voice: 'mujer_1', bgm_mood: 'analisis', sfx_type: 'transiciones' },
            { type: 'product_video', video_url: 'VIDEO_2', text: 'El efecto 30D se ve de verdad en el video, no es filtro. Quedan suaves y con volumen.', layout_category: 'mujer', voice: 'mujer_1', bgm_mood: 'analisis', sfx_type: 'transiciones' },
            { type: 'mapa', ubicacion: 'Asunción, Paraguay', text: 'Somos Ferumishop en Paraguay y enviamos por Motobolt en Central y alrededores.', layout_category: 'sin_presentador', voice: 'mujer_1', bgm_mood: 'analisis', sfx_type: 'alertas' },
            { type: 'product_video', video_url: 'VIDEO_1', text: 'Pedilo al WhatsApp 0987 301 591. En Central llega por Motobolt y el interior por encomienda.', layout_category: 'mujer', voice: 'mujer_1', bgm_mood: 'urgencia', sfx_type: 'impactos' }
        ]
    });
    try {
        const payload = await scenes.generateProductVideoScenesJSON(sampleProduct(), siteConfig, { jobId: 'abc' });
        assert.equal(payload.article_id, 'abc');
        const productScenes = payload.scenes.filter((s) => s.type === 'product_video');
        assert.ok(productScenes.length >= 2);
        productScenes.forEach((s) => {
            assert.match(s.video_url, /videos\.ferumi\.shop/);
        });
        assert.equal(payload.metrics.sceneCount, payload.scenes.length);
        assert.ok(payload.metrics.words > 20);
    } finally {
        gemma.generateContentWithRetry = original;
    }
});

test('clampBatch stays between 1 and 30', () => {
    assert.equal(videoBot.clampBatch(20), 20);
    assert.equal(videoBot.clampBatch(50), 30);
    assert.equal(videoBot.clampBatch(0), 20);
    assert.equal(videoBot.clampBatch('7'), 7);
});

test('prompt talks about Paraguay, Motobolt, WhatsApp and DIY lashes', () => {
    const shop = scenes.shopContext(siteConfig);
    const prompt = scenes.buildPrompt({
        shop,
        product: scenes.productBrief(sampleProduct()),
        videoSlots: scenes.usableVideos(sampleProduct())
    });
    assert.match(prompt, /Motobolt/);
    assert.match(prompt, /Paraguay/);
    assert.match(prompt, /0987 301 591/);
    assert.match(prompt, /product_video/);
    assert.match(prompt, /VIDEO_1/);
    assert.match(prompt, /racimo|DIY|pestañas/i);
    assert.match(prompt, /gemma|Director TÉCNICO/i);
});

test('videos admin view renders eligible products', async () => {
    const html = await ejs.renderFile(path.join(__dirname, '..', 'views/admin/videos.html'), {
        filename: path.join(__dirname, '..', 'views/admin/videos.html'),
        path: '/admin/videos',
        pageTitle: 'Videos Shorts',
        eligible: [sampleProduct()],
        jobs: [{
            id: '1',
            productName: 'Pestañas 30D racimo',
            youtubeTitle: 'Test',
            status: 'json_ready',
            sceneCount: 8,
            metrics: { words: 200, estimatedSeconds: 80 },
            error: ''
        }],
        gemmaOk: true,
        gemmaModel: 'gemma-4-31b-it',
        gemmaKeys: 1,
        botUrl: '',
        botReady: false,
        batchRunning: false,
        success: null,
        error: null
    });
    assert.match(html, /Bot de Shorts FERUMI/);
    assert.match(html, /Pestañas 30D racimo/);
    assert.match(html, /gemma-4-31b-it/);
    assert.match(html, /VIDEO_BOT_URL/);
    assert.match(html, /Videos Shorts/);
});
