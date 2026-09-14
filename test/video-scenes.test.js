'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const ejs = require('ejs');
const gemma = require('../lib/gemma');
const scenes = require('../lib/video-scenes');
const videoBot = require('../lib/video-bot');

function sampleProduct(extra = {}) {
    return scenes.demoProduct({
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
        ...extra
    });
}

const siteConfig = {
    whatsappNumber: '595987301591',
    storeAddress: 'Ferumishop, Asunción - Paraguay',
    motoboltMaxKm: 40,
    instagramUrl: 'https://instagram.com/ferumishop',
    tiktokUrl: 'https://tiktok.com/@ferumishop'
};

function eightScenes() {
    return [
        { type: 'video', text: '¿Cansada de gastar en pestañas que se caen a las dos horas, linda?', texto_pantalla: '¿Se te caen?', video_url: 'VIDEO_1', voice: 'mujer_1' },
        { type: 'video', text: 'Este libro de pestañas 30D de Ferumishop te deja mirada de salón y lo ponés vos en casa.', texto_pantalla: 'Look de salón', video_url: 'VIDEO_2', voice: 'mujer_1' },
        { type: 'video', text: 'El racimo da volumen de verdad, se ve en el video, no es filtro ni promesa vacía.', texto_pantalla: 'Volumen 30D', video_url: 'VIDEO_1', voice: 'mujer_1' },
        { type: 'video', text: 'Es un look DIY fácil: las acomodás, pegás y salís. Quedan suaves y naturales.', texto_pantalla: 'DIY en casa', video_url: 'VIDEO_2', voice: 'mujer_1' },
        { type: 'video', text: 'Sirve para el trabajo, para una cita, y no tenés que ir al centro cada fin de semana.', texto_pantalla: 'Todos los días', video_url: 'VIDEO_1', voice: 'mujer_1' },
        { type: 'video', text: 'El precio es 45.000 Gs., calidad de tienda y stock listo para mandarte hoy.', texto_pantalla: '45.000 Gs.', video_url: 'VIDEO_2', voice: 'mujer_1' },
        { type: 'video', text: 'En Paraguay enviamos por Motobolt en Central y alrededores, interior por transportadora.', texto_pantalla: 'Envío Motobolt', video_url: 'VIDEO_1', voice: 'mujer_1' },
        { type: 'video', text: 'Pedilo ahora al WhatsApp 0987 301 591 o en ferumi.shop y te asesoramos, linda.', texto_pantalla: 'Pedilo por WhatsApp', video_url: 'VIDEO_2', voice: 'mujer_1' }
    ];
}

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

test('Gemma REST retries 500 Internal error and does not send safety settings', () => {
    assert.equal(gemma.isRetryableError({ message: 'Internal error encountered.', status: 500 }), true);
    assert.equal(gemma.isQuotaError({ message: 'Internal error encountered.', status: 500 }), false);
    assert.ok(gemma.listedModels().includes('gemma-4-26b-a4b-it'));
    assert.ok(gemma.listedModels().includes('gemma-4-31b-it'));
    const body = gemma.restBody('hola linda');
    assert.equal(body.contents[0].parts[0].text, 'hola linda');
    assert.equal(body.contents[0].role, undefined);
    assert.equal(body.safetySettings, undefined);
    assert.equal(body.generationConfig.thinkingConfig.thinkingLevel, 'minimal');
    assert.equal(gemma.restBody('x', { thinking: false }).generationConfig.thinkingConfig, undefined);
});

test('finalizePayload matches ferumishopvideos: type video, texto_pantalla, no mapa, max 85s', () => {
    const product = sampleProduct();
    const shop = scenes.shopContext(siteConfig);
    const payload = scenes.finalizePayload({
        youtube_title: 'Pestañas 30D que parecen tiras de salón',
        youtube_tags: ['pestañas'],
        texto_pantalla: 'Pestañas 30D Ferumi',
        scenes: [
            {
                type: 'intro',
                text: '¡Estas pestañas te dejan mirada de muñeca en dos minutos!',
                texto_pantalla: 'Mirada de muñeca',
                video_url: 'VIDEO_1',
                voice: 'mujer_1'
            },
            {
                type: 'product_video',
                video_url: 'VIDEO_1',
                text: 'Mirá el racimo de cerca, es un libro de pestañas para un look DIY en casa.',
                texto_pantalla: 'Libro de pestañas',
                voice: 'mujer_1'
            },
            {
                type: 'mapa',
                ubicacion: 'Asunción, Paraguay',
                text: 'Somos Ferumishop en Paraguay y enviamos por Motobolt.',
                voice: 'mujer_1'
            },
            ...eightScenes().slice(2)
        ]
    }, { shop, product, jobId: 'job1' });

    assert.equal(payload.article_id, 'job1');
    assert.equal(payload.product_id, '65f0000000000000000000aa');
    assert.equal(payload.shop, 'ferumishop');
    assert.equal(payload.kind, 'ferumishop_short');
    assert.equal(payload.whatsapp, '595987301591');
    assert.ok(payload.texto_pantalla);
    assert.equal(payload.scenes.some((s) => s.type === 'mapa'), false);
    payload.scenes.forEach((s) => {
        assert.equal(s.type, 'video');
        assert.ok(s.texto_pantalla);
        assert.ok(s.text);
        assert.equal(s.voice, 'mujer_1');
        assert.ok(s.video_url.startsWith('https://'));
        assert.ok(!s.text.includes('\n'));
        assert.ok(!s.ubicacion);
    });
    const allText = payload.scenes.map((s) => s.text || '').join(' ');
    assert.match(allText, /Motobolt/i);
    assert.match(allText, /0987 301 591/);
    assert.match(payload.youtube_description, /wa\.me\/595987301591/);
    assert.match(payload.youtube_description, /Paraguay/);
    assert.ok(payload.metrics.estimatedSeconds <= scenes.MAX_SECONDS);
    const check = scenes.assertPayloadForBot(payload);
    assert.equal(check.ok, true, check.errors.join(' | '));
});

test('generateProductVideoScenesJSON uses Gemma mock and overlay per scene', async () => {
    const original = gemma.generateContentWithRetry;
    gemma.generateContentWithRetry = async () => JSON.stringify({
        youtube_title: 'Pestañas racimo DIY Ferumishop',
        youtube_tags: ['ferumishop', 'pestañas', 'diy'],
        whatsapp: '595987301591',
        texto_pantalla: 'Pestañas 30D',
        scenes: eightScenes()
    });
    try {
        const payload = await scenes.generateProductVideoScenesJSON(sampleProduct(), siteConfig, { jobId: 'abc' });
        assert.equal(payload.article_id, 'abc');
        assert.equal(payload.scenes.length, 8);
        payload.scenes.forEach((s) => {
            assert.equal(s.type, 'video');
            assert.match(s.video_url, /videos\.ferumi\.shop/);
            assert.ok(s.texto_pantalla);
        });
        assert.equal(payload.metrics.sceneCount, payload.scenes.length);
        assert.ok(payload.metrics.words > 20);
        assert.ok(payload.metrics.estimatedSeconds <= 85);
    } finally {
        gemma.generateContentWithRetry = original;
    }
});

test('clampDuration never exceeds 85 seconds', () => {
    const product = sampleProduct();
    const shop = scenes.shopContext(siteConfig);
    const long = 'palabra '.repeat(80).trim();
    const payload = scenes.finalizePayload({
        youtube_title: 'Test largo',
        scenes: eightScenes().map((s, i) => ({
            ...s,
            text: i === 0 || i === 7 ? s.text : `${s.text} ${long}`
        }))
    }, { shop, product, jobId: 'long1' });
    assert.ok(payload.metrics.estimatedSeconds <= 85);
    assert.equal(payload.scenes.some((s) => s.type === 'mapa'), false);
});

test('clampBatch stays between 1 and 30', () => {
    assert.equal(videoBot.clampBatch(20), 20);
    assert.equal(videoBot.clampBatch(50), 30);
    assert.equal(videoBot.clampBatch(0), 20);
    assert.equal(videoBot.clampBatch('7'), 7);
});

test('prompt talks about overlay, no map, 85s and ferumishopvideos', () => {
    const shop = scenes.shopContext(siteConfig);
    const prompt = scenes.buildPrompt({
        shop,
        product: scenes.productBrief(sampleProduct()),
        videoSlots: scenes.usableVideos(sampleProduct())
    });
    assert.match(prompt, /Motobolt/);
    assert.match(prompt, /Paraguay/);
    assert.match(prompt, /0987 301 591/);
    assert.match(prompt, /texto_pantalla/);
    assert.match(prompt, /"type": "video"/);
    assert.match(prompt, /PROHIBIDO "mapa"/);
    assert.match(prompt, /85/);
    assert.match(prompt, /VIDEO_1/);
    assert.match(prompt, /ferumishopvideos/);
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
            metrics: { words: 180, estimatedSeconds: 78 },
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
    assert.match(html, /texto en pantalla/);
});
