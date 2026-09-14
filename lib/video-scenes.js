'use strict';

/**
 * Director de Shorts de venta FERUMI.
 * Replica las reglas de lfaftechapi (generateShortVideoScenesJSON):
 * JSON estricto para FFmpeg, campo text = TTS, 8-9 escenas, ~80s.
 * En cada escena de producto va 1 clip real de Cloudflare R2.
 */

const gemma = require('./gemma');
const r2 = require('./r2');

const SCENE_TYPES = ['intro', 'body', 'product_video', 'mapa', 'ad_video', 'ad_mencion'];
const LAYOUTS = ['hombre', 'mujer', 'sin_presentador'];
const VOICES = ['hombre_1', 'mujer_1'];
const BGM = ['urgencia', 'analisis', 'tension'];
const SFX = ['impactos', 'transiciones', 'alertas', 'tecnologia'];

const DEFAULT_SHOP = {
    name: 'Ferumishop',
    country: 'Paraguay',
    city: 'Asunción',
    phone: '595987301591',
    web: 'https://www.ferumi.shop',
    instagram: 'https://instagram.com/ferumishop',
    tiktok: 'https://tiktok.com/@ferumishop',
    address: 'Ferumishop, Asunción - Paraguay',
    motoboltMaxKm: 40
};

function stripHtml(text) {
    return String(text || '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

function formatGs(n) {
    return `${new Intl.NumberFormat('es-PY').format(Math.round(Number(n) || 0))} Gs.`;
}

function formatPyPhone(raw) {
    let d = String(raw || '').replace(/\D/g, '');
    if (d.startsWith('595')) d = `0${d.slice(3)}`;
    if (d.length === 10) return `${d.slice(0, 4)} ${d.slice(4, 7)} ${d.slice(7)}`;
    return d || String(raw || '');
}

function waMe(raw) {
    const d = String(raw || '').replace(/\D/g, '');
    return d ? `https://wa.me/${d}` : 'https://wa.me/595987301591';
}

function countWords(text) {
    return String(text || '').trim().split(/\s+/).filter(Boolean).length;
}

function shopContext(siteConfig = {}) {
    const phone = String(siteConfig.whatsappNumber || DEFAULT_SHOP.phone).replace(/\D/g, '') || DEFAULT_SHOP.phone;
    return {
        name: DEFAULT_SHOP.name,
        country: DEFAULT_SHOP.country,
        city: DEFAULT_SHOP.city,
        phone,
        phoneDisplay: formatPyPhone(phone),
        waLink: waMe(phone),
        web: String(process.env.BASE_URL || DEFAULT_SHOP.web).replace(/\/$/, ''),
        instagram: siteConfig.instagramUrl || DEFAULT_SHOP.instagram,
        tiktok: siteConfig.tiktokUrl || DEFAULT_SHOP.tiktok,
        address: siteConfig.storeAddress || DEFAULT_SHOP.address,
        motoboltMaxKm: Number(siteConfig.motoboltMaxKm) || DEFAULT_SHOP.motoboltMaxKm
    };
}

function productStock(product) {
    if (product?.hasVariants) {
        return (product.variants || []).reduce((s, v) => s + (Number(v.stock) || 0), 0);
    }
    return Number(product?.stock) || 0;
}

function usableVideos(product) {
    return (product?.videos || []).filter((v) => v && String(v.url || '').startsWith('http'));
}

function isEligibleProduct(product) {
    if (!product || product.isForSale === false) return false;
    if (productStock(product) <= 0) return false;
    return usableVideos(product).length > 0;
}

function productBrief(product) {
    const json = r2.botProductJson(product);
    const categoryName = product.category?.name || product.categoryName || 'Belleza';
    const variants = (json.variants || [])
        .filter((v) => (v.stock || 0) > 0)
        .map((v) => `${v.name} (stock ${v.stock})`);
    return {
        id: json.id,
        name: json.name,
        description: json.description || 'Producto de belleza Ferumishop.',
        price: json.price,
        priceLabel: formatGs(json.price),
        stock: productStock(product),
        categoryName,
        variants,
        photos: json.photos || [],
        videos: json.videos || [],
        productUrl: `${String(process.env.BASE_URL || DEFAULT_SHOP.web).replace(/\/$/, '')}/producto/${json.id}`
    };
}

function youtubeDescription(shop, product, extra = '') {
    const tags = ['#shorts', '#ferumishop', '#paraguay', '#pestañas', '#diy', '#belleza'].join(' ');
    return [
        `🛒 Pedí por WhatsApp: ${shop.waLink}`,
        `📞 ${shop.phoneDisplay} · ${shop.name} · ${shop.country}`,
        `📍 Envíos por Motobolt en Central y alrededores (hasta ${shop.motoboltMaxKm} km). Interior por transportadora.`,
        `🌐 ${shop.web}`,
        `📸 Instagram: ${shop.instagram}`,
        `🎵 TikTok: ${shop.tiktok}`,
        '',
        extra || product.description || '',
        '',
        tags
    ].join('\n');
}

function sanitizeScene(scene) {
    const out = { ...(scene || {}) };
    if (!SCENE_TYPES.includes(out.type)) out.type = 'product_video';
    if (out.text) out.text = String(out.text).replace(/\n/g, ' ').replace(/\s+/g, ' ').trim();
    if (out.layout_category && !LAYOUTS.includes(out.layout_category)) out.layout_category = 'mujer';
    if (out.voice && !VOICES.includes(out.voice)) out.voice = 'mujer_1';
    if (out.bgm_mood && !BGM.includes(out.bgm_mood)) out.bgm_mood = 'urgencia';
    if (out.sfx_type && !SFX.includes(out.sfx_type)) out.sfx_type = 'transiciones';
    if (out.type === 'ad_video') {
        delete out.text;
        delete out.voice;
        delete out.bgm_mood;
        delete out.sfx_type;
    }
    return out;
}

function assignProductMedia(payload, product) {
    const videos = usableVideos(product);
    const photos = product.photos || [];
    const mainPhoto = photos[0] || '';
    let vi = 0;
    const used = [];

    (payload.scenes || []).forEach((scene) => {
        if (scene.type === 'intro' || scene.type === 'ad_video') return;
        if (scene.type === 'mapa') {
            scene.ubicacion = scene.ubicacion || 'Asunción, Paraguay';
            if (!scene.layout_category) scene.layout_category = 'sin_presentador';
            return;
        }
        if (['body', 'product_video', 'ad_mencion', 'pexels'].includes(scene.type)) {
            scene.type = 'product_video';
            if (videos.length) {
                const clip = videos[vi % videos.length];
                vi += 1;
                scene.video_url = clip.url;
                scene.ad_media_url = clip.url;
                used.push(clip.url);
            }
            scene.image_url = photos[vi % Math.max(photos.length, 1)] || mainPhoto || scene.image_url || '';
            if (!scene.layout_category) scene.layout_category = 'mujer';
            if (!scene.voice) scene.voice = 'mujer_1';
            if (!scene.bgm_mood) scene.bgm_mood = 'analisis';
            if (!scene.sfx_type) scene.sfx_type = 'transiciones';
        }
    });

    payload.video_urls_used = [...new Set(used)];
    return payload;
}

function ensureCtaAndMap(payload, shop, product) {
    const scenes = payload.scenes || [];
    const allText = scenes.map((s) => s.text || '').join(' ');
    const hasPhone = allText.includes(shop.phoneDisplay)
        || allText.includes(shop.phone)
        || /whatsapp|0987|0981|0982|0983|0984|0985|0986/i.test(allText);
    const hasMotobolt = /motobolt/i.test(allText);
    const hasMapa = scenes.some((s) => s.type === 'mapa');
    const photo = (product.photos || [])[0] || '';
    const clip = usableVideos(product)[0];

    if (!hasMapa) {
        const mapa = {
            type: 'mapa',
            ubicacion: 'Asunción, Paraguay',
            layout_category: 'sin_presentador',
            text: hasMotobolt
                ? `Somos ${shop.name} en Paraguay. Pedí por WhatsApp al ${shop.phoneDisplay} y te lo enviamos.`
                : `Somos ${shop.name} en Paraguay. Envíos por Motobolt en Central y alrededores. WhatsApp ${shop.phoneDisplay}.`,
            voice: 'mujer_1',
            bgm_mood: 'analisis',
            sfx_type: 'alertas'
        };
        const insertAt = Math.max(scenes.length - 1, 1);
        scenes.splice(insertAt, 0, mapa);
    }

    if (!hasPhone) {
        scenes.push({
            type: 'product_video',
            video_url: clip?.url || '',
            ad_media_url: clip?.url || '',
            image_url: photo,
            layout_category: 'mujer',
            text: `Pedilo ahora al WhatsApp ${shop.phoneDisplay}. Envíos por Motobolt en Central y alrededores, Paraguay.`,
            voice: 'mujer_1',
            bgm_mood: 'urgencia',
            sfx_type: 'impactos'
        });
    }

    payload.scenes = scenes;
    return payload;
}

function metrics(payload) {
    const scenes = payload?.scenes || [];
    let words = 0;
    scenes.forEach((s) => {
        if (s.type === 'ad_video') return;
        words += countWords(s.text);
    });
    return {
        sceneCount: scenes.length,
        words,
        estimatedSeconds: Math.round((words / 2.5) * 10) / 10
    };
}

function buildPrompt({ shop, product, videoSlots }) {
    const variantes = product.variants.length
        ? product.variants.join(', ')
        : 'sin variantes, stock general';
    const slots = videoSlots.map((s, i) => `VIDEO_${i + 1}`).join(', ');

    return `Eres el Director TÉCNICO de un canal de YouTube Shorts de VENTA de ${shop.name}. Tu trabajo es transformar un producto real en un guion JSON estricto para un motor de renderizado FFmpeg vertical. El video tiene que ser VIRAL y vender.

    PRODUCTO A CONVERTIR:
    Nombre: "${product.name}"
    Categoría: "${product.categoryName}"
    Precio: "${product.priceLabel}"
    Stock disponible: ${product.stock}
    Variantes con stock: ${variantes}
    Descripción real: "${product.description}"
    Fotos: ${product.photos[0] || 'sin foto'}
    Clips reales del producto (Cloudflare R2): ${slots || 'VIDEO_1'}
    Link de la tienda: ${product.productUrl}

    DATOS OBLIGATORIOS DE LA TIENDA (tenés que decirlos en el guion, no los inventes):
    - Somos ${shop.name} de Paraguay (Asunción).
    - Envíos por Motobolt en Central y alrededores (Gran Asunción, hasta ${shop.motoboltMaxKm} km). Interior por transportadora.
    - WhatsApp de ventas: ${shop.phoneDisplay}
    - Pedidos: ${shop.web} o WhatsApp.
    - Hablá de lo que realmente es el producto. Si es pestañas, libro de pestañas, racimos o un look DIY para hacerse en casa, explicalo con ganas. No inventes beneficios médicos.

    REGLAS ABSOLUTAS Y CRÍTICAS (SI FALLAS, EL SISTEMA EXPLOTARÁ):
    1. El campo "text" en TODAS las escenas es ÚNICA Y EXCLUSIVAMENTE lo que la locutora va a decir en voz alta (TTS). ¡NUNCA pongas descripciones de cámara!
    2. Voz SIEMPRE "mujer_1" y layout_category "mujer" o "sin_presentador" (tienda de belleza, vendedora paraguaya, tuteo "vos", cercana, sin sonar a robot).
    3. Si la escena es "type": "product_video", poné "video_url" con VIDEO_1, VIDEO_2, etc. (NO inventes https). En cada escena product_video va 1 solo clip. Si hay menos clips que escenas, repetí en orden.
    4. Si la escena es "type": "body", incluí "image_url" con la foto del producto. Preferí product_video antes que body.
    5. MAPAS: incluí EXACTAMENTE UNA escena "type": "mapa" con "ubicacion": "Asunción, Paraguay" para el envío Motobolt.
    6. CANTIDAD DE ESCENAS (¡CRÍTICO!): Debes generar EXACTAMENTE entre 8 a 9 escenas en total (intro + producto + mapa + cierre de venta).
    7. MATEMÁTICA DEL TIEMPO (¡CRÍTICO!): Para que el Short dure exactamente 80 a 82 segundos, el total de palabras de todos los campos "text" sumados DEBE estar ESTRICTAMENTE entre 195 a 205 palabras. Distribuye (aprox 20-25 palabras por escena, intro de 10-15 palabras).
    8. La PRIMERA escena es "intro" (gancho viral de venta, máximo 15 palabras). La ÚLTIMA escena cierra la venta con el WhatsApp ${shop.phoneDisplay}.
    9. Mencioná el precio ${product.priceLabel} al menos una vez. Mencioná Motobolt / Paraguay / el teléfono.
    10. DEVUELVE ÚNICAMENTE UN JSON VÁLIDO. SIN MARKDOWN, SIN TEXTO EXTRA.

    DICCIONARIO DE VARIABLES PERMITIDAS:
    - "type": "intro", "body", "product_video", "mapa".
    - "layout_category": "mujer", "sin_presentador".
    - "voice": "mujer_1".
    - "bgm_mood": "urgencia", "analisis", "tension".
    - "sfx_type": "impactos", "transiciones", "alertas", "tecnologia".
    - "video_url": VIDEO_1, VIDEO_2... (solo product_video).
    - "image_url": URL de foto (body o fallback).
    - "ubicacion": para type mapa.

    FORMATO JSON EXACTO QUE DEBES REPLICAR:
    {
      "youtube_title": "Título llamativo de venta para Shorts (sin clickbait falso)",
      "youtube_description": "Descripción optimizada...",
      "youtube_tags": ["ferumishop", "pestañas", "paraguay", "shorts"],
      "scenes": [
        {
          "type": "intro",
          "text": "¡Estas pestañas te dejan la mirada de muñeca en dos minutos, linda!",
          "layout_category": "sin_presentador",
          "voice": "mujer_1",
          "bgm_mood": "urgencia",
          "sfx_type": "impactos"
        },
        {
          "type": "product_video",
          "video_url": "VIDEO_1",
          "image_url": "${product.photos[0] || ''}",
          "layout_category": "mujer",
          "text": "Mirá el efecto de cerca: volumen de racimo, fácil de poner y queda divino para un look DIY en casa.",
          "voice": "mujer_1",
          "bgm_mood": "analisis",
          "sfx_type": "transiciones"
        },
        {
          "type": "mapa",
          "ubicacion": "Asunción, Paraguay",
          "layout_category": "sin_presentador",
          "text": "Somos Ferumishop en Paraguay y enviamos por Motobolt en Central y alrededores.",
          "voice": "mujer_1",
          "bgm_mood": "analisis",
          "sfx_type": "alertas"
        }
      ]
    }`;
}

function resolveVideoPlaceholders(payload, product) {
    const videos = usableVideos(product);
    (payload.scenes || []).forEach((scene) => {
        const raw = String(scene.video_url || scene.ad_media_url || '');
        const m = raw.match(/VIDEO_(\d+)/i);
        if (m && videos.length) {
            const idx = Math.max(0, Number(m[1]) - 1) % videos.length;
            scene.video_url = videos[idx].url;
            scene.ad_media_url = videos[idx].url;
        }
    });
    return payload;
}

function finalizePayload(rawPayload, { shop, product, jobId }) {
    const payload = { ...(rawPayload || {}) };
    payload.scenes = Array.isArray(payload.scenes) ? payload.scenes.map(sanitizeScene) : [];
    if (!payload.scenes.length) throw new Error('La IA no devolvió escenas.');

    resolveVideoPlaceholders(payload, product);
    assignProductMedia(payload, product);
    ensureCtaAndMap(payload, shop, product);
    payload.scenes = payload.scenes.map(sanitizeScene);

    payload.youtube_title = String(payload.youtube_title || `${product.name} | ${shop.name}`).slice(0, 100);
    payload.youtube_tags = Array.isArray(payload.youtube_tags) && payload.youtube_tags.length
        ? payload.youtube_tags
        : ['ferumishop', 'paraguay', 'shorts', 'belleza', 'pestañas', 'diy'];
    payload.youtube_description = youtubeDescription(shop, product, stripHtml(payload.youtube_description || ''));

    payload.article_id = String(jobId || product._id || product.id);
    payload.product_id = String(product._id || product.id);
    payload.shop = 'ferumishop';
    payload.kind = 'ferumishop_short';
    payload.metrics = metrics(payload);
    return payload;
}

async function generateProductVideoScenesJSON(product, siteConfig, { jobId } = {}) {
    const shop = shopContext(siteConfig);
    const brief = productBrief(product);
    const videos = usableVideos(product);
    if (!videos.length) throw new Error('El producto no tiene videos en Cloudflare R2.');
    if (brief.stock <= 0) throw new Error('El producto no tiene stock.');

    const prompt = buildPrompt({ shop, product: brief, videoSlots: videos });
    console.log(`[Gemma Shorts Director] Producto ${brief.name}. Creando JSON viral de ${videos.length} clip(s) R2...`);

    const jsonText = await gemma.generateContentWithRetry(prompt);
    const parsed = gemma.extractJsonObject(jsonText);
    return finalizePayload(parsed, { shop, product, jobId: jobId || brief.id });
}

module.exports = {
    SCENE_TYPES,
    DEFAULT_SHOP,
    stripHtml,
    formatGs,
    formatPyPhone,
    countWords,
    shopContext,
    productStock,
    usableVideos,
    isEligibleProduct,
    productBrief,
    youtubeDescription,
    sanitizeScene,
    assignProductMedia,
    ensureCtaAndMap,
    metrics,
    buildPrompt,
    resolveVideoPlaceholders,
    finalizePayload,
    generateProductVideoScenesJSON
};
