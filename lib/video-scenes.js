'use strict';

/**
 * Director de Shorts de venta FERUMI.
 * Contrato exacto de n14-py/ferumishopvideos:
 *   article_id, youtube_*, whatsapp, texto_pantalla,
 *   scenes[] = { type: "video", text, texto_pantalla, video_url, voice }
 *
 * Sin mapa. text = locución TTS. texto_pantalla = overlay por escena.
 * El Short no puede llegar a 90s: techo duro 85s.
 */

const gemma = require('./gemma');
const r2 = require('./r2');

const VOICES = ['mujer_1', 'mujer_2', 'hombre_1', 'hombre_2'];
const CLIP_TYPES = new Set([
    'video', 'clip', 'body', 'pexels', 'intro',
    'ad_video', 'ad_mencion', 'product', 'product_video', 'foto', 'image'
]);
const SKIP_TYPES = new Set(['mapa', 'map']);

const MAX_SECONDS = 85;
const TARGET_SECONDS = 80;
const WORDS_PER_SEC = 2.5;
const TRANSITION_SEC = 0.38;
const MAX_WORDS = 200;
const TARGET_WORDS_MIN = 170;
const TARGET_WORDS_MAX = 190;
const OVERLAY_MAX_CHARS = 42;
const SCENE_MIN = 7;
const SCENE_MAX = 8;

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

function digitsPhone(raw) {
    const d = String(raw || '').replace(/\D/g, '');
    return d || DEFAULT_SHOP.phone;
}

function waMe(raw) {
    const d = digitsPhone(raw);
    return `https://wa.me/${d}`;
}

function countWords(text) {
    return String(text || '').trim().split(/\s+/).filter(Boolean).length;
}

function shopContext(siteConfig = {}) {
    const phone = digitsPhone(siteConfig.whatsappNumber || DEFAULT_SHOP.phone);
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

function shuffleArray(list) {
    const a = Array.isArray(list) ? [...list] : [];
    for (let i = a.length - 1; i > 0; i -= 1) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

function pickRandomItem(list) {
    if (!list || !list.length) return null;
    return list[Math.floor(Math.random() * list.length)];
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

function demoProduct(extra = {}) {
    return {
        _id: 'ferumi_labial_mate_prueba_01',
        name: 'Labial mate Ferumi',
        description: 'Labial mate de Ferumi Shop. Textura suave, no reseca, dura todo el día. Varios tonos, del nude diario al rojo para salir. Envío a Paraguay.',
        price: 35000,
        stock: 18,
        hasVariants: true,
        variants: [
            { name: 'Nude', stock: 6 },
            { name: 'Rosa', stock: 7 },
            { name: 'Rojo', stock: 5 }
        ],
        photos: ['https://img.ferumi.shop/labial-mate.jpg'],
        videos: [
            { url: 'https://videos.ferumi.shop/productos/prueba/clip1_hook.mp4', key: 'c1', originalName: 'clip1_hook.mp4' },
            { url: 'https://videos.ferumi.shop/productos/prueba/clip2_producto.mp4', key: 'c2', originalName: 'clip2_producto.mp4' },
            { url: 'https://videos.ferumi.shop/productos/prueba/clip3_textura.mp4', key: 'c3', originalName: 'clip3_textura.mp4' },
            { url: 'https://videos.ferumi.shop/productos/prueba/clip4_tonos.mp4', key: 'c4', originalName: 'clip4_tonos.mp4' }
        ],
        category: { name: 'Labiales' },
        isForSale: true,
        ...extra
    };
}

function youtubeDescription(shop, product, extra = '') {
    const tags = ['#shorts', '#ferumishop', '#paraguay', '#belleza', '#maquillaje'].join(' ');
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

function sanitizeTts(text) {
    return String(text || '')
        .replace(/\n/g, ' ')
        .replace(/\s+/g, ' ')
        .replace(/["']/g, '')
        .trim();
}

function sanitizeOverlay(text, fallback) {
    let out = String(text || '')
        .replace(/[\r\n]+/g, ' ')
        .replace(/['":\\]/g, '')
        .replace(/[^\w\s\.\,\!\?\-áéíóúÁÉÍÓÚñÑ¿¡%]/gi, '')
        .replace(/\s+/g, ' ')
        .trim();
    if (!out) out = String(fallback || 'Ferumi Shop').trim();
    if (out.length > OVERLAY_MAX_CHARS) out = out.slice(0, OVERLAY_MAX_CHARS).trim();
    return out;
}

function overlayFromText(text, fallback) {
    const words = sanitizeTts(text)
        .replace(/[¡!¿?.,]/g, '')
        .split(/\s+/)
        .filter(Boolean);
    let out = '';
    for (const word of words.slice(0, 6)) {
        const next = out ? `${out} ${word}` : word;
        if (next.length > OVERLAY_MAX_CHARS) break;
        out = next;
    }
    return sanitizeOverlay(out, fallback);
}

function sceneType(raw) {
    const type = String(raw || 'video').toLowerCase().trim();
    if (SKIP_TYPES.has(type)) return 'mapa';
    if (CLIP_TYPES.has(type) || type === 'video') return 'video';
    return 'video';
}

function sanitizeScene(scene, fallbackOverlay) {
    const out = { ...(scene || {}) };
    out.type = sceneType(out.type);
    out.text = sanitizeTts(out.text);
    out.texto_pantalla = sanitizeOverlay(
        out.texto_pantalla || out.overlay_text || out.on_screen_text || out.caption,
        overlayFromText(out.text, fallbackOverlay)
    );
    if (out.voice && !VOICES.includes(out.voice)) out.voice = 'mujer_1';
    if (!out.voice) out.voice = 'mujer_1';
    delete out.layout_category;
    delete out.bgm_mood;
    delete out.sfx_type;
    delete out.ubicacion;
    delete out.overlay_text;
    delete out.on_screen_text;
    delete out.caption;
    return out;
}

function resolveVideoPlaceholders(payload, product) {
    const videos = usableVideos(product);
    (payload.scenes || []).forEach((scene) => {
        const raw = String(scene.video_url || scene.ad_media_url || scene.media_url || '');
        const m = raw.match(/VIDEO_(\d+)/i);
        if (m && videos.length) {
            const idx = Math.max(0, Number(m[1]) - 1) % videos.length;
            scene.video_url = videos[idx].url;
        }
    });
    return payload;
}

function assignProductMedia(payload, product, { random = false } = {}) {
    const videos = usableVideos(product);
    let vi = 0;
    const used = [];

    (payload.scenes || []).forEach((scene) => {
        if (scene.type === 'mapa') return;
        scene.type = 'video';
        if (videos.length) {
            const already = String(scene.video_url || '');
            const known = videos.find((v) => v.url === already);
            let clip;
            if (random) {
                clip = pickRandomItem(videos);
            } else {
                clip = known || videos[vi % videos.length];
                vi += 1;
            }
            if (clip) {
                scene.video_url = clip.url;
                used.push(clip.url);
            }
        }
        if (!scene.voice) scene.voice = 'mujer_1';
    });

    payload.video_urls_used = [...new Set(used)];
    return payload;
}

function dropMapScenes(payload) {
    payload.scenes = (payload.scenes || []).filter((s) => sceneType(s.type) !== 'mapa');
    return payload;
}

function ensureCta(payload, shop, product) {
    const scenes = payload.scenes || [];
    const allText = scenes.map((s) => s.text || '').join(' ');
    const hasPhone = allText.includes(shop.phoneDisplay)
        || allText.includes(shop.phone)
        || /whatsapp|0987|0981|0982|0983|0984|0985|0986/i.test(allText);
    const hasMotobolt = /motobolt/i.test(allText);
    const clip = usableVideos(product)[0];

    if (!hasPhone || !hasMotobolt) {
        const bits = [];
        if (!hasMotobolt) bits.push(`Envíos por Motobolt en Central y alrededores, Paraguay.`);
        if (!hasPhone) bits.push(`Pedilo ahora al WhatsApp ${shop.phoneDisplay}.`);
        const last = scenes[scenes.length - 1];
        const canAppend = last && (countWords(last.text) < 28 || scenes.length >= SCENE_MAX);
        if (canAppend) {
            last.text = sanitizeTts(`${last.text} ${bits.join(' ')}`);
            if (!/whatsapp|ferumi/i.test(last.texto_pantalla || '')) {
                last.texto_pantalla = hasPhone ? 'Envío Motobolt' : 'Pedilo por WhatsApp';
            }
        } else {
            scenes.push({
                type: 'video',
                video_url: clip?.url || '',
                text: bits.join(' ') || `Pedilo ahora al WhatsApp ${shop.phoneDisplay}. Envíos por Motobolt en Central y alrededores, Paraguay.`,
                texto_pantalla: 'Pedilo por WhatsApp',
                voice: 'mujer_1'
            });
        }
    }

    payload.scenes = scenes;
    return payload;
}

function estimatedSeconds(payload) {
    const scenes = (payload?.scenes || []).filter((s) => s.type !== 'ad_video');
    const words = scenes.reduce((n, s) => n + countWords(s.text), 0);
    const tts = words / WORDS_PER_SEC;
    const transitions = Math.max(0, scenes.length - 1) * TRANSITION_SEC;
    return Math.round((tts + transitions) * 10) / 10;
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
        estimatedSeconds: estimatedSeconds(payload),
        maxSeconds: MAX_SECONDS
    };
}

function shortenText(text, removeWords) {
    const parts = String(text || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length <= 8) return parts.join(' ');
    const cut = Math.min(removeWords, Math.max(1, parts.length - 8));
    return parts.slice(0, parts.length - cut).join(' ');
}

function clampDuration(payload) {
    let guard = 0;
    const tooLong = () => estimatedSeconds(payload) > MAX_SECONDS || metrics(payload).words > MAX_WORDS;
    while (tooLong() && guard < 60) {
        const list = payload.scenes || [];
        let idx = -1;
        let best = 0;
        list.forEach((s, i) => {
            if (i === 0 || i === list.length - 1) return;
            const n = countWords(s.text);
            if (n > best) {
                best = n;
                idx = i;
            }
        });
        if (idx < 0 || best <= 10) break;
        list[idx].text = shortenText(list[idx].text, Math.max(4, Math.ceil(best * 0.15)));
        guard += 1;
    }
    if ((payload.scenes || []).length > SCENE_MAX) {
        const first = payload.scenes[0];
        const last = payload.scenes[payload.scenes.length - 1];
        const mid = payload.scenes.slice(1, -1).slice(0, SCENE_MAX - 2);
        payload.scenes = [first, ...mid, last];
    }
    if (tooLong()) {
        const list = payload.scenes || [];
        const keepFirst = countWords(list[0]?.text);
        const keepLast = countWords(list[list.length - 1]?.text);
        const midBudget = Math.max(40, MAX_WORDS - keepFirst - keepLast);
        const mid = list.slice(1, -1);
        const midWords = mid.reduce((n, s) => n + countWords(s.text), 0) || 1;
        mid.forEach((s) => {
            const share = Math.max(8, Math.floor((countWords(s.text) / midWords) * midBudget));
            const parts = String(s.text || '').split(/\s+/).filter(Boolean);
            if (parts.length > share) s.text = parts.slice(0, share).join(' ');
        });
    }
    return payload;
}

function clampSceneCount(payload, product) {
    let list = payload.scenes || [];
    if (list.length > SCENE_MAX) {
        const first = list[0];
        const last = list[list.length - 1];
        const mid = list.slice(1, -1).slice(0, SCENE_MAX - 2);
        list = [first, ...mid, last];
    }
    if (list.length < SCENE_MIN && usableVideos(product).length) {
        const clip = usableVideos(product)[0];
        const insertAt = Math.max(list.length - 1, 0);
        while (list.length < SCENE_MIN) {
            list.splice(insertAt, 0, {
                type: 'video',
                video_url: clip.url,
                text: `${product.name} de Ferumishop. Calidad de tienda, precio claro y te llega a Paraguay.`,
                texto_pantalla: String(product.name || 'Ferumi Shop').slice(0, OVERLAY_MAX_CHARS),
                voice: 'mujer_1'
            });
        }
    }
    payload.scenes = list;
    return payload;
}

function buildPrompt({ shop, product, videoSlots }) {
    const variantes = product.variants.length
        ? product.variants.join(', ')
        : 'sin variantes, stock general';
    const slots = videoSlots.map((_, i) => `VIDEO_${i + 1}`).join(', ');

    return `Eres el Director de Shorts de VENTA de ${shop.name}. Tu trabajo es un guion JSON para el motor ferumishopvideos: video tras video, texto arriba, logo y WhatsApp. El Short tiene que VENDER, no informar.

PRODUCTO:
Nombre: "${product.name}"
Categoría: "${product.categoryName}"
Precio: "${product.priceLabel}"
Stock: ${product.stock}
Variantes con stock: ${variantes}
Descripción: "${product.description}"
Clips reales (Cloudflare R2): ${slots || 'VIDEO_1'}
Link: ${product.productUrl}

TIENDA (decilos en la locución, no inventes otros):
- ${shop.name}, Paraguay (Asunción).
- Envíos Motobolt en Central y alrededores (hasta ${shop.motoboltMaxKm} km). Interior por transportadora.
- WhatsApp: ${shop.phoneDisplay}
- Web: ${shop.web}
- Tratá de "vos", cercana, vendedora paraguaya. Sin sonar a robot ni a médico.

REGLAS ABSOLUTAS:
1. "text" = SOLO lo que se dice en voz alta (TTS). Nunca describas la cámara.
2. "texto_pantalla" = titular CORTO en pantalla para ESA escena (máximo 6 palabras, estilo TikTok, sin comillas). UNA frase distinta por escena. Es obligatorio en TODAS las escenas.
3. TODAS las escenas son "type": "video". PROHIBIDO "mapa", "map", "intro", "body", "product_video".
4. NO hay mapa. Cero escenas de mapa. El motor de Ferumi ya no usa mapas.
5. voice SIEMPRE "mujer_1".
6. EXACTAMENTE 8 escenas. video_url con VIDEO_1, VIDEO_2... (NO inventes https). 1 clip por escena. Si hay menos clips, repetí en orden.
7. TIEMPO: el Short NO puede llegar a 90 segundos. Máximo 85s. Suma de palabras de todos los "text": ESTRICTAMENTE entre ${TARGET_WORDS_MIN} y ${TARGET_WORDS_MAX} palabras (aprox 21-24 por escena). Si te pasás, el render se corta.
8. Estructura de venta: 1 gancho (dolor/deseo, 3 segundos), 2 producto, 3 beneficio sensorial, 4 prueba/resultado, 5 variantes o uso, 6 precio ${product.priceLabel}, 7 envío Motobolt Paraguay, 8 cierre WhatsApp ${shop.phoneDisplay} + ${shop.web}.
9. Mencioná el precio al menos una vez. Mencioná Motobolt, Paraguay y el teléfono. Vendé con ganas: urgencia suave, resultado, "pedilo ahora".
10. DEVUELVE ÚNICAMENTE UN JSON VÁLIDO. SIN MARKDOWN.

FORMATO EXACTO (el VPS ferumishopvideos lee estos campos):
{
  "youtube_title": "Título de venta para Shorts",
  "youtube_description": "Descripción corta con hashtags",
  "youtube_tags": ["ferumishop", "paraguay", "shorts"],
  "whatsapp": "${shop.phone}",
  "texto_pantalla": "${product.name}",
  "scenes": [
    {
      "type": "video",
      "text": "¿Cansada de que el producto no te dure, linda?",
      "texto_pantalla": "¿Te dura poco?",
      "video_url": "VIDEO_1",
      "voice": "mujer_1"
    }
  ]
}`;
}

function assertPayloadForBot(payload) {
    const errors = [];
    if (!payload || typeof payload !== 'object') errors.push('JSON vacío.');
    const scenes = payload?.scenes || [];
    if (scenes.length < SCENE_MIN) errors.push(`Hacen falta ${SCENE_MIN} a ${SCENE_MAX} escenas, hay ${scenes.length}.`);
    if (scenes.length > SCENE_MAX) errors.push(`Hay ${scenes.length} escenas; el máximo es ${SCENE_MAX}.`);
    if (scenes.some((s) => s.type === 'mapa' || s.type === 'map')) errors.push('El JSON no puede llevar mapa.');
    if (scenes.some((s) => s.type !== 'video')) errors.push('Todas las escenas deben ser type "video".');
    scenes.forEach((s, i) => {
        if (!s.text) errors.push(`Escena ${i + 1} sin locución text.`);
        if (!s.texto_pantalla) errors.push(`Escena ${i + 1} sin texto_pantalla.`);
        if (!s.video_url || !String(s.video_url).startsWith('http')) errors.push(`Escena ${i + 1} sin video_url http.`);
        if (s.voice && s.voice !== 'mujer_1') errors.push(`Escena ${i + 1} voice distinto de mujer_1.`);
    });
    if (!payload?.whatsapp) errors.push('Falta whatsapp en la raíz.');
    const m = metrics(payload);
    if (m.estimatedSeconds > MAX_SECONDS) {
        errors.push(`Duración estimada ${m.estimatedSeconds}s supera el máximo de ${MAX_SECONDS}s.`);
    }
    return { ok: errors.length === 0, errors, metrics: m };
}

function finalizePayload(rawPayload, { shop, product, jobId }) {
    const payload = { ...(rawPayload || {}) };
    const fallbackOverlay = String(product.name || shop.name).slice(0, OVERLAY_MAX_CHARS);

    payload.scenes = Array.isArray(payload.scenes) ? payload.scenes.map((s) => sanitizeScene(s, fallbackOverlay)) : [];
    dropMapScenes(payload);
    if (!payload.scenes.length) throw new Error('La IA no devolvió escenas.');

    resolveVideoPlaceholders(payload, product);
    ensureCta(payload, shop, product);
    clampSceneCount(payload, product);
    payload.scenes = payload.scenes.map((s) => sanitizeScene(s, fallbackOverlay));
    assignProductMedia(payload, product, { random: true });
    clampDuration(payload);

    payload.youtube_title = String(payload.youtube_title || `${product.name} | ${shop.name}`).slice(0, 100);
    payload.youtube_tags = Array.isArray(payload.youtube_tags) && payload.youtube_tags.length
        ? payload.youtube_tags
        : ['ferumishop', 'paraguay', 'shorts', 'belleza', 'maquillaje'];
    payload.youtube_description = youtubeDescription(shop, product, stripHtml(payload.youtube_description || ''));
    payload.whatsapp = digitsPhone(payload.whatsapp || shop.phone);
    payload.texto_pantalla = sanitizeOverlay(payload.texto_pantalla, product.name);

    payload.article_id = String(jobId || product._id || product.id);
    payload.product_id = String(product._id || product.id);
    payload.shop = 'ferumishop';
    payload.kind = 'ferumishop_short';
    payload.metrics = metrics(payload);

    const check = assertPayloadForBot(payload);
    if (!check.ok) {
        const fatal = check.errors.filter((e) => /mapa|type "video"|video_url|locución|texto_pantalla|escenas/.test(e));
        if (fatal.length) {
            console.warn('[Gemma Shorts] JSON ajustado con avisos:', check.errors.join(' | '));
        }
    }
    if (payload.metrics.estimatedSeconds > MAX_SECONDS) {
        throw new Error(`El guion quedó en ${payload.metrics.estimatedSeconds}s (máximo ${MAX_SECONDS}s).`);
    }
    return payload;
}

async function generateProductVideoScenesJSON(product, siteConfig, { jobId } = {}) {
    const shop = shopContext(siteConfig);
    const brief = productBrief(product);
    const videos = shuffleArray(usableVideos(product));
    if (!videos.length) throw new Error('El producto no tiene videos en Cloudflare R2.');
    if (brief.stock <= 0) throw new Error('El producto no tiene stock.');
    product.videos = videos;

    const prompt = buildPrompt({ shop, product: brief, videoSlots: videos });
    console.log(`[Gemma Shorts Director] ${brief.name}: JSON de venta (${videos.length} clip(s) R2 aleatorios, max ${MAX_SECONDS}s)...`);

    const jsonText = await gemma.generateContentWithRetry(prompt);
    const parsed = gemma.extractJsonObject(jsonText);
    return finalizePayload(parsed, { shop, product, jobId: jobId || brief.id });
}

module.exports = {
    MAX_SECONDS,
    TARGET_SECONDS,
    MAX_WORDS,
    DEFAULT_SHOP,
    stripHtml,
    formatGs,
    formatPyPhone,
    digitsPhone,
    countWords,
    shopContext,
    productStock,
    usableVideos,
    shuffleArray,
    pickRandomItem,
    isEligibleProduct,
    productBrief,
    demoProduct,
    youtubeDescription,
    sanitizeScene,
    sanitizeOverlay,
    overlayFromText,
    assignProductMedia,
    dropMapScenes,
    ensureCta,
    metrics,
    estimatedSeconds,
    clampDuration,
    buildPrompt,
    resolveVideoPlaceholders,
    finalizePayload,
    assertPayloadForBot,
    generateProductVideoScenesJSON
};
