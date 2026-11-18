'use strict';

const STATUSES = ['activo', 'oculto', 'agotado'];

function asList(value) {
    if (Array.isArray(value)) return value;
    if (value == null || value === '') return [];
    return [value];
}

function lines(value) {
    return asList(value)
        .flatMap((item) => String(item || '').split(/\r?\n/))
        .map((item) => item.trim())
        .filter(Boolean);
}

function tokens(value) {
    return String(value || '')
        .split(/[,;\n]/)
        .map((item) => item.trim())
        .filter(Boolean)
        .slice(0, 40);
}

function money(value) {
    if (typeof value === 'number' && Number.isFinite(value)) return Math.max(0, Math.round(value));
    const digits = String(value ?? '').replace(/\./g, '').replace(/[^\d]/g, '');
    const number = parseInt(digits, 10);
    return Number.isFinite(number) ? number : 0;
}

function on(value) {
    return value === 'on' || value === 'true' || value === true || value === '1';
}

function slugify(text) {
    return String(text || '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 80);
}

function faqsFromBody(body) {
    const questions = asList(body.faqQuestion);
    const answers = asList(body.faqAnswer);
    const faqs = [];
    for (let i = 0; i < questions.length; i += 1) {
        const question = String(questions[i] || '').trim();
        const answer = String(answers[i] || '').trim();
        if (question && answer) faqs.push({ question, answer });
    }
    return faqs.slice(0, 12);
}

function text(purify, value, max = 4000) {
    return purify.sanitize(String(value || '')).slice(0, max);
}

function html(purify, value) {
    return purify.sanitize(String(value || ''), { USE_PROFILES: { html: true } }).slice(0, 20000);
}

function applyContent(product, body, purify) {
    const clean = (value, max) => text(purify, value, max);
    product.commercialTitle = clean(body.commercialTitle, 180);
    product.subtitle = clean(body.subtitle, 220);
    product.shortDescription = clean(body.shortDescription, 400);
    if (body.description != null) product.description = html(purify, body.description);
    product.subcategory = clean(body.subcategory, 80);
    product.brand = clean(body.brand, 80) || 'FERUMI';
    product.tags = tokens(body.tags).map((item) => clean(item, 40));
    product.keywords = tokens(body.keywords).map((item) => clean(item, 40));
    product.sku = clean(body.sku, 60);
    if (body.promoPrice != null && body.promoPrice !== '') product.promoPrice = money(body.promoPrice);
    if (body.displayOrder != null && body.displayOrder !== '') product.displayOrder = parseInt(body.displayOrder, 10) || 0;
    if (body.status) product.status = STATUSES.includes(body.status) ? body.status : 'activo';
    product.isNew = on(body.isNew);
    product.isOnPromo = on(body.isOnPromo);
    if (body.isFeatured != null) product.isFeatured = on(body.isFeatured);
    product.slug = slugify(body.slug || body.commercialTitle || body.name || product.name);
    product.seoTitle = clean(body.seoTitle, 70);
    product.seoDescription = clean(body.seoDescription, 180);
    product.seoKeywords = clean(body.seoKeywords, 200);
    product.ogTitle = clean(body.ogTitle, 90);
    product.ogDescription = clean(body.ogDescription, 200);
    product.ogImage = clean(body.ogImage, 500);
    product.benefits = lines(body.benefits).map((item) => clean(item, 240)).slice(0, 12);
    product.features = lines(body.features).map((item) => clean(item, 240)).slice(0, 16);
    product.howToUse = clean(body.howToUse, 2000);
    product.contents = clean(body.contents, 2000);
    product.extraInfo = clean(body.extraInfo, 2000);
    product.warnings = clean(body.warnings, 2000);
    product.faqs = faqsFromBody(body).map((faq) => ({
        question: clean(faq.question, 180),
        answer: clean(faq.answer, 600)
    }));
    if (body.aiNotes != null) product.aiNotes = clean(body.aiNotes, 1000);
    if (body.aiUsage != null) product.aiUsage = clean(body.aiUsage, 1000);
}

async function uniqueSlug(Product, slug, exceptId) {
    const base = slugify(slug);
    if (!base) return '';
    let candidate = base;
    let n = 2;
    while (n < 40) {
        const query = { slug: candidate };
        if (exceptId) query._id = { $ne: exceptId };
        const exists = await Product.exists(query);
        if (!exists) return candidate;
        candidate = `${base}-${n}`;
        n += 1;
    }
    return `${base}-${Date.now().toString(36)}`;
}

function altsFor(photos, body) {
    const urls = asList(body.photoAltUrl);
    const texts = asList(body.photoAltText);
    const map = new Map();
    urls.forEach((url, index) => map.set(String(url), String(texts[index] || '').trim()));
    const extras = lines(body.newPhotoAlts);
    let cursor = 0;
    return (photos || []).map((url) => {
        if (map.has(String(url))) return map.get(String(url)).slice(0, 180);
        const alt = extras[cursor] || '';
        cursor += 1;
        return alt.slice(0, 180);
    });
}

function blankProduct() {
    return {
        name: '',
        description: '',
        commercialTitle: '',
        subtitle: '',
        shortDescription: '',
        subcategory: '',
        brand: 'FERUMI',
        tags: [],
        keywords: [],
        sku: '',
        costPrice: 0,
        price: '',
        promoPrice: 0,
        stock: 0,
        status: 'activo',
        isFeatured: false,
        isNew: false,
        isOnPromo: false,
        isForSale: true,
        isForRent: false,
        displayOrder: 0,
        hasVariants: false,
        variants: [],
        photos: [],
        photoAlts: [],
        videos: [],
        slug: '',
        seoTitle: '',
        seoDescription: '',
        seoKeywords: '',
        ogTitle: '',
        ogDescription: '',
        ogImage: '',
        benefits: [],
        features: [],
        howToUse: '',
        contents: '',
        faqs: [],
        extraInfo: '',
        warnings: '',
        aiNotes: '',
        aiUsage: '',
        category: null
    };
}

function publicFilter(extra = {}) {
    return {
        isForSale: { $ne: false },
        status: { $ne: 'oculto' },
        ...extra
    };
}

module.exports = {
    STATUSES,
    lines,
    tokens,
    money,
    slugify,
    applyContent,
    uniqueSlug,
    altsFor,
    blankProduct,
    publicFilter,
    faqsFromBody
};
