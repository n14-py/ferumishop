'use strict';

const mongoose = require('mongoose');
const promos = require('../lib/promotions');
const copy = require('../lib/product-copy');
const productForm = require('../lib/product-form');

function list(value) {
    if (Array.isArray(value)) return value;
    if (value == null || value === '') return [];
    return [value];
}

function parseDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function filesByField(files, field) {
    return (files || []).filter((file) => file.fieldname === field);
}

function promoFromBody(body, files, current = {}) {
    const productIds = list(body.productIds).filter((id) => mongoose.Types.ObjectId.isValid(id));
    const priceOverrides = [];
    for (const id of productIds) {
        const raw = body[`override_${id}`];
        const price = productForm.money(raw);
        if (raw !== undefined && raw !== '' && price > 0) priceOverrides.push({ productId: id, price });
    }
    const imageFile = filesByField(files, 'image')[0];
    const bannerFile = filesByField(files, 'banner')[0];
    return {
        title: String(body.title || '').trim(),
        subtitle: String(body.subtitle || '').trim(),
        description: String(body.description || '').trim(),
        commercialText: String(body.commercialText || '').trim(),
        image: imageFile ? imageFile.path : (body.keepImage || current.image || ''),
        banner: bannerFile ? bannerFile.path : (body.keepBanner || current.banner || ''),
        active: body.active === 'on' || body.active === 'true',
        featured: body.featured === 'on' || body.featured === 'true',
        startsAt: parseDate(body.startsAt),
        endsAt: parseDate(body.endsAt),
        discountType: ['percent', 'amount', 'fixed_price'].includes(body.discountType) ? body.discountType : 'percent',
        discountValue: productForm.money(body.discountValue),
        productIds,
        priceOverrides,
        sortOrder: parseInt(body.sortOrder, 10) || 0
    };
}

module.exports = function registerCatalog(app, deps) {
    const { Promotion, Product, requireAdmin, upload } = deps;

    app.get('/promociones', async (req, res, next) => {
        try {
            const all = await Promotion.find().sort({ sortOrder: 1, createdAt: -1 }).lean();
            const active = promos.liveList(all);
            const ids = [...new Set(active.flatMap((promo) => (promo.productIds || []).map(String)))];
            const products = ids.length
                ? await Product.find(productForm.publicFilter({ _id: { $in: ids } })).populate('category')
                : [];
            res.render('public/promociones', {
                pageTitle: 'Promociones',
                seoDescription: 'Promociones vigentes de FERUMI, marca paraguaya de pestañas, belleza y cosméticos.',
                promotions: active,
                products
            });
        } catch (err) {
            next(err);
        }
    });

    app.get('/admin/promociones', requireAdmin, async (req, res, next) => {
        try {
            const [promotions, products] = await Promise.all([
                Promotion.find().sort({ sortOrder: 1, createdAt: -1 }),
                Product.find().select('name price photos').sort({ name: 1 })
            ]);
            res.render('admin/promociones', {
                pageTitle: 'Promociones',
                promotions,
                products,
                now: new Date(),
                isLive: promos.isLive,
                success: req.session.success,
                error: req.session.error
            });
            delete req.session.success;
            delete req.session.error;
        } catch (err) {
            next(err);
        }
    });

    app.post('/admin/promociones/add', requireAdmin, upload.any(), async (req, res) => {
        try {
            const data = promoFromBody(req.body, req.files);
            if (!data.title) throw new Error('La promoción necesita un título.');
            await Promotion.create(data);
            req.session.success = 'Promoción creada.';
        } catch (err) {
            req.session.error = err.message;
        }
        res.redirect('/admin/promociones');
    });

    app.post('/admin/promociones/edit/:id', requireAdmin, upload.any(), async (req, res) => {
        try {
            const current = await Promotion.findById(req.params.id);
            if (!current) throw new Error('Promoción no encontrada.');
            const data = promoFromBody(req.body, req.files, current);
            if (!data.title) throw new Error('La promoción necesita un título.');
            Object.assign(current, data);
            await current.save();
            req.session.success = 'Promoción actualizada.';
        } catch (err) {
            req.session.error = err.message;
        }
        res.redirect('/admin/promociones');
    });

    app.post('/admin/promociones/delete/:id', requireAdmin, async (req, res) => {
        try {
            await Promotion.findByIdAndDelete(req.params.id);
            req.session.success = 'Promoción eliminada.';
        } catch (err) {
            req.session.error = err.message;
        }
        res.redirect('/admin/promociones');
    });

    app.post('/admin/producto/ia', requireAdmin, async (req, res) => {
        try {
            const result = await copy.generate(req.body || {});
            res.json({ success: true, ...result });
        } catch (err) {
            const status = err.status || 500;
            res.status(status).json({ success: false, message: err.message || 'No se pudo generar el contenido.' });
        }
    });

    app.get('/admin/producto/nuevo', requireAdmin, async (req, res, next) => {
        try {
            const Category = mongoose.model('Category');
            const categories = await Category.find().sort({ name: 1 });
            res.render('admin/edit-producto', {
                pageTitle: 'Publicar producto',
                product: productForm.blankProduct(),
                categories,
                creating: true,
                r2Configured: false,
                aiReady: copy.providerReady(),
                success: req.session.success,
                error: req.session.error
            });
            delete req.session.success;
            delete req.session.error;
        } catch (err) {
            next(err);
        }
    });
};
