'use strict';

const crypto = require('crypto');

const PAGOPAR_API = 'https://api.pagopar.com/api';
const PAGOPAR_PAY_URL = 'https://www.pagopar.com/pagos';

function sha1(value) {
    return crypto.createHash('sha1').update(String(value)).digest('hex');
}

function getKeys() {
    const privateKey = String(process.env.PAGOPAR_PRIVATE_KEY || '').trim();
    const publicKey = String(process.env.PAGOPAR_PUBLIC_KEY || '').trim();
    return { privateKey, publicKey };
}

function tokenIniciar(orderId, montoTotal) {
    const { privateKey } = getKeys();
    return sha1(privateKey + String(orderId) + String(montoTotal));
}

function tokenConsulta() {
    const { privateKey } = getKeys();
    return sha1(privateKey + 'CONSULTA');
}

function tokenWebhook(hashPedido) {
    const { privateKey } = getKeys();
    return sha1(privateKey + String(hashPedido || ''));
}

function timingSafeEqual(a, b) {
    const aa = Buffer.from(String(a || ''));
    const bb = Buffer.from(String(b || ''));
    if (aa.length !== bb.length) return false;
    return crypto.timingSafeEqual(aa, bb);
}

function extractResultado(body) {
    if (!body) return null;
    if (Array.isArray(body.resultado) && body.resultado.length) return body.resultado[0];
    if (Array.isArray(body) && body.length) return body[0];
    if (body.hash_pedido || body.pagado !== undefined) return body;
    return null;
}

function fechaMaximaPago(days = 3) {
    const maxDate = new Date();
    maxDate.setDate(maxDate.getDate() + days);
    return maxDate.toISOString().replace('T', ' ').substring(0, 19);
}

function alignCompraItems(comprasItems, montoTotal) {
    const copy = (comprasItems || []).map((item) => ({ ...item }));
    const target = parseInt(montoTotal, 10) || 0;
    const sum = copy.reduce((total, item) => total + (Number(item.precio_total) || 0), 0);
    const diff = target - sum;
    if (!diff || !copy.length) return copy;
    if (diff > 0) {
        const sample = copy[0] || {};
        copy.push({
            ciudad: '1',
            nombre: 'Envio',
            cantidad: 1,
            categoria: '909',
            public_key: sample.public_key || '',
            url_imagen: sample.url_imagen || 'https://ferumi.shop/ferumi.logo.png',
            descripcion: 'Envio',
            id_producto: 990,
            precio_total: diff,
            vendedor_telefono: '',
            vendedor_direccion: '',
            vendedor_direccion_referencia: '',
            vendedor_direccion_coordenadas: ''
        });
        return copy;
    }
    let rest = -diff;
    for (let index = copy.length - 1; index >= 0 && rest > 0; index -= 1) {
        const current = Number(copy[index].precio_total) || 0;
        const take = Math.min(Math.max(0, current - 1), rest);
        if (take > 0) {
            copy[index].precio_total = current - take;
            rest -= take;
        }
    }
    return copy;
}

async function iniciarTransaccion({ orderId, montoTotal, customer, items, descripcion, timeoutMs = 20000 }) {
    const { publicKey } = getKeys();
    const token = tokenIniciar(orderId, montoTotal);

    const comprasItems = (items && items.length ? items : [{
        name: descripcion || 'Compra en FERUMI',
        quantity: 1,
        price: montoTotal,
        image: 'https://ferumi.shop/ferumi.logo.png'
    }]).map((item, index) => ({
        ciudad: '1',
        nombre: String(item.name || 'Producto FERUMI').slice(0, 120),
        cantidad: parseInt(item.quantity, 10) || 1,
        categoria: '909',
        public_key: publicKey,
        url_imagen: item.image || 'https://ferumi.shop/ferumi.logo.png',
        descripcion: String(item.name || 'Compra en FERUMI').slice(0, 200),
        id_producto: Number.isFinite(Number(item.productId)) ? Number(item.productId) : (895 + index),
        precio_total: parseInt(item.price, 10) * (parseInt(item.quantity, 10) || 1),
        vendedor_telefono: '',
        vendedor_direccion: '',
        vendedor_direccion_referencia: '',
        vendedor_direccion_coordenadas: ''
    }));
    const balancedItems = alignCompraItems(comprasItems, montoTotal);

    const payload = {
        token,
        comprador: {
            ruc: customer.document ? `${customer.document}-0` : '',
            email: customer.email,
            ciudad: customer.cityId || null,
            nombre: customer.name,
            telefono: customer.phone,
            direccion: customer.address || '',
            documento: customer.document,
            coordenadas: customer.coords || '',
            razon_social: customer.name,
            tipo_documento: 'CI',
            direccion_referencia: customer.reference || null
        },
        public_key: publicKey,
        monto_total: parseInt(montoTotal, 10),
        tipo_pedido: 'VENTA-COMERCIO',
        compras_items: balancedItems,
        fecha_maxima_pago: fechaMaximaPago(3),
        id_pedido_comercio: String(orderId),
        descripcion_resumen: descripcion || 'Compra en FERUMI'
        // forma_pago se omite a propósito: Pagopar muestra todos los medios (tarjetas, Tigo, bocas, etc.)
    };

    const response = await fetch(`${PAGOPAR_API}/comercios/2.0/iniciar-transaccion`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs)
    });

    const raw = await response.text();
    let result;
    try {
        result = raw ? JSON.parse(raw) : {};
    } catch {
        const error = new Error('PagoPar respondió sin un JSON válido.');
        error.status = response.status;
        error.uncertain = response.status >= 500 || response.status === 0;
        throw error;
    }
    if (!response.ok && response.status >= 500) {
        const error = new Error('PagoPar no confirmó el resultado de la operación.');
        error.status = response.status;
        error.uncertain = true;
        error.payload = result;
        throw error;
    }
    return { result, payload };
}

async function consultarPedido(hashPedido) {
    const { publicKey } = getKeys();
    if (!hashPedido) {
        return { respuesta: false, resultado: [], error: 'hash_pedido vacío' };
    }

    const payload = {
        hash_pedido: String(hashPedido),
        token: tokenConsulta(),
        token_publico: publicKey
    };

    const response = await fetch(`${PAGOPAR_API}/pedidos/1.1/traer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    const result = await response.json();
    return result;
}

function checkoutUrl(hash) {
    return `${PAGOPAR_PAY_URL}/${hash}`;
}

module.exports = {
    sha1,
    getKeys,
    tokenIniciar,
    tokenConsulta,
    tokenWebhook,
    timingSafeEqual,
    extractResultado,
    fechaMaximaPago,
    alignCompraItems,
    iniciarTransaccion,
    consultarPedido,
    checkoutUrl,
    PAGOPAR_API,
    PAGOPAR_PAY_URL
};
