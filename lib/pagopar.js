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

async function iniciarTransaccion({ orderId, montoTotal, customer, items, descripcion }) {
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
        compras_items: comprasItems,
        fecha_maxima_pago: fechaMaximaPago(3),
        id_pedido_comercio: String(orderId),
        descripcion_resumen: descripcion || 'Compra en FERUMI'
        // forma_pago se omite a propósito: Pagopar muestra todos los medios (tarjetas, Tigo, bocas, etc.)
    };

    const response = await fetch(`${PAGOPAR_API}/comercios/2.0/iniciar-transaccion`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    const result = await response.json();
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
    iniciarTransaccion,
    consultarPedido,
    checkoutUrl,
    PAGOPAR_API,
    PAGOPAR_PAY_URL
};
