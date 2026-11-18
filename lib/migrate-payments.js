'use strict';

const { retiredToken } = require('./scrub');

function legacyFields() {
    const token = retiredToken();
    return [
        `${token}Hash`,
        `${token}Numero`,
        `${token}FormaPago`,
        `${token}LastConsulta`,
        `${token}AttemptStatus`,
        `${token}AttemptAt`,
        `${token}AttemptError`
    ];
}

async function run(mongoose) {
    if (!mongoose?.connection || mongoose.connection.readyState !== 1) return { skipped: true };
    const token = retiredToken();
    const orders = mongoose.connection.collection('weborders');
    const paid = await orders.updateMany(
        { paymentMethod: token, paymentStatus: 'pagado' },
        [{
            $set: {
                paymentMethod: 'online',
                paymentRef: { $ifNull: ['$paymentRef', `$${token}Hash`] },
                paymentExternalId: { $ifNull: ['$paymentExternalId', `$${token}Numero`] },
                paymentAttemptStatus: 'ready'
            }
        }]
    );
    const pending = await orders.updateMany(
        { paymentMethod: token },
        { $set: { paymentMethod: 'transferencia', paymentAttemptStatus: 'ready', paymentAttemptError: '' } }
    );
    const unset = {};
    for (const field of legacyFields()) unset[field] = '';
    const cleared = await orders.updateMany({}, { $unset: unset });

    const products = mongoose.connection.collection('products');
    await products.updateMany(
        { displayOrder: { $exists: false } },
        { $set: { displayOrder: 0 } }
    );
    await products.updateMany(
        { status: { $exists: false } },
        { $set: { status: 'activo' } }
    );

    return {
        paid: paid.modifiedCount || 0,
        pending: pending.modifiedCount || 0,
        cleared: cleared.modifiedCount || 0
    };
}

module.exports = { run, legacyFields };
