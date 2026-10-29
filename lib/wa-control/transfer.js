'use strict';

function transferMessage(transfer = {}, extra = {}) {
    const alias = String(transfer.alias || '').trim();
    if (!alias) {
        return {
            ok: false,
            text: 'Todavía no cargaron el alias de transferencia. Puedo armarte el enlace de PagoPar, que acepta QR, tarjeta de crédito y débito.'
        };
    }
    const lines = [
        extra.orderNumber ? `Pedido: ${extra.orderNumber}` : '',
        extra.total ? `Importe: ${extra.total}` : '',
        `Banco: ${transfer.bank || '—'}`,
        `Alias: ${alias}`,
        `Nombre: ${transfer.holderName || '—'}`
    ].filter(Boolean);
    if (transfer.note) lines.push(String(transfer.note));
    return {
        ok: true,
        text: `Podés transferir a esta cuenta:\n${lines.join('\n')}\n\nCuando la hagas, enviame la foto del comprobante. El pago queda pendiente hasta que lo revisemos. PagoPar, si preferís, es con QR, crédito o débito.`
    };
}

module.exports = { transferMessage };
