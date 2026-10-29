'use strict';

const { normalizeText } = require('./text');

const DEFAULT_RULES = [
    {
        key: 'prefer_transfer',
        name: 'Priorizar transferencia cuando esté habilitada',
        description: 'Si la modalidad permite transferencia y PagoPar, se informan las dos y se menciona primero la transferencia.',
        priority: 20,
        active: true,
        scope: 'payment',
        when: [{ field: 'paymentMethods', op: 'includes', value: 'transferencia' }],
        then: { type: 'prefer_payment', params: { method: 'transferencia' } }
    },
    {
        key: 'cash_pickup_only',
        name: 'Efectivo solo en retiro habilitado',
        description: 'El efectivo al recibir solo se ofrece si la matriz de pago lo habilita para esa modalidad.',
        priority: 80,
        active: true,
        scope: 'payment',
        when: [{ field: 'method', op: 'neq', value: 'retiro' }],
        then: { type: 'forbid_payment', params: { method: 'efectivo' } }
    },
    {
        key: 'motobolt_paid_first',
        name: 'MotoBolt exige pago confirmado',
        description: 'No se despacha MotoBolt ni se afirma que el moto fue pedido sin pago confirmado.',
        priority: 100,
        active: true,
        scope: 'logistics',
        when: [{ field: 'method', op: 'eq', value: 'motobolt' }],
        then: { type: 'require_confirmed_payment', params: {} }
    },
    {
        key: 'max_discount_zero',
        name: 'Sin descuento automático',
        description: 'El descuento máximo autorizado arranca en cero hasta que un administrador lo cambie.',
        priority: 90,
        active: true,
        scope: 'commercial',
        when: [],
        then: { type: 'max_discount', params: { amount: 0, percent: 0 } }
    },
    {
        key: 'no_partial',
        name: 'No aceptar señas sin política activa',
        description: 'Las señas y pagos parciales quedan deshabilitados hasta que se active la regla correspondiente.',
        priority: 90,
        active: true,
        scope: 'commercial',
        when: [],
        then: { type: 'block_partial', params: {} }
    },
    {
        key: 'no_stock_promise',
        name: 'No confirmar stock insuficiente',
        description: 'No se confirma un pedido si la cantidad supera el stock.',
        priority: 100,
        active: true,
        scope: 'catalog',
        when: [{ field: 'stockOk', op: 'eq', value: false }],
        then: { type: 'block_confirm', params: { reason: 'stock' } }
    },
    {
        key: 'cutoff',
        name: 'No prometer la salida de hoy después del horario límite',
        description: 'Después del horario límite el pedido pasa a la siguiente salida.',
        priority: 70,
        active: true,
        scope: 'logistics',
        when: [{ field: 'afterCutoff', op: 'eq', value: true }],
        then: { type: 'next_departure', params: {} }
    },
    {
        key: 'human_exceptions',
        name: 'Derivar solicitudes excepcionales',
        description: 'Descuentos especiales, señas no habilitadas y conflictos se derivan a una persona.',
        priority: 60,
        active: true,
        scope: 'attention',
        when: [{ field: 'needsHuman', op: 'eq', value: true }],
        then: { type: 'require_human', params: {} }
    },
    {
        key: 'verify_payments',
        name: 'Verificar comprobantes',
        description: 'Un comprobante no confirma el pago. Hace falta verificación humana o PagoPar.',
        priority: 100,
        active: true,
        scope: 'payment',
        when: [],
        then: { type: 'require_payment_verification', params: {} }
    },
    {
        key: 'block_unpaid_dispatch',
        name: 'No despachar con pago pendiente',
        description: 'El despacho queda bloqueado cuando la política exige pago confirmado y el pedido no lo tiene.',
        priority: 100,
        active: true,
        scope: 'logistics',
        when: [{ field: 'requiresPayment', op: 'eq', value: true }, { field: 'paymentConfirmed', op: 'eq', value: false }],
        then: { type: 'block_dispatch', params: {} }
    }
];

function matchClause(context, clause) {
    const current = context?.[clause.field];
    if (clause.op === 'eq') return current === clause.value;
    if (clause.op === 'neq') return current !== clause.value;
    if (clause.op === 'includes') return Array.isArray(current) && current.includes(clause.value);
    if (clause.op === 'truthy') return Boolean(current);
    return false;
}

function ruleActive(rule, now) {
    if (!rule || rule.active === false) return false;
    if (rule.startsAt && new Date(rule.startsAt) > now) return false;
    if (rule.endsAt && new Date(rule.endsAt) < now) return false;
    return true;
}

function evaluateRules(rules, context, now = new Date()) {
    const traces = [];
    const decisions = {
        preferredPayment: null,
        forbiddenPayments: [],
        requireConfirmedPayment: false,
        maxDiscountAmount: null,
        maxDiscountPercent: null,
        allowPartial: false,
        blockConfirm: false,
        blockConfirmReason: '',
        nextDeparture: false,
        requireHuman: false,
        requirePaymentVerification: true,
        blockDispatch: false
    };
    const ordered = [...(rules || [])].filter((rule) => ruleActive(rule, now))
        .sort((a, b) => (Number(a.priority) || 0) - (Number(b.priority) || 0));
    for (const rule of ordered) {
        const clauses = rule.when || [];
        const matched = clauses.every((clause) => matchClause(context, clause));
        traces.push({ key: rule.key, name: rule.name, matched, priority: rule.priority || 0 });
        if (!matched) continue;
        const type = rule.then?.type;
        const params = rule.then?.params || {};
        if (type === 'prefer_payment') decisions.preferredPayment = params.method;
        if (type === 'forbid_payment') decisions.forbiddenPayments.push(params.method);
        if (type === 'require_confirmed_payment') decisions.requireConfirmedPayment = true;
        if (type === 'max_discount') {
            decisions.maxDiscountAmount = Number(params.amount) || 0;
            decisions.maxDiscountPercent = Number(params.percent) || 0;
        }
        if (type === 'block_partial') decisions.allowPartial = false;
        if (type === 'allow_partial') decisions.allowPartial = true;
        if (type === 'block_confirm') {
            decisions.blockConfirm = true;
            decisions.blockConfirmReason = params.reason || 'regla';
        }
        if (type === 'next_departure') decisions.nextDeparture = true;
        if (type === 'require_human') decisions.requireHuman = true;
        if (type === 'require_payment_verification') decisions.requirePaymentVerification = true;
        if (type === 'block_dispatch') decisions.blockDispatch = true;
    }
    if (decisions.maxDiscountAmount == null) decisions.maxDiscountAmount = 0;
    if (decisions.maxDiscountPercent == null) decisions.maxDiscountPercent = 0;
    decisions.forbiddenPayments = [...new Set(decisions.forbiddenPayments.filter(Boolean))];
    return { decisions, traces };
}

function discountAllowed(decisions, requestedAmount, subtotal) {
    const amount = Number(requestedAmount) || 0;
    const maxAmount = decisions.maxDiscountAmount || 0;
    const maxPercent = decisions.maxDiscountPercent || 0;
    const percentCap = subtotal ? Math.floor((Number(subtotal) * maxPercent) / 100) : 0;
    const cap = Math.max(maxAmount, percentCap);
    return { ok: amount <= cap && amount >= 0, cap, requested: amount };
}

function normalizeRuleName(name) {
    return normalizeText(name);
}

module.exports = {
    DEFAULT_RULES,
    evaluateRules,
    discountAllowed,
    ruleActive,
    normalizeRuleName
};
