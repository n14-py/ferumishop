'use strict';

const ATTENTION = {
    AI_ACTIVE: 'ai_active',
    WAITING_CUSTOMER: 'waiting_customer',
    HUMAN_REQUESTED: 'human_requested',
    HUMAN_ACTIVE: 'human_active',
    PENDING: 'pending_resolution',
    CLOSED: 'closed',
    AI_PAUSED: 'ai_paused',
    ERROR: 'processing_error'
};

const ATTENTION_LABELS = {
    ai_active: 'IA activa',
    waiting_customer: 'Esperando respuesta del cliente',
    human_requested: 'Atención humana solicitada',
    human_active: 'Atención humana activa',
    pending_resolution: 'Pendiente de resolución',
    closed: 'Cerrada',
    ai_paused: 'IA pausada',
    processing_error: 'Error de procesamiento'
};

const COMMERCIAL = ['borrador', 'pendiente_confirmacion', 'confirmado', 'cancelado', 'incidencia'];
const FINANCIAL = ['pendiente', 'parcial', 'en_verificacion', 'confirmado', 'rechazado', 'reembolsado'];
const LOGISTICS = [
    'pendiente_preparacion', 'en_preparacion', 'listo_despacho', 'programado',
    'despachado', 'en_camino', 'entregado', 'intento_fallido', 'reprogramado', 'cancelado', 'incidencia'
];

const FINANCIAL_TRANSITIONS = {
    pendiente: ['parcial', 'en_verificacion', 'confirmado', 'rechazado'],
    parcial: ['en_verificacion', 'confirmado', 'rechazado'],
    en_verificacion: ['confirmado', 'rechazado', 'parcial', 'pendiente'],
    confirmado: ['reembolsado'],
    rechazado: ['pendiente', 'en_verificacion'],
    reembolsado: []
};

const LOGISTICS_TRANSITIONS = {
    pendiente_preparacion: ['en_preparacion', 'cancelado', 'reprogramado'],
    en_preparacion: ['listo_despacho', 'cancelado', 'incidencia'],
    listo_despacho: ['programado', 'despachado', 'en_camino', 'cancelado'],
    programado: ['despachado', 'reprogramado', 'cancelado'],
    despachado: ['en_camino', 'entregado', 'intento_fallido', 'reprogramado'],
    en_camino: ['entregado', 'intento_fallido', 'reprogramado'],
    intento_fallido: ['reprogramado', 'en_camino', 'entregado', 'incidencia'],
    reprogramado: ['programado', 'en_preparacion', 'cancelado'],
    entregado: ['incidencia'],
    cancelado: [],
    incidencia: ['en_preparacion', 'reprogramado', 'cancelado']
};

function canTransition(map, from, to) {
    if (from === to) return true;
    const allowed = map[from] || [];
    return allowed.includes(to);
}

function legacyFulfillmentForLogistics(logistics, shippingMethod) {
    if (logistics === 'entregado') return 'entregado';
    if (logistics === 'cancelado') return 'cancelado';
    if (logistics === 'incidencia') return 'devuelto';
    if (logistics === 'en_camino' || logistics === 'despachado') {
        if (shippingMethod === 'motobolt') return 'esperando_motobolt';
        if (shippingMethod === 'retiro') return 'esperando_retiro';
        return 'enviando';
    }
    if (logistics === 'listo_despacho' || logistics === 'programado') {
        if (shippingMethod === 'retiro') return 'esperando_retiro';
        if (shippingMethod === 'motobolt') return 'esperando_motobolt';
        return 'preparado';
    }
    if (logistics === 'en_preparacion' || logistics === 'pendiente_preparacion' || logistics === 'reprogramado' || logistics === 'intento_fallido') {
        return 'preparando';
    }
    return 'preparando';
}

function aiMayRespond(conv) {
    const status = conv?.attentionStatus || ATTENTION.AI_ACTIVE;
    if (conv?.aiPaused) return false;
    return ![
        ATTENTION.HUMAN_REQUESTED,
        ATTENTION.HUMAN_ACTIVE,
        ATTENTION.AI_PAUSED,
        ATTENTION.CLOSED
    ].includes(status);
}

function attentionAfter(action, conv = {}) {
    if (action === 'pause') return { aiPaused: true, attentionStatus: ATTENTION.AI_PAUSED };
    if (action === 'resume') return { aiPaused: false, attentionStatus: ATTENTION.AI_ACTIVE, humanOwnerId: '', humanOwnerName: '' };
    if (action === 'takeover') return { aiPaused: true, attentionStatus: ATTENTION.HUMAN_ACTIVE };
    if (action === 'release') return { aiPaused: false, attentionStatus: ATTENTION.AI_ACTIVE };
    if (action === 'request_human') return { aiPaused: true, attentionStatus: ATTENTION.HUMAN_REQUESTED };
    if (action === 'resolve') return { aiPaused: false, attentionStatus: ATTENTION.CLOSED };
    if (action === 'reopen') return { aiPaused: false, attentionStatus: ATTENTION.AI_ACTIVE };
    if (action === 'error') return { attentionStatus: ATTENTION.ERROR };
    return { aiPaused: Boolean(conv.aiPaused), attentionStatus: conv.attentionStatus || ATTENTION.AI_ACTIVE };
}

module.exports = {
    ATTENTION,
    ATTENTION_LABELS,
    COMMERCIAL,
    FINANCIAL,
    LOGISTICS,
    FINANCIAL_TRANSITIONS,
    LOGISTICS_TRANSITIONS,
    canTransition,
    legacyFulfillmentForLogistics,
    aiMayRespond,
    attentionAfter
};
