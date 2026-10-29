'use strict';

const mongoose = require('mongoose');

function model(name, schema) {
    return mongoose.models[name] || mongoose.model(name, schema);
}

const revisionSchema = new mongoose.Schema({
    version: Number,
    status: { type: String, default: 'draft' },
    snapshot: mongoose.Schema.Types.Mixed,
    diff: mongoose.Schema.Types.Mixed,
    author: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
}, { collection: 'wa_ai_revisions' });

const settingsSchema = new mongoose.Schema({
    key: { type: String, unique: true, default: 'main' },
    timezone: { type: String, default: 'America/Asuncion' },
    departureTime: { type: String, default: '18:00' },
    cutoffTime: { type: String, default: '17:30' },
    serviceDays: { type: [Number], default: [1, 2, 3, 4, 5, 6] },
    requirePaidBeforeDispatch: { type: Boolean, default: true },
    paymentMatrix: { type: mongoose.Schema.Types.Mixed, default: {} },
    partialPayments: { type: mongoose.Schema.Types.Mixed, default: { enabled: false } },
    pickup: { type: mongoose.Schema.Types.Mixed, default: {} },
    followup: { type: mongoose.Schema.Types.Mixed, default: { enabled: false, maxPerConversation: 1 } },
    updatedAt: { type: Date, default: Date.now },
    updatedBy: { type: String, default: '' }
}, { collection: 'wa_settings' });

const aiSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    snapshot: mongoose.Schema.Types.Mixed,
    version: { type: Number, default: 0 },
    updatedAt: { type: Date, default: Date.now },
    updatedBy: { type: String, default: '' }
}, { collection: 'wa_ai_profiles' });

const inboundSchema = new mongoose.Schema({
    wamid: { type: String, unique: true, index: true },
    waId: { type: String, index: true },
    status: { type: String, default: 'processing' },
    type: { type: String, default: '' },
    preview: { type: String, default: '' },
    error: { type: String, default: '' },
    attempts: { type: Number, default: 1 },
    createdAt: { type: Date, default: Date.now },
    finishedAt: Date
}, { collection: 'wa_inbound_events' });

const intentSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    fingerprint: { type: String, index: true },
    waId: { type: String, index: true },
    orderId: { type: String, default: '' },
    status: { type: String, default: 'reserved', index: true },
    hash: { type: String, default: '' },
    payUrl: { type: String, default: '' },
    expiresAt: Date,
    linkSentAt: Date,
    linkSendStatus: { type: String, default: '' },
    providerCalls: { type: Number, default: 0 },
    callingAt: Date,
    error: { type: String, default: '' },
    events: [{ type: { type: String }, at: Date, detail: String }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
}, { collection: 'wa_payment_intents' });

const outboundSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    waId: { type: String, index: true },
    purpose: { type: String, default: '' },
    status: { type: String, default: 'sending', index: true },
    providerId: { type: String, default: '' },
    error: { type: String, default: '' },
    attempts: { type: Number, default: 1 },
    createdAt: { type: Date, default: Date.now },
    sentAt: Date
}, { collection: 'wa_outbound' });

const placeSchema = new mongoose.Schema({
    kind: { type: String, default: 'city', index: true },
    name: { type: String, required: true },
    parent: { type: String, default: '' },
    aliases: { type: [String], default: [] },
    code: { type: String, default: '' },
    active: { type: Boolean, default: true },
    notes: { type: String, default: '' }
}, { collection: 'wa_places', timestamps: true });

const rateSchema = new mongoose.Schema({
    name: { type: String, default: '' },
    method: { type: String, required: true, index: true },
    department: { type: String, default: '' },
    city: { type: String, default: '' },
    zone: { type: String, default: '' },
    neighborhood: { type: String, default: '' },
    basePrice: { type: Number, default: null },
    surcharges: [{ name: String, amount: Number }],
    freeFrom: { type: Number, default: null },
    minOrder: { type: Number, default: null },
    eta: { type: String, default: '' },
    serviceDays: { type: [Number], default: [] },
    cutoffTime: { type: String, default: '' },
    priority: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    available: { type: Boolean, default: true },
    startsAt: Date,
    endsAt: Date,
    notes: { type: String, default: '' },
    author: { type: String, default: '' }
}, { collection: 'wa_rates', timestamps: true });

const carrierSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    name: { type: String, required: true },
    active: { type: Boolean, default: true },
    coverage: { type: String, default: '' },
    destinations: { type: [String], default: [] },
    tariffMode: { type: String, default: 'unknown' },
    ratesNote: { type: String, default: '' },
    paymentTerms: { type: String, default: '' },
    dispatchRules: { type: String, default: '' },
    hours: { type: String, default: '' },
    trackingInfo: { type: String, default: '' },
    requirements: { type: String, default: '' },
    contact: { type: String, default: '' },
    notes: { type: String, default: '' }
}, { collection: 'wa_carriers', timestamps: true });

const departureSchema = new mongoose.Schema({
    businessDate: { type: String, index: true },
    timezone: { type: String, default: 'America/Asuncion' },
    departAt: Date,
    cutoffAt: Date,
    zones: { type: [String], default: [] },
    capacity: { type: Number, default: null },
    status: { type: String, default: 'planificada', index: true },
    responsible: { type: String, default: '' },
    notes: { type: String, default: '' },
    orderIds: { type: [String], default: [] },
    notified: [{ orderId: String, status: String, at: Date, error: String }],
    dispatchedAt: Date,
    incidents: [{ orderId: String, kind: String, note: String, by: String, at: Date, nextAction: String }]
}, { collection: 'wa_departures', timestamps: true });

const situationSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, default: '' },
    category: { type: String, default: 'otra' },
    priority: { type: Number, default: 0 },
    startsAt: Date,
    endsAt: Date,
    status: { type: String, default: 'draft', index: true },
    scope: { type: String, default: 'not_prepared' },
    cities: { type: [String], default: [] },
    zones: { type: [String], default: [] },
    methods: { type: [String], default: [] },
    orderIds: { type: [String], default: [] },
    customerWaIds: { type: [String], default: [] },
    responseInstructions: { type: String, default: '' },
    authorizedActions: { type: [String], default: [] },
    rescheduleFor: Date,
    responsible: { type: String, default: '' },
    history: [{ at: Date, by: String, change: String }]
}, { collection: 'wa_situations', timestamps: true });

const templateSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    name: { type: String, required: true },
    channel: { type: String, default: 'session' },
    body: { type: String, default: '' },
    active: { type: Boolean, default: true },
    official: { type: Boolean, default: false },
    author: { type: String, default: '' }
}, { collection: 'wa_templates', timestamps: true });

const ruleSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    name: { type: String, required: true },
    description: { type: String, default: '' },
    priority: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    scope: { type: String, default: 'commercial' },
    startsAt: Date,
    endsAt: Date,
    when: { type: [mongoose.Schema.Types.Mixed], default: [] },
    then: { type: mongoose.Schema.Types.Mixed, default: {} },
    author: { type: String, default: '' },
    history: [{ at: Date, by: String, change: String }]
}, { collection: 'wa_rules', timestamps: true });

const automationSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    name: { type: String, required: true },
    enabled: { type: Boolean, default: false },
    intervalMinutes: { type: Number, default: 15 },
    timezone: { type: String, default: 'America/Asuncion' },
    external: { type: Boolean, default: false },
    lastRunAt: Date,
    nextRunAt: Date,
    lastResult: { type: String, default: '' },
    lastError: { type: String, default: '' },
    history: [{ at: Date, result: String, error: String }]
}, { collection: 'wa_automations' });

const receiptSchema = new mongoose.Schema({
    fingerprint: { type: String, unique: true },
    waId: { type: String, index: true },
    orderId: { type: String, index: true },
    expectedAmount: Number,
    declaredAmount: Number,
    confirmedAmount: { type: Number, default: 0 },
    method: { type: String, default: 'transferencia' },
    reference: { type: String, default: '' },
    mediaUrl: { type: String, default: '' },
    status: { type: String, default: 'en_verificacion', index: true },
    difference: Number,
    duplicateOf: { type: String, default: '' },
    review: [{ at: Date, by: String, action: String, note: String }]
}, { collection: 'wa_receipts', timestamps: true });

const auditSchema = new mongoose.Schema({
    at: { type: Date, default: Date.now, index: true },
    action: { type: String, index: true },
    status: { type: String, default: 'ok' },
    actor: { type: String, default: 'sistema' },
    orderId: { type: String, default: '', index: true },
    waId: { type: String, default: '', index: true },
    operationId: { type: String, default: '' },
    before: mongoose.Schema.Types.Mixed,
    after: mongoose.Schema.Types.Mixed,
    result: { type: String, default: '' },
    error: { type: String, default: '' },
    attempt: { type: Number, default: 1 }
}, { collection: 'wa_audit' });

const bulkSchema = new mongoose.Schema({
    token: { type: String, unique: true },
    actor: String,
    payload: mongoose.Schema.Types.Mixed,
    preview: mongoose.Schema.Types.Mixed,
    expiresAt: Date,
    consumedAt: Date
}, { collection: 'wa_bulk_previews' });

const lockSchema = new mongoose.Schema({
    name: { type: String, unique: true },
    owner: String,
    until: Date
}, { collection: 'wa_job_locks' });

function controlModels() {
    return {
        WaSettings: model('WaSettings', settingsSchema),
        WaAiProfile: model('WaAiProfile', aiSchema),
        WaAiRevision: model('WaAiRevision', revisionSchema),
        WaInbound: model('WaInbound', inboundSchema),
        WaPaymentIntent: model('WaPaymentIntent', intentSchema),
        WaOutbound: model('WaOutbound', outboundSchema),
        WaPlace: model('WaPlace', placeSchema),
        WaRate: model('WaRate', rateSchema),
        WaCarrier: model('WaCarrier', carrierSchema),
        WaDeparture: model('WaDeparture', departureSchema),
        WaSituation: model('WaSituation', situationSchema),
        WaTemplate: model('WaTemplate', templateSchema),
        WaRule: model('WaRule', ruleSchema),
        WaAutomation: model('WaAutomation', automationSchema),
        WaReceipt: model('WaReceipt', receiptSchema),
        WaAudit: model('WaAudit', auditSchema),
        WaBulkPreview: model('WaBulkPreview', bulkSchema),
        WaJobLock: model('WaJobLock', lockSchema)
    };
}

module.exports = { controlModels };
