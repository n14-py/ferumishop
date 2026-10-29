'use strict';

const ROLES = ['owner', 'manager', 'operator', 'viewer'];

const ROLE_PERMISSIONS = {
    owner: ['*'],
    manager: [
        'wa.view', 'wa.reply', 'wa.handoff', 'wa.orders.write', 'wa.payments.approve',
        'wa.prices', 'wa.delivery', 'wa.promos', 'wa.ai.edit', 'wa.audit', 'wa.catalog'
    ],
    operator: ['wa.view', 'wa.reply', 'wa.handoff', 'wa.orders.write', 'wa.catalog'],
    viewer: ['wa.view', 'wa.audit']
};

function roleOf(user) {
    const role = String(user?.role || 'owner');
    return ROLES.includes(role) ? role : 'owner';
}

function permissionList(user) {
    if (Array.isArray(user?.waPermissions) && user.waPermissions.length) {
        return user.waPermissions;
    }
    return ROLE_PERMISSIONS[roleOf(user)] || ROLE_PERMISSIONS.viewer;
}

function can(user, permission) {
    const list = permissionList(user);
    return list.includes('*') || list.includes(permission);
}

function requirePermission(permission) {
    return function permissionMiddleware(req, res, next) {
        if (!req.isAuthenticated || !req.isAuthenticated() || !req.user) {
            if (req.path.startsWith('/admin/whatsapp/api')) {
                return res.status(401).json({ ok: false, message: 'Tenés que iniciar sesión.' });
            }
            return res.redirect('/admin/login');
        }
        if (!can(req.user, permission)) {
            if (req.path.startsWith('/admin/whatsapp/api') || req.get('accept') === 'application/json') {
                return res.status(403).json({ ok: false, message: 'No tenés permiso para esta operación.' });
            }
            return res.status(403).render('admin/whatsapp/index', {
                pageTitle: 'WhatsApp AI',
                path: req.path,
                section: 'denegado',
                nav: [],
                data: { permission },
                admin: publicAdmin(req.user),
                perms: permissionFlags(req.user),
                success: null,
                error: 'No tenés permiso para esta operación.',
                query: req.query || {}
            });
        }
        return next();
    };
}

function publicAdmin(user) {
    return {
        id: user?._id ? String(user._id) : '',
        email: user?.email || '',
        username: user?.username || 'Admin',
        role: roleOf(user)
    };
}

function permissionFlags(user) {
    const keys = [
        'wa.view', 'wa.reply', 'wa.handoff', 'wa.orders.write', 'wa.payments.approve',
        'wa.prices', 'wa.delivery', 'wa.promos', 'wa.ai.edit', 'wa.notify.bulk',
        'wa.users', 'wa.audit', 'wa.catalog'
    ];
    const flags = {};
    for (const key of keys) flags[key] = can(user, key);
    return flags;
}

module.exports = {
    ROLES,
    ROLE_PERMISSIONS,
    roleOf,
    can,
    requirePermission,
    publicAdmin,
    permissionFlags
};
