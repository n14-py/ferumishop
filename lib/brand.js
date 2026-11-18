'use strict';

const FOUNDERS = [
    {
        name: 'Luis Fernando Arce Fretes',
        role: 'Fundador · Dirección Ejecutiva, Finanzas y Desarrollo de Producto',
        bio: 'Lleva la dirección general de FERUMI: planificación, inversiones, administración financiera, recursos, abastecimiento, importaciones y desarrollo de productos. Supervisa las operaciones y el crecimiento de la marca.',
        monogram: 'LF'
    },
    {
        name: 'Fadua Mahiumy Gomez Benitez',
        role: 'Fundadora · Coordinación Comercial y Experiencia del Cliente',
        bio: 'Acompaña a cada clienta: atención, gestión comercial, asesoramiento, seguimiento de pedidos, cierre de ventas y la comunicación digital de la marca. También crea y publica el contenido, las fotografías y los videos de las redes.',
        monogram: 'FG'
    }
];

const FACTS = {
    name: 'FERUMI',
    country: 'Paraguay',
    foundedOn: '11 de enero de 2026',
    stageOn: 'diciembre de 2026',
    clients: 'Más de 1.000 clientes',
    clientsShort: '1.000+',
    launchTitle: 'Diciembre 2026: FERUMI se presenta como marca',
    launchText: 'Un proyecto emprendedor que creció con cada clienta y, desde diciembre de 2026, sale a escena como marca paraguaya de pestañas, belleza y cosméticos. El lanzamiento llega con promociones exclusivas.'
};

function monogram(name) {
    const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return 'F';
    const first = parts[0][0] || '';
    const last = parts.length > 1 ? parts[parts.length - 1][0] : '';
    return (first + last).toUpperCase();
}

function present(config = {}) {
    const savedFounders = Array.isArray(config.founders)
        ? config.founders.filter((person) => person && String(person.name || '').trim())
        : [];
    const founders = (savedFounders.length ? savedFounders : FOUNDERS).map((person) => ({
        name: String(person.name || '').trim(),
        role: String(person.role || '').trim(),
        bio: String(person.bio || '').trim(),
        monogram: person.monogram || monogram(person.name)
    }));
    return {
        name: FACTS.name,
        country: FACTS.country,
        foundedOn: config.foundedOn || FACTS.foundedOn,
        stageOn: config.stageOn || FACTS.stageOn,
        clients: config.clientsLabel || FACTS.clients,
        clientsShort: config.clientsShort || FACTS.clientsShort,
        story: config.brandStory || '',
        launchTitle: config.launchTitle || FACTS.launchTitle,
        launchText: config.launchText || FACTS.launchText,
        showLaunch: config.showLaunch !== false,
        founders,
        instagram: config.instagramUrl || 'https://instagram.com/ferumishop',
        facebook: config.facebookUrl || '',
        tiktok: config.tiktokUrl || 'https://tiktok.com/@ferumishop',
        whatsapp: config.whatsappNumber || '595987301591'
    };
}

module.exports = {
    FOUNDERS,
    FACTS,
    monogram,
    present
};
