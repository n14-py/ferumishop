'use strict';

const { haversineKm } = require('../orders');
const { normalizeText } = require('./text');

const CITY_POINTS = [
    { name: 'Asunción', lat: -25.2637, lng: -57.5759 },
    { name: 'San Lorenzo', lat: -25.3397, lng: -57.5076 },
    { name: 'Luque', lat: -25.267, lng: -57.487 },
    { name: 'Capiatá', lat: -25.3552, lng: -57.4454 },
    { name: 'Fernando de la Mora', lat: -25.3386, lng: -57.558 },
    { name: 'Lambaré', lat: -25.3466, lng: -57.637 },
    { name: 'Ñemby', lat: -25.3947, lng: -57.5356 },
    { name: 'Villa Elisa', lat: -25.3678, lng: -57.5927 },
    { name: 'Mariano Roque Alonso', lat: -25.208, lng: -57.532 },
    { name: 'Limpio', lat: -25.166, lng: -57.481 },
    { name: 'San Antonio', lat: -25.421, lng: -57.547 },
    { name: 'Itauguá', lat: -25.3928, lng: -57.3336 },
    { name: 'Guarambaré', lat: -25.491, lng: -57.456 },
    { name: 'Ypané', lat: -25.455, lng: -57.526 },
    { name: 'Areguá', lat: -25.3126, lng: -57.3847 },
    { name: 'Itá', lat: -25.5006, lng: -57.3612 },
    { name: 'J. Augusto Saldívar', lat: -25.445, lng: -57.453 }
];

function roundKm(value) {
    return Math.round(Number(value) * 10) / 10;
}

function formatCoordinate(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return '';
    return number.toFixed(7).replace(/0+$/, '').replace(/\.$/, '');
}

function mapsRoute(origin, destination) {
    if (!origin || destination?.lat == null || destination?.lng == null) return '';
    return `https://www.google.com/maps/dir/?api=1&origin=${formatCoordinate(origin.lat)},${formatCoordinate(origin.lng)}&destination=${formatCoordinate(destination.lat)},${formatCoordinate(destination.lng)}`;
}

function cityFromText(text, cities = CITY_POINTS) {
    const haystack = normalizeText(text);
    if (!haystack) return '';
    const found = [...cities].sort((a, b) => normalizeText(b.name).length - normalizeText(a.name).length)
        .find((city) => haystack.includes(normalizeText(city.name)));
    return found ? found.name : '';
}

function nearestCity(lat, lng, cities = CITY_POINTS, maxKm = 12) {
    if (lat == null || lng == null) return null;
    const ranked = cities.map((city) => ({
        ...city,
        km: haversineKm(lat, lng, city.lat, city.lng)
    })).sort((a, b) => a.km - b.km);
    const nearest = ranked[0];
    if (!nearest || nearest.km > maxKm) return null;
    return { name: nearest.name, km: roundKm(nearest.km) };
}

function describePoint({ lat, lng, address = '', name = '', store, cities = CITY_POINTS, maxCityKm = 12 }) {
    const latitude = Number(lat);
    const longitude = Number(lng);
    const valid = Number.isFinite(latitude) && Number.isFinite(longitude);
    const textCity = cityFromText(`${address} ${name}`, cities);
    const near = valid && !textCity ? nearestCity(latitude, longitude, cities, maxCityKm) : null;
    const city = textCity || near?.name || '';
    const distanceKm = valid && store
        ? roundKm(haversineKm(store.lat, store.lng, latitude, longitude))
        : null;
    const interior = valid ? !city : false;
    return {
        lat: valid ? latitude : null,
        lng: valid ? longitude : null,
        city,
        distanceKm,
        interior,
        inZone: Boolean(city),
        routeUrl: valid && store ? mapsRoute(store, { lat: latitude, lng: longitude }) : '',
        pinUrl: valid ? `https://www.google.com/maps?q=${latitude},${longitude}` : '',
        label: valid ? `${formatCoordinate(latitude)}, ${formatCoordinate(longitude)}` : ''
    };
}

module.exports = {
    CITY_POINTS,
    formatCoordinate,
    mapsRoute,
    cityFromText,
    nearestCity,
    describePoint
};
