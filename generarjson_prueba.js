#!/usr/bin/env node
'use strict';

/**
 * Prueba el JSON que la IA manda al VPS ferumishopvideos.
 *
 *   node generarjson_prueba.js
 *
 * Usa GEMINI_API_KEY (y opcional GEMINI_API_KEY_2 … _5) del .env.
 * Escribe json_prueba_salida.json en la raíz con el contrato:
 *   type: "video", text (TTS), texto_pantalla por escena, whatsapp, sin mapa, ≤ 85s.
 */

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const gemma = require('./lib/gemma');
const scenes = require('./lib/video-scenes');

const OUT_FILE = path.join(__dirname, 'json_prueba_salida.json');

const siteConfig = {
    whatsappNumber: process.env.WHATSAPP_NUMBER || '595987301591',
    storeAddress: 'Ferumishop, Asunción - Paraguay',
    motoboltMaxKm: 40,
    instagramUrl: 'https://instagram.com/ferumishop',
    tiktokUrl: 'https://tiktok.com/@ferumishop'
};

function printCheck(check) {
    if (check.ok) {
        console.log('\nContrato ferumishopvideos: OK');
        console.log(`  escenas     ${check.metrics.sceneCount}`);
        console.log(`  palabras    ${check.metrics.words}`);
        console.log(`  duración ~  ${check.metrics.estimatedSeconds}s  (máximo ${check.metrics.maxSeconds}s)`);
        return;
    }
    console.log('\nContrato ferumishopvideos: FALLÓ');
    check.errors.forEach((err) => console.log(`  - ${err}`));
}

async function main() {
    const cfg = gemma.config();
    console.log('=== FERUMI · generar JSON de prueba para ferumishopvideos ===');
    console.log(`Modelos: ${cfg.models.join(' → ')}`);
    console.log(`Claves Google: ${cfg.keyCount}`);

    if (!cfg.ok) {
        console.error('\nFalta GEMINI_API_KEY en el .env (podés sumar GEMINI_API_KEY_2 … _5).');
        process.exit(1);
    }

    const product = scenes.demoProduct();
    const shop = scenes.shopContext(siteConfig);
    console.log(`Producto demo: ${product.name} · ${scenes.usableVideos(product).length} clips`);
    console.log('Llamando a Gemma...\n');

    const payload = await scenes.generateProductVideoScenesJSON(product, siteConfig, {
        jobId: 'ferumi_labial_mate_prueba_01'
    });

    fs.writeFileSync(OUT_FILE, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    console.log(JSON.stringify(payload, null, 2));
    console.log(`\nGuardado: ${OUT_FILE}`);

    const check = scenes.assertPayloadForBot(payload);
    printCheck(check);

    console.log('\nCampos que lee el VPS:');
    console.log(`  article_id / product_id  ${payload.article_id} / ${payload.product_id}`);
    console.log(`  whatsapp                 ${payload.whatsapp}  (display ${shop.phoneDisplay})`);
    console.log(`  texto_pantalla global    ${payload.texto_pantalla}`);
    payload.scenes.forEach((s, i) => {
        console.log(`  [${i + 1}] ${s.texto_pantalla}  ·  ${(s.text || '').slice(0, 70)}…`);
    });

    if (!check.ok) process.exit(2);
}

main().catch((err) => {
    console.error('\nNo se pudo generar el JSON. Eso lo mandó Google/la IA, no el armado del archivo.');
    console.error(err.message || err);
    if (err.model) console.error(`Modelo: ${err.model}`);
    if (err.status) console.error(`HTTP: ${err.status}`);
    if (Array.isArray(err.tried) && err.tried.length) {
        console.error('Intentos:');
        err.tried.forEach((line) => console.error(`  - ${line}`));
    }
    process.exit(1);
});
