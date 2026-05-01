import { kv } from '@vercel/kv';
import { createHash, randomBytes } from 'crypto'; // Node.js built-in

export default async function handler(req, res) {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-heartbeat, x-token');
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'POST') {
        res.status(405).json({ error: 'Method not allowed' });
        return;
    }

    const { password } = req.body;
    const correctPassword = process.env.ACCESS_PASSWORD;

    // Verifica password
    if (!password || password !== correctPassword) {
        res.status(403).json({ error: 'Password errata!' });
        return;
    }

    // Gestione heartbeat: se c'è un header x-token, verifichiamo la validità
    const tokenFromHeader = req.headers['x-token'];
    if (tokenFromHeader) {
        // Heartbeat: controlla se il token è ancora valido
        const storedPassword = await kv.get(`token:${tokenFromHeader}`);
        if (storedPassword === password) {
            // Rinnova il TTL del token (30 secondi)
            await kv.expire(`token:${tokenFromHeader}`, 30);
            res.status(200).json({ status: 'ok', token: tokenFromHeader });
            return;
        } else {
            res.status(401).json({ error: 'Sessione scaduta o invalidata da un altro accesso' });
            return;
        }
    }

    // Login: genera un nuovo token e invalida eventuali sessioni precedenti per la stessa password
    // Trova il vecchio token associato a questa password e cancellalo
    const oldToken = await kv.get(`password:${password}`);
    if (oldToken) {
        await kv.del(`token:${oldToken}`);
    }

    // Genera un nuovo token
    const newToken = randomBytes(32).toString('hex');

    // Salva le associazioni
    await kv.set(`token:${newToken}`, password); // token -> password
    await kv.expire(`token:${newToken}`, 30);    // scade dopo 30 secondi senza heartbeat
    await kv.set(`password:${password}`, newToken); // password -> token

    // Legge il file lista.m3u
    try {
        const fs = require('fs');
        const path = require('path');
        const filePath = path.join(process.cwd(), 'lista.m3u');
        const m3uContent = fs.readFileSync(filePath, 'utf-8');
        res.status(200).json({ m3u: m3uContent, token: newToken });
    } catch (error) {
        res.status(500).json({ error: 'Errore nel leggere la lista' });
    }
}
