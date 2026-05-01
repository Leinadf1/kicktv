import { createClient } from '@vercel/kv';
import fs from 'fs';
import path from 'path';

export default async function handler(req, res) {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-heartbeat');

    if (req.method === 'OPTIONS') return res.status(200).end();

    // Crea il client KV usando le variabili automatiche di Vercel
    const kv = createClient({
        url: process.env.KV_REST_API_URL,
        token: process.env.KV_REST_API_TOKEN,
    });

    // Legge il corpo della richiesta
    let body = {};
    try {
        const buffers = [];
        for await (const chunk of req) { buffers.push(chunk); }
        const data = Buffer.concat(buffers).toString();
        body = data ? JSON.parse(data) : {};
    } catch (e) {
        body = {};
    }

    const psw = body.password ? body.password.trim() : '';
    // Supporta più password separate da virgola
    const authorizedPasswords = (process.env.ACCESS_PASSWORD || '')
        .split(',')
        .map(p => p.trim());

    // Verifica se la password è tra quelle autorizzate
    if (!psw || !authorizedPasswords.includes(psw)) {
        return res.status(401).json({ error: 'Password errata' });
    }

    const sessionKey = `session_${psw}`;

    // Heartbeat: rinnova sessione (TTL 25 secondi)
    if (req.headers['x-heartbeat'] === 'true') {
        await kv.set(sessionKey, 'active', { ex: 25 });
        return res.status(200).json({ status: 'ok' });
    }

    // Controllo sessione già attiva (impedisce accessi simultanei)
    const isOccupied = await kv.get(sessionKey);
    if (isOccupied) {
        return res.status(403).json({ error: 'Accesso negato: sessione già attiva' });
    }

    // Nuovo accesso: imposta la sessione
    await kv.set(sessionKey, 'active', { ex: 25 });

    // Legge il file lista.m3u dalla root del progetto
    try {
        const filePath = path.join(process.cwd(), 'lista.m3u');
        const m3uContent = fs.readFileSync(filePath, 'utf-8');
        return res.status(200).send(m3uContent);
    } catch (error) {
        return res.status(500).json({ error: 'Errore nel leggere la lista' });
    }
}
