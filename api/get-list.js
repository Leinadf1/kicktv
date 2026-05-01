import { kv } from '@vercel/kv';
import { randomBytes } from 'crypto';
import fs from 'fs';
import path from 'path';

export default async function handler(req, res) {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-heartbeat, x-token');
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'POST') {
        res.status(405).json({ error: 'Metodo non permesso' });
        return;
    }

    const { password } = req.body;
    const tokenFromHeader = req.headers['x-token'];
    const correctPassword = process.env.ACCESS_PASSWORD;

    // Se la richiesta è un heartbeat (contiene x-token)
    if (tokenFromHeader) {
        try {
            const storedPassword = await kv.get(`token:${tokenFromHeader}`);
            if (storedPassword === correctPassword) {
                // Rinnova TTL di 30 secondi
                await kv.expire(`token:${tokenFromHeader}`, 30);
                return res.status(200).json({ status: 'ok', token: tokenFromHeader });
            } else {
                return res.status(401).json({ error: 'Sessione scaduta o invalidata' });
            }
        } catch (kvError) {
            console.error('KV error:', kvError);
            return res.status(500).json({ error: 'Errore interno (KV)' });
        }
    }

    // Altrimenti è un tentativo di login
    if (!password || password !== correctPassword) {
        return res.status(403).json({ error: 'Password errata!' });
    }

    // Genera nuovo token, invalida il vecchio
    try {
        const oldToken = await kv.get(`pass:${password}`);
        if (oldToken) {
            await kv.del(`token:${oldToken}`);
        }

        const newToken = randomBytes(32).toString('hex');
        await kv.set(`token:${newToken}`, password);
        await kv.expire(`token:${newToken}`, 30);
        await kv.set(`pass:${password}`, newToken);

        // Legge il file lista.m3u
        const filePath = path.join(process.cwd(), 'lista.m3u');
        const m3uContent = fs.readFileSync(filePath, 'utf-8');

        return res.status(200).json({ m3u: m3uContent, token: newToken });
    } catch (err) {
        console.error('Errore durante login:', err);
        return res.status(500).json({ error: 'Errore interno' });
    }
}
