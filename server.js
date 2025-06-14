//
// Custom Text-to-Speech (TTS) Voice API Server (Production Ready)
// ---------------------------------------------
// This version logs all API requests to a PostgreSQL database.
// Version 2.3: Fixed DigitalOcean SSL connection issues.
//

// --- Dependencies ---
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg'); // PostgreSQL client
require('dotenv').config();

// --- Database Connection ---
// This configuration connects to the database using the connection string
// and disables strict SSL certificate validation, which is required to
// resolve the "self-signed certificate" error with DigitalOcean Managed Databases.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// --- Function to ensure the log table exists ---
const ensureLogTableExists = async () => {
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS api_logs (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL,
            ip_address VARCHAR(45),
            method VARCHAR(10),
            endpoint VARCHAR(255),
            status_code INT,
            response_message TEXT
        );
    `;
    try {
        await pool.query(createTableQuery);
        console.log('[INFO] Log table "api_logs" is ready.');
    } catch (err) {
        console.error('[FATAL] Error creating log table:', err.stack);
        process.exit(1);
    }
};

// --- Function to log requests to the database ---
const logRequestToDb = async (req, statusCode, message) => {
    const logQuery = `
        INSERT INTO api_logs (timestamp, ip_address, method, endpoint, status_code, response_message)
        VALUES ($1, $2, $3, $4, $5, $6);
    `;
    const values = [ new Date(), req.ip, req.method, req.originalUrl, statusCode, JSON.stringify(message) ];
    try {
        await pool.query(logQuery, values);
    } catch (err) {
        console.error('[ERROR] Failed to write log to database:', err.stack);
    }
};


// --- Express App Initialization ---
const app = express();
app.use(express.json());
app.use(cors());
app.set('trust proxy', true);


const PORT = process.env.PORT || 3000;

// --- API Key Authentication Middleware ---
const apiKeyAuth = (req, res, next) => {
    const userApiKey = req.headers['x-api-key'];
    if (!userApiKey || !process.env.MY_API_KEY || userApiKey !== process.env.MY_API_KEY) {
        const message = { error: 'Unauthorized. Invalid or missing API Key.' };
        logRequestToDb(req, 401, message);
        return res.status(401).json(message);
    }
    next();
};

// --- API Routes ---
app.post('/api/v1/call/tts', apiKeyAuth, async (req, res) => {
    const { to, text, from } = req.body;
    if (!to || !text) {
        const message = { error: 'Missing required fields: `to` and `text` are required.' };
        await logRequestToDb(req, 400, message);
        return res.status(400).json(message);
    }
    
    const callerId = from || process.env.DEFAULT_CALLER_ID;
    const infobipPayload = { from: callerId, to, text, language: 'en', voice: { name: "Joanna", gender: "female" } };
    const infobipHeaders = { 'Authorization': `App ${process.env.INFOBIP_API_KEY}`, 'Content-Type': 'application/json', 'Accept': 'application/json' };
    const infobipApiUrl = `https://${process.env.INFOBIP_BASE_URL}/tts/3/single`;

    try {
        const infobipResponse = await axios.post(infobipApiUrl, infobipPayload, { headers: infobipHeaders });
        const successMessage = { message: 'Call initiated successfully.', tracking: infobipResponse.data };
        await logRequestToDb(req, 200, { to, bulkId: infobipResponse.data.bulkId });
        res.status(200).json(successMessage);

    } catch (error) {
        const statusCode = error.response ? error.response.status : 500;
        const errorMessage = error.response ? error.response.data : 'Internal Server Error';
        await logRequestToDb(req, statusCode, { error: 'Failed to call Infobip', details: errorMessage });
        res.status(statusCode).json({ error: 'Failed to initiate call via backend service.', details: errorMessage });
    }
});

app.get('/api/v1/call/status/:bulkId', apiKeyAuth, async (req, res) => {
    const { bulkId } = req.params;
    if (!bulkId) {
        const message = { error: 'Missing bulkId parameter.' };
        await logRequestToDb(req, 400, message);
        return res.status(400).json(message);
    }
    
    const infobipHeaders = { 'Authorization': `App ${process.env.INFOBIP_API_KEY}`, 'Accept': 'application/json' };
    const infobipReportsUrl = `https://${process.env.INFOBIP_BASE_URL}/tts/3/reports?bulkId=${bulkId}`;

    try {
        const reportsResponse = await axios.get(infobipReportsUrl, { headers: infobipHeaders });
        await logRequestToDb(req, 200, { action: 'Status check success', bulkId });
        res.status(200).json(reportsResponse.data);
    } catch (error) {
        const statusCode = error.response ? error.response.status : 500;
        const errorMessage = error.response ? error.response.data : 'Internal Server Error';
        await logRequestToDb(req, statusCode, { error: 'Failed to get status', details: errorMessage });
        res.status(statusCode).json({ error: 'Failed to get call status.', details: errorMessage });
    }
});

// --- Server Startup ---
const startServer = async () => {
    await ensureLogTableExists();

    app.listen(PORT, () => {
        console.log(`TTS API Server is running in production mode on port ${PORT}`);
        if (!process.env.MY_API_KEY || !process.env.INFOBIP_BASE_URL || !process.env.INFOBIP_API_KEY || !process.env.DATABASE_URL || !process.env.DEFAULT_CALLER_ID) {
            console.error('[FATAL] A CRITICAL ENVIRONMENT VARIABLE IS MISSING. Shutting down.');
            process.exit(1);
        }
    });
};

startServer();
