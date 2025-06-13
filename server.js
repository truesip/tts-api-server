//
// Custom Text-to-Speech (TTS) Voice API Server (Production Ready)
// ---------------------------------------------
// This version includes logging, status checking, and improved error handling.
//

// --- Dependencies ---
const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

// --- Express App Initialization ---
const app = express();
app.use(express.json());
app.use(cors());

// --- Production Logging Middleware ---
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.originalUrl} from ${req.ip}`);
    next();
});


const PORT = process.env.PORT || 3000;

// --- API Key Authentication Middleware ---
const apiKeyAuth = (req, res, next) => {
    const userApiKey = req.headers['x-api-key'];
    if (!userApiKey || userApiKey !== process.env.MY_API_KEY) {
        console.warn(`[WARN] Unauthorized access attempt from ${req.ip} with key: ${userApiKey}`);
        return res.status(401).json({ error: 'Unauthorized. Invalid or missing API Key.' });
    }
    next();
};

// --- API Routes ---

/**
 * @route   POST /api/v1/call/tts
 * @desc    Initiates a Text-to-Speech (TTS) voice call.
 * @access  Private (Requires API Key)
 */
app.post('/api/v1/call/tts', apiKeyAuth, async (req, res) => {
    const { to, text, from, language = 'en', speechRate = 1 } = req.body;

    if (!to || !text) {
        return res.status(400).json({ error: 'Missing required fields: `to` and `text` are required.' });
    }
    
    const callerId = from || process.env.DEFAULT_CALLER_ID;

    const infobipPayload = {
        from: callerId,
        to: to,
        text: text,
        language: language,
        voice: {
            name: "Joanna",
            gender: "female"
        },
        speechRate: speechRate
    };

    const infobipHeaders = {
        'Authorization': `App ${process.env.INFOBIP_API_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    const infobipApiUrl = `https://${process.env.INFOBIP_BASE_URL}/tts/3/single`;

    try {
        console.log(`[INFO] Sending request to Infobip for recipient: ${to}`);
        const infobipResponse = await axios.post(infobipApiUrl, infobipPayload, { headers: infobipHeaders });

        console.log(`[SUCCESS] Call initiated for ${to}. BulkId: ${infobipResponse.data.bulkId}`);
        res.status(200).json({
            message: 'Call initiated successfully.',
            tracking: infobipResponse.data
        });

    } catch (error) {
        const timestamp = new Date().toISOString();
        console.error(`[${timestamp}] [ERROR] Failed to call Infobip for ${to}. Reason: ${error.message}`);

        if (error.response) {
            console.error('[ERROR_DETAILS] Infobip Response Status:', error.response.status);
            console.error('[ERROR_DETAILS] Infobip Response Body:', JSON.stringify(error.response.data, null, 2));
            const statusCode = error.response.status || 500;
            const errorMessage = error.response.data.requestError?.serviceException?.text || 'An error occurred with the backend voice service.';
            return res.status(statusCode).json({
                error: 'Failed to initiate call via backend service.',
                details: errorMessage,
            });
        }
        
        const errorMessage = error.message || 'Internal Server Error';
        res.status(500).json({
            error: 'Failed to initiate call via backend service.',
            details: `A network or configuration error occurred on the server: ${errorMessage}.`
        });
    }
});

/**
 * @route   GET /api/v1/call/status/:bulkId
 * @desc    Gets the delivery status report for a call bulk.
 * @access  Private (Requires API Key)
 */
app.get('/api/v1/call/status/:bulkId', apiKeyAuth, async (req, res) => {
    const { bulkId } = req.params;

    if (!bulkId) {
        return res.status(400).json({ error: 'Missing bulkId parameter.' });
    }
    
    const infobipHeaders = {
        'Authorization': `App ${process.env.INFOBIP_API_KEY}`,
        'Accept': 'application/json'
    };
    
    // This is the Infobip endpoint for getting text-to-speech reports
    const infobipReportsUrl = `https://${process.env.INFOBIP_BASE_URL}/tts/3/reports?bulkId=${bulkId}`;

    try {
        console.log(`[INFO] Fetching status for bulkId: ${bulkId}`);
        const reportsResponse = await axios.get(infobipReportsUrl, { headers: infobipHeaders });
        
        console.log(`[SUCCESS] Status retrieved for bulkId: ${bulkId}`);
        res.status(200).json(reportsResponse.data);

    } catch (error) {
        const timestamp = new Date().toISOString();
        console.error(`[${timestamp}] [ERROR] Failed to get status for bulkId ${bulkId}. Reason: ${error.message}`);

        if (error.response) {
            const statusCode = error.response.status || 500;
            const errorMessage = error.response.data.requestError?.serviceException?.text || 'An error occurred while fetching status.';
            return res.status(statusCode).json({
                error: 'Failed to get call status.',
                details: errorMessage,
            });
        }
        
        res.status(500).json({
            error: 'Failed to get call status.',
            details: `A network or configuration error occurred on the server.`
        });
    }
});


// --- Server Startup ---
app.listen(PORT, () => {
    console.log(`TTS API Server is running in production mode on port ${PORT}`);
    if (!process.env.MY_API_KEY || !process.env.INFOBIP_BASE_URL || !process.env.INFOBIP_API_KEY) {
        console.error('[FATAL] CRITICAL ENVIRONMENT VARIABLE MISSING. Shutting down.');
        process.exit(1);
    }
});
