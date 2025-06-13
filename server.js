//
// Custom Text-to-Speech (TTS) Voice API Server
// ---------------------------------------------
// This Node.js application creates a simple API wrapper around the Infobip TTS API.
// It exposes a single endpoint to send outbound voice calls with text-to-speech.
//
// How to Run:
// 1. Install dependencies: npm install express axios dotenv cors
// 2. Create a .env file in the same directory with the variables below.
// 3. Run the server: node server.js
//

// --- Environment Variables (.env file) ---
//
// # Your secret key to protect your new API endpoint
// MY_API_KEY=your-super-secret-api-key
//
// # Your Infobip Account Details
// INFOBIP_BASE_URL=your.api.infobip.com
// INFOBIP_API_KEY=your-infobip-api-key
//
// # The default caller ID (a voice number you have with Infobip)
// DEFAULT_CALLER_ID=447418369169
//

// --- Dependencies ---
const express = require('express');
const axios = require('axios');
const cors = require('cors'); // Import the CORS package
require('dotenv').config();

// --- Express App Initialization ---
const app = express();
app.use(express.json()); // Middleware to parse JSON bodies

// --- CORS Middleware ---
// This is the fix. It allows your web app (on a different domain) to make requests to this API.
app.use(cors());

const PORT = process.env.PORT || 3000;

// --- API Key Authentication Middleware ---
// This function checks if a valid API key is provided in the request headers.
const apiKeyAuth = (req, res, next) => {
    const userApiKey = req.headers['x-api-key'];
    if (!userApiKey || userApiKey !== process.env.MY_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized. Invalid or missing API Key.' });
    }
    next(); // API key is valid, proceed to the next handler.
};

// --- API Routes ---

/**
 * @route   POST /api/v1/call/tts
 * @desc    Initiates a Text-to-Speech (TTS) voice call.
 * @access  Private (Requires API Key)
 */
app.post('/api/v1/call/tts', apiKeyAuth, async (req, res) => {
    // 1. Validate incoming request body, now including the optional 'from' field.
    const { to, text, from, language = 'en', speechRate = 1 } = req.body;

    if (!to || !text) {
        return res.status(400).json({ error: 'Missing required fields: `to` and `text` are required.' });
    }
    
    // 2. Determine the caller ID. Use the 'from' number if provided, otherwise use the default.
    const callerId = from || process.env.DEFAULT_CALLER_ID;


    // 3. Prepare the request payload for the Infobip API
    const infobipPayload = {
        from: callerId, // Use the determined callerId
        to: to,
        text: text,
        language: language,
        voice: {
            name: "Joanna", // This could also be made configurable in the request body
            gender: "female"
        },
        speechRate: speechRate
    };

    // 4. Configure headers for the Infobip API call
    const infobipHeaders = {
        'Authorization': `App ${process.env.INFOBIP_API_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    const infobipApiUrl = `https://${process.env.INFOBIP_BASE_URL}/tts/3/single`;

    try {
        // 5. Make the POST request to the Infobip API
        console.log(`Sending request to Infobip from ${callerId} for recipient: ${to}`);
        const infobipResponse = await axios.post(infobipApiUrl, infobipPayload, { headers: infobipHeaders });

        console.log('Successfully received response from Infobip.');
        // 6. Send a success response back to the original caller
        res.status(200).json({
            message: 'Call initiated successfully.',
            tracking: infobipResponse.data
        });

    } catch (error) {
        // 7. Handle errors from the Infobip API
        console.error('Error calling Infobip API:', error.response ? error.response.data : error.message);

        const statusCode = error.response ? error.response.status : 500;
        const errorMessage = error.response ? error.response.data : 'Internal Server Error';

        res.status(statusCode).json({
            error: 'Failed to initiate call via backend service.',
            details: errorMessage
        });
    }
});


// --- Server Startup ---
app.listen(PORT, () => {
    console.log(`TTS API Server is running on port ${PORT}`);
    if (!process.env.MY_API_KEY || !process.env.INFOBIP_BASE_URL || !process.env.INFOBIP_API_KEY || !process.env.DEFAULT_CALLER_ID) {
        console.warn('Warning: One or more required environment variables are not set. Please check your .env file.');
    }
});
