Custom Text-to-Speech (TTS) Voice API Server

This repository contains the source code for a self-hosted API that acts as a wrapper around the Infobip Voice API. It provides a simple, protected endpoint to initiate outbound PSTN (Public Switched Telephone Network) calls with text-to-speech functionality.
Use Cases

This API is ideal for developers and businesses looking to integrate automated voice notifications into their applications without exposing their core Infobip API keys on the client-side.

    Automated Alerts: Send voice call alerts for critical system events, server outages, or important notifications.

    Two-Factor Authentication (2FA): Deliver one-time passcodes via a voice call as an alternative to SMS.

    Appointment Reminders: Automatically call customers to remind them of upcoming appointments or reservations.

    Order Status Updates: Notify customers via a voice call when their order has been shipped, is out for delivery, or has been delivered.

    Marketing Campaigns: Send promotional messages or special offers to a list of customers via automated voice calls.

By using this wrapper, you create a secure and simplified interface for your applications to trigger these calls.
Getting Started: Installation & Deployment

Follow these instructions to deploy the API server from this GitHub repository to your own cloud server (e.g., AWS, DigitalOcean, Linode, etc.).
Prerequisites

Before you begin, ensure you have the following installed on your server:

    Node.js (version 14.x or newer)

    npm (Node Package Manager)

    Git

1. Clone the Repository

Connect to your server via SSH and clone this repository.

# Navigate to your desired project directory
cd /var/www

# Clone the repository
git clone https://github.com/your-username/your-repo-name.git

# Enter the new project directory
cd your-repo-name

2. Install Dependencies

Install the required Node.js packages listed in package.json.

npm install

3. Configure Environment Variables

Create a .env file in the root of the project to store your secret keys and configuration. This file should never be committed to Git.

# Create the .env file
nano .env

Add the following variables to the file, replacing the placeholder values with your actual credentials.

# Your secret key to protect your new API endpoint
MY_API_KEY=your-super-secret-api-key

# Your Infobip Account Details (e.g., xyz123.api.infobip.com)
INFOBIP_BASE_URL=your.api.infobip.com

# Your Infobip API Key
INFOBIP_API_KEY=your-infobip-api-key

# The default caller ID (a voice number you have with Infobip)
DEFAULT_CALLER_ID=447418369169

4. Run the Application with a Process Manager

To ensure your API runs continuously and restarts automatically if it crashes or the server reboots, use a process manager like PM2.

# Install PM2 globally on your server
npm install pm2 -g

# Start the API server with PM2
pm2 start server.js --name "tts-api-server"

# (Optional but Recommended) Save the PM2 process list to restart on server reboot
pm2 save

Your API is now live and running! You can monitor it using the command pm2 status.
API Documentation

This server exposes a single endpoint for initiating calls. For full details on the request body, parameters, and example responses, please refer to the complete API Documentation. (You can link to the custom_api_documentation artifact or a hosted version of it).
Quick Reference

    Method: POST

    Endpoint: /api/v1/call/tts

    Auth: Requires x-api-key in the header.

Example Request (cURL)

curl -X POST \
  http://your-server-address:3000/api/v1/call/tts \
  -H 'x-api-key: your-super-secret-api-key' \
  -H 'Content-Type: application/json' \
  -d '{
    "from": "447418369170",
    "to": "442071234567",
    "text": "This is a test call from our API platform!"
  }'

Contributing

Contributions are welcome! If you have suggestions for improvements or find any issues, please feel free to open an issue or submit a pull reque
