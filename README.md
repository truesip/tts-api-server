# TrueSIP Hybrid Voice API Server

High-performance Text-to-Speech Voice API Server with **SIP routing** and Infobip integration, optimized for 1M+ requests.

🔥 **NEW**: Direct SIP trunk routing - bypass third-party providers and connect directly to your VoIP infrastructure!

## 🚀 Features

### 🌟 **Multi-Provider Routing**
- **📞 VoIP Services**: Twilio, Vonage, AWS Connect, Wavix
- **🎯 SIP Routing**: Direct connection to SIP trunks and VoIP providers
- **☁️ Infobip Routing**: Cloud-based API routing (fallback)
- **🔄 Hybrid Mode**: Automatic failover between providers

### ⚡ **Core Capabilities**
- **High-Performance**: Handles 1M+ requests with clustering and connection pooling
- **TTS & Audio**: Text-to-speech and audio file playback
- **IVR Support**: Call transfers with DTMF
- **Content Analysis**: Optional Perspective API integration
- **Audio Transcription**: Google Speech-to-Text support
- **Caching**: Intelligent in-memory caching
- **Security**: Rate limiting, validation, and security headers
- **Production Ready**: Clustering, monitoring, and graceful shutdown

## 📋 API Endpoints

### POST `/api/v1/call/tts`
Initiate voice calls with TTS, audio files, or IVR transfer.

### GET `/api/v1/call/status/:bulkId`
Get call status and reports.

### GET `/health`
Health check with system metrics.

## 🔧 Environment Variables

### Required
```env
MY_API_KEY=your_secure_api_key
DEFAULT_CALLER_ID=+1234567890
```

### VoIP Provider Configuration (Choose One)
```env
# Wavix (Recommended)
USE_VOIP=true
VOIP_PROVIDER=wavix
WAVIX_API_KEY=your_wavix_api_key

# Twilio
USE_VOIP=true
VOIP_PROVIDER=twilio
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token

# SIP Direct
USE_SIP=true
SIP_PROXY_HOST=your_sip_server
SIP_USERNAME=your_username
SIP_PASSWORD=your_password
SIP_DOMAIN=your_domain

# Infobip (Fallback)
INFOBIP_BASE_URL=your_infobip_base_url
INFOBIP_API_KEY=your_infobip_api_key
```

### Optional
```env
PERSPECTIVE_API_KEY=your_perspective_api_key
GOOGLE_SPEECH_API_KEY=your_google_speech_api_key
RATE_LIMIT_MAX=10000
HEAVY_RATE_LIMIT_MAX=500
TRUST_PROXY=true
LOG_LEVEL=info
```

## 🏗️ Deployment

### Local Development
```bash
npm install
cp .env.production.example .env
# Edit .env with your settings
npm run dev
```

### DigitalOcean App Platform
1. Push to GitHub repository
2. Create app on DigitalOcean
3. Connect GitHub repository
4. Set environment variables
5. Deploy!

## 📊 Performance

- **Single Instance**: 500-1,000 req/sec
- **Clustered**: 2,000-4,000 req/sec
- **Load Balanced**: 10,000+ req/sec

## 💰 Cost (Database-Free)

- **DigitalOcean App Platform**: ~$12/month
- **No database costs**
- **Scales automatically**

## 🔒 Security

- API key authentication
- Rate limiting (10,000 req/15min)
- Input validation
- Security headers (Helmet.js)
- Content analysis (optional)

## 📈 Monitoring

- Health check endpoint
- Memory usage monitoring
- Cache statistics
- Structured logging (Pino)

## 🆘 Support

Check the `SCALING_GUIDE.md` for detailed production deployment instructions.
