TTS Voice API - Full DocumentationWelcome to the TTS Voice API! This service allows you to programmatically send outbound voice calls with text-to-speech and check the delivery status of those calls.The API acts as a secure wrapper around the Infobip backend, protecting your primary API keys.Base URLAll API endpoints are relative to your production server's base URL:https://api.sespcl.com/api/v1AuthenticationAll endpoints are protected by an API key. You must include your assigned key in the x-api-key header with every request.Required HeadersHeaderDescriptionx-api-keyRequired. Your private API key.Content-TypeRequired. Must be application/json for POST requests.Endpoints1. Send TTS CallThis endpoint initiates a new text-to-speech voice call to a specified recipient.Endpoint: /call/ttsMethod: POSTRequest BodyParameterTypeDescriptionRequiredtoStringRequired. The recipient's phone number in E.164 format (e.g., +15053753840).YestextStringRequired. The text message to be converted to speech.YesfromStringOptional. The caller ID to be displayed, in E.164 format. If not provided, the system's default caller ID will be used.NolanguageStringOptional. The language of the text. Defaults to en (English).NospeechRateNumberOptional. The speed of the speech. 1 is normal speed. Defaults to 1.NoExample Request (curl)curl -X POST \
  https://api.sespcl.com/api/v1/call/tts \
  -H 'x-api-key: YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "to": "+15053753840",
    "text": "Hello, this is a test call from the API.",
    "from": "+15053761293"
  }'
Success Response (200 OK)A successful request returns a bulkId which is the unique identifier for this call request.{
    "message": "Call initiated successfully.",
    "tracking": {
        "bulkId": "2034072219640523072",
        "messages": [
            // ... message details
        ]
    }
}
2. Get Call StatusThis endpoint retrieves the delivery status report for a previously initiated call.Endpoint: /call/status/:bulkIdMethod: GETURL Parameter:bulkId: Required. The unique ID that was returned when the call was first created.Example Request (curl)curl -X GET \
  https://api.sespcl.com/api/v1/call/status/2034072219640523072 \
  -H 'x-api-key: YOUR_API_KEY'
Success Response (200 OK)The response contains an array of results. The status object gives the most recent delivery information for the call.{
    "results": [
        {
            "bulkId": "2034072219640523072",
            "messageId": "2034072219640523073",
            "to": "15053753840",
            "sentAt": "2025-06-13T20:30:00.123Z",
            "doneAt": "2025-06-13T20:30:15.456Z",
            "messageCount": 1,
            "price": {
                "pricePerMessage": 0.005,
                "currency": "USD"
            },
            "status": {
                "groupId": 3,
                "groupName": "DELIVERED",
                "id": 5,
                "name": "DELIVERED_TO_HANDSET",
                "description": "Message delivered to handset"
            },
            "error": {
                "groupId": 0,
                "groupName": "OK",
                "id": 0,
                "name": "NO_ERROR",
                "description": "No Error",
                "permanent": false
            }
        }
    ]
}
Common Status GroupsPENDING: The call is still being processed.DELIVERED: The call was answered.UNDELIVERABLE: The call could not be completed (e.g., invalid number).REJECTED: The recipient rejected the call.EXPIRED: The call was not answered within the timeout period.Error ResponsesIf a request fails, the API will return an appropriate error code and a JSON body with details.401 Unauthorized{
    "error": "Unauthorized. Invalid or missing API Key."
}
400 Bad Request{
    "error": "Missing required fields: `to` and `text` are required."
}
5xx Server Error{
    "error": "Failed to initiate call via backend service.",
    "details": "An error occurred with the backend voice service."
}
