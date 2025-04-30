# azure_openai_client.py
import os
from openai import AzureOpenAI, OpenAIError

# --- Configuration from Environment Variables ---
AZURE_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_DEPLOYMENT_NAME = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")

# --- Initialize Client ---
client = None
is_configured = False
if AZURE_ENDPOINT and AZURE_API_KEY and AZURE_DEPLOYMENT_NAME:
    try:
        client = AzureOpenAI(
            azure_endpoint=AZURE_ENDPOINT,
            api_key=AZURE_API_KEY,
            api_version="2024-02-01" # Specify a stable API version
        )
        is_configured = True
        print("Azure OpenAI client configured successfully.")
    except Exception as e:
        print(f"ERROR: Failed to configure Azure OpenAI client: {e}")
else:
    print("ERROR: Azure OpenAI environment variables not fully set.")

def get_chat_response(user_message, system_prompt="You are a helpful DevOps assistant."):
    """Gets a chat response from the configured Azure OpenAI deployment."""
    if not is_configured or not client:
        return "Error: Azure OpenAI client is not configured. Please check server logs and environment variables."

    print(f"Sending query to Azure OpenAI deployment '{AZURE_DEPLOYMENT_NAME}': '{user_message[:50]}...'")
    try:
        response = client.chat.completions.create(
            model=AZURE_DEPLOYMENT_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            temperature=0.7,
            max_tokens=800
        )

        if response.choices:
            print("Received response from Azure OpenAI.")
            return response.choices[0].message.content.strip()
        else:
            print("Warning: Azure OpenAI returned no choices.")
            # Add check for content filtering if needed based on Azure setup
            return "Sorry, I received an unexpected empty response from the AI."

    except OpenAIError as e:
        print(f"ERROR: Azure OpenAI API error: {e}")
        error_message = f"Error communicating with Azure OpenAI: Status Code {e.status_code}"
        if hasattr(e, 'message') and e.message: error_message += f" - {e.message}"
        elif hasattr(e, 'body') and e.body and 'message' in e.body: error_message += f" - {e.body['message']}" # More robust error message extraction
        return error_message
    except Exception as e:
        print(f"ERROR: Unexpected error in get_chat_response: {e}")
        return f"An unexpected error occurred on the server: {e}"

