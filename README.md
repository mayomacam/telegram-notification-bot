# Secure Telegram Notification Gateway

A highly secure, SOC 2-aligned lightweight gateway that receives webhook payloads from any service and forwards them to a Telegram chat. 

Designed to run in [Coolify](https://coolify.io/) or standard Docker environments.

## 🔒 Security Features
* **Least Privilege:** Runs as a non-root user (`appuser`) inside the container.
* **Access Control:** All endpoints are protected by an `X-API-Key` strict header requirement.
* **Secrets Management:** Zero hardcoded credentials. Controlled entirely via Environment Variables.
* **Robust Parsing:** Built with FastAPI and Pydantic to safely parse unexpected JSON payloads without crashing.
* **Health Probes:** Built-in `/health` endpoint for Docker/Coolify readiness checks.

## 🏗 Architecture Flow
`Any Service` ➔ `POST /notify (with X-API-Key)` ➔ `Gateway (Validates & Parses)` ➔ `Telegram API` ➔ `Your Phone`

## ⚙️ Environment Variables

You must provide the following environment variables in your Coolify/Docker configuration:

| Variable | Description | Example |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Token provided by @BotFather | `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11` |
| `TELEGRAM_CHAT_ID` | Your personal Chat ID (via @userinfobot) | `987654321` |
| `API_SECRET_KEY` | A strong password you generate to protect this API | `your-super-secret-key-123` |

## 🚀 Deployment (Coolify)

1. Push this repository to GitHub/GitLab.
2. In Coolify, create a new **Git Repository** resource.
3. Select this repository. Coolify will automatically detect the `Dockerfile`.
4. Go to **Environment Variables** and add the three variables listed above.
5. *(Optional)* If you want to receive webhooks from external services (like GitHub), set up a **Domain** in the Coolify configuration (e.g., `https://notify.yourdomain.com`).
6. Click **Deploy**.

## 📡 Usage

Once deployed, you can configure any service to send a `POST` request to your bot. 

### Security Header
You **must** include the `X-API-Key` header in all requests, otherwise the bot will return a `403 Unauthorized` error.

### 1. Sending a Simple Text Message
```bash
curl -X POST "https://notify.yourdomain.com/notify" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: your-super-secret-key-123" \
     -d '{"message": "✅ Database backup completed successfully!"}'
