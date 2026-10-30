# 🚀 CASOC 100% Free Multi-Server Cloud Deployment Guide
**Architecture:** Cloudflare Pages (Frontend) + Render.com (APIs) + Oracle Cloud Always Free (Ollama AI)

---

## 📋 Architectural Overview

```
[ Security Admin / Browser ]
             │
             ▼ HTTPS (Port 443)
┌─────────────────────────────────────────────────────────────┐
│ 1. Frontend Web App (Cloudflare Pages or Vercel - Free CDN) │
│    URL: https://casoc.pages.dev                            │
└──────────────────────┬──────────────────────┬───────────────┘
                       │                      │
       WebSocket / REST│                      │ REST API
                       ▼                      ▼
┌──────────────────────────────┐   ┌──────────────────────────────┐
│ 2. NIDS ML API (Render Free) │   │ 3. Insider UEBA (Render Free)│
│    URL: ...onrender.com      │◄──│    URL: ...onrender.com      │
│    Engine: LightGBM + XAI    │   │    Engine: Isolation Forest  │
└──────────────┬───────────────┘   └──────────────────────────────┘
               │
               │ HTTP / Private Tunnel
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. AI Copilot Node (Oracle Cloud Always Free VM / Tunnel)   │
│    URL: https://ollama.yourdomain.com (Port 11434)          │
│    Engine: Ollama (llama3.2 / qwen2.5)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Step 1: Deploy Core Backend APIs to Render.com (Free)

We have created a ready-to-use [`render.yaml`](./render.yaml) blueprint in the repository.

1. Sign up / Log in to [Render.com](https://render.com).
2. Click **New +** ➔ **Blueprint**.
3. Connect your Git repository.
4. Render will detect [`render.yaml`](./render.yaml) and automatically create **both services**:
   - `casoc-nids-ml-api` (Root: `src/flask-api`)
   - `casoc-insider-threat` (Root: `src/insider-threat`)
5. Click **Apply**.
6. When deployment finishes, note your two live URLs:
   - `NIDS_API_URL`: e.g., `https://casoc-nids-ml-api.onrender.com`
   - `INSIDER_API_URL`: e.g., `https://casoc-insider-threat.onrender.com`

---

## 🌐 Step 2: Deploy Frontend to Cloudflare Pages (or Vercel)

1. Sign up / Log in to [Cloudflare Dashboard](https://dash.cloudflare.com) ➔ **Workers & Pages** ➔ **Create application** ➔ **Pages** ➔ **Connect to Git**.
2. Select your repository and configure the build settings:
   - **Framework preset:** `Vite`
   - **Root directory:** `src/frontend/my-app`
   - **Build command:** `npm run build`
   - **Build output directory:** `build`
3. Expand **Environment variables** and add:
   | Variable | Value |
   | :--- | :--- |
   | `VITE_NIDS_API_URL` | `https://casoc-nids-ml-api.onrender.com` |
   | `VITE_INSIDER_API_URL` | `https://casoc-insider-threat.onrender.com` |
   | `VITE_AGENT_API_KEY` | `dev-agent-key-change-in-production` |
4. Click **Save and Deploy**.
   *(SPA routing is already handled by [`public/_redirects`](./src/frontend/my-app/public/_redirects).)*

---

## 🧠 Step 3: Deploy Ollama AI Node (100% Free on Oracle Cloud)

Oracle Cloud provides an **Always Free Tier** with an **Ampere A1 ARM Compute Instance** (up to **4 OCPUs and 24 GB of RAM** with 0 cost forever).

### Option 3A: Oracle Cloud Always Free VM Setup

1. Create a free account at [cloud.oracle.com](https://www.oracle.com/cloud/free/).
2. Create an **Ampere (ARM) VM Instance**:
   - Image: Ubuntu 22.04 or 24.04 (aarch64)
   - Shape: `VM.Standard.A1.Flex` (4 OCPUs, 24 GB RAM)
3. SSH into the instance and install Ollama:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```
4. Configure Ollama to listen on all interfaces:
   ```bash
   sudo mkdir -p /etc/systemd/system/ollama.service.d
   echo -e '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0:11434"\nEnvironment="OLLAMA_ORIGINS=*"' | sudo tee /etc/systemd/system/ollama.service.d/override.conf
   sudo systemctl daemon-reload
   sudo systemctl restart ollama
   ```
5. Pull the models:
   ```bash
   ollama pull llama3.2
   ollama pull qwen2.5:1.5b
   ```
6. Open Port `11434` in Oracle Cloud **VCN Ingress Rules** (or restrict to your Render server IP).
7. In Render dashboard, set `OLLAMA_BASE_URL` on `casoc-nids-ml-api` to:
   `http://<YOUR_ORACLE_VM_IP>:11434`

---

### Option 3B: Run Ollama on Your Local PC via Free Cloudflare Tunnel

If you already have Ollama running locally and want the cloud NIDS API to reach it without paying for a cloud VM:

1. Install Cloudflare Tunnel (`cloudflared`):
   ```bash
   brew install cloudflared  # On macOS
   ```
2. Start an instant, zero-cost public tunnel pointing to your local Ollama port:
   ```bash
   cloudflared tunnel --url http://localhost:11434
   ```
3. Cloudflare will output a public HTTPS URL (e.g. `https://random-subdomain.trycloudflare.com`).
4. In Render, set `OLLAMA_BASE_URL` on `casoc-nids-ml-api` to that Cloudflare URL!

---

## ✅ Deployment Verification Checklist

- [ ] `https://casoc-nids-ml-api.onrender.com/health` returns `{"status":"healthy","model_loaded":true}`.
- [ ] `https://casoc-insider-threat.onrender.com/health` returns `{"status":"healthy"}`.
- [ ] Open your Cloudflare Pages URL (e.g., `https://casoc.pages.dev`).
- [ ] Top bar displays: **ML Service: ONLINE** and **AI Engine: ONLINE**.
- [ ] Click **"AI Copilot"** and ask: *"How many are blocked?"* or *"What is this project?"*.
