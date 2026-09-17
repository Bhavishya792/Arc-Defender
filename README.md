# 🛡️ ARC Defender

> **Web Application Attack Detection & Traffic Intelligence System**  
> *A developer-first, zero-external-dependency security engine with real-time telemetry, heuristic rule detection, and unsupervised Isolation Forest anomaly scoring.*

---

[![Node Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)]()
[![ML Model](https://img.shields.io/badge/ML-Isolation%20Forest%20(Subsampled)-orange.svg)]()
[![Interface](https://img.shields.io/badge/UI-GitHub%20Dark%20%7C%20Responsive-blueviolet.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## 📑 Table of Contents
1. [Executive Overview](#-executive-overview)
2. [Block Architecture Diagrams](#-block-architecture-diagrams)
3. [Quick Start Guide for New Users](#-quick-start-guide-for-new-users)
4. [Connecting Your Own API](#-connecting-your-own-api)
   - [Option A: Drop-in Node.js / Express Middleware](#option-a-drop-in-nodejs--express-middleware)
   - [Option B: Python / FastAPI & Flask Middleware](#option-b-python--fastapi--flask-middleware)
   - [Option C: Universal HTTP Ingestion API (`/arc/api/v1/ingest`)](#option-c-universal-http-ingestion-api-arcapiv1ingest)
   - [Option D: Go (Gin) & Microservices](#option-d-go-gin--microservices)
5. [Threat Detection & Machine Learning Engine](#-threat-detection--machine-learning-engine)
   - [Rule-Based Heuristic Scanners](#rule-based-heuristic-scanners)
   - [Isolation Forest Anomaly Architecture](#isolation-forest-anomaly-architecture)
   - [Mathematical Normalization ($c(n)$)](#mathematical-normalization-cn)
6. [Interactive Built-in Threat Simulator](#-interactive-built-in-threat-simulator)
7. [API Endpoint Reference](#-api-endpoint-reference)
8. [Responsive Design & Mobile Support](#-responsive-design--mobile-support)
9. [Project Structure](#-project-structure)

---

## 🌟 Executive Overview

Modern cloud APIs and microservices face relentless automated threats: credential stuffing, brute force attacks, distributed endpoint discovery probes, and erratic latency spikes. Enterprise SIEM tools (Datadog, Splunk) are often cloud-bound, opaque, and cost-prohibitive for developers and small teams.

**ARC Defender** is a self-contained, developer-grade security intelligence platform that bridges this gap:
- **Zero Heavy Infrastructure:** Runs in-memory with persistent-ready hooks; requires no external Redis, Kafka, or cloud SIEM setup.
- **Dual Defense Pipeline:** Combines **deterministic heuristic rules** (instant alert triggering) with an **unsupervised Isolation Forest** (discovering unknown abnormal behavior without labeled attack datasets).
- **Interactive Live Dashboard:** GitHub-inspired dark interface with real-time telemetry metrics, Chart.js visualizations, client risk drilldowns, and responsive layout across desktops, tablets, and phones.
- **Both Demo & Production Ready:** Includes pre-loaded synthetic attacks for instant testing, plus ready-to-use SDKs and REST ingestion endpoints for securing real production APIs.

---

## 📐 Block Architecture Diagrams

### 1. High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             EXTERNAL TRAFFIC & CLIENTS                      │
└──────┬───────────────────────────────────┬───────────────────────────┬──────┘
       │ [Your Express API]                │ [Your Python FastAPI]     │ [cURL / Any Webhook]
       ▼                                   ▼                           ▼
┌──────────────────┐               ┌──────────────────┐        ┌──────────────────┐
│  arcClient (TS)  │               │arc_middleware(PY)│        │   POST Payload   │
└──────┬───────────┘               └───────┬──────────┘        └───────┬──────────┘
       │ Non-blocking Stream               │ Async HTTP                │ JSON Telemetry
       └─────────────────────────┬─────────┴───────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ARC DEFENDER INGESTION LAYER                      │
│                                                                             │
│   • POST /arc/api/v1/ingest         (Single HTTP Event)                     │
│   • POST /arc/api/v1/batch-ingest   (Buffered Microservice Batches)         │
│   • In-Process Middleware Hooks     (Zero-overhead native interception)     │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │ Sanitization & IP Normalization
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             ARC STORAGE & STATE                             │
│                                                                             │
│   ┌────────────────────────┐  ┌────────────────────────┐  ┌──────────────┐  │
│   │ Requests Database (WAL)│  │ Security Alerts Log    │  │ ML Results   │  │
│   └────────────────────────┘  └────────────────────────┘  └──────────────┘  │
└───────────────┬────────────────────────────────┬────────────────────────────┘
                │                                │
                ▼                                ▼
┌──────────────────────────────┐ ┌────────────────────────────────────────────┐
│   RULE-BASED DETECTOR        │ │   ISOLATION FOREST ML ENGINE               │
│                              │ │                                            │
│ • Brute Force (Login 401s)   │ │ • 9-D Behavioral Feature Vector Extraction │
│ • High Request Rate (DoS)    │ │ • Subsampled iTree Ensembles (Liu et al.)  │
│ • 404 Endpoint Scanning      │ │ • Euler-Mascheroni c(n) Path Normalization │
│ • 5xx Server Error Spikes    │ │ • Student-Friendly Diagnostic Breakdown    │
└───────────────┬──────────────┘ └──────────────────────┬─────────────────────┘
                │                                       │
                └───────────────────┬───────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMPOSITE RISK ENGINE (0 - 100)                      │
│                                                                             │
│         Risk = 0.35(Brute) + 0.25(Scan) + 0.20(Rate) + 0.20(ML Anomaly)     │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     RESPONSIVE DASHBOARD & REST API                         │
│                                                                             │
│   [Overview Stats]  [Traffic Analytics]  [Security Center]  [API Connect]   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2. Isolation Forest Machine Learning Pipeline

```
Raw Telemetry Logs
      │
      ▼
Client Feature Aggregation (9 Behavioral Dimensions)
  ┌─────────────────────────────────────────────────────────┐
  │ 1. Request Count        2. Failure Rate (4xx)           │
  │ 3. Error Rate (5xx)     4. Avg Latency (ms)             │
  │ 5. Latency Variance     6. Path Entropy (Scan breadth)  │
  │ 7. Method Diversity     8. Login Ratio                  │
  │ 9. Nighttime Ratio (02:00-06:00 UTC)                    │
  └───────────────────────────┬─────────────────────────────┘
                              │ Subsampling (max 64 samples per tree)
                              ▼
           ┌─────────────────────────────────────┐
           │ Ensemble of 100 Isolation Trees     │
           │ (Recursive variance-based splitting)│
           └──────────────────┬──────────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
        [Normal Client]               [Anomalous Client]
   (Deep tree depth: h(x) >> c(n)) (Shallow tree depth: h(x) << c(n))
               │                             │
               ▼                             ▼
       Score: 10 - 30/100            Score: 75 - 95/100
       Status: Benign Traffic        Status: Anomaly Detected
```

---

## 🚀 Quick Start Guide for New Users

### 1. Prerequisites
- **Node.js** >= 18.0.0
- **npm** >= 9.0.0
- *(Optional)* Python >= 3.8 if using Python SDK or simulation scripts

### 2. Installation & Launch
```bash
# Clone the repository
git clone https://github.com/your-org/arc-defender.git
cd arc-defender

# Install Node dependencies
npm install

# Run the development server
npm run dev
```

The application starts immediately on `http://localhost:3000`.

### 3. Exploring the Dashboard
Open your browser to `http://localhost:3000`:
1. **Overview Tab:** View live cluster status, threat banners, key statistics (total requests, unique clients, error counts, active alerts), and recent security events.
2. **Traffic Tab:** Explore interactive Chart.js graphs showing requests per minute, HTTP status code distributions, method breakdown, and latency percentiles ($p50$, $p95$, $p99$).
3. **Security Tab:** Inspect triggered rule-based alerts, run real-time threat scans, review Isolation Forest ML anomaly tables, and view client behavioral feature breakdowns.
4. **Requests Tab:** Live log stream with IP filtering, method filters, and full JSON payload inspectors.
5. **Connect Your API Tab:** Interactive live ingestion sandbox and copy-paste code snippets for multiple languages.

---

## 🔌 Connecting Your Own API

ARC Defender is designed to monitor external APIs and microservices seamlessly. You have multiple ways to stream telemetry:

### Option A: Drop-in Node.js / Express Middleware
If your backend is built with Express or Connect, use the bundled client SDK (`src/sdk/arcClient.ts`):

```typescript
import express from 'express';
import { ArcDefenderClient } from './src/sdk/arcClient.js';

const app = express();

// Initialize the ARC Defender telemetry client
const arc = new ArcDefenderClient({
  endpoint: 'http://localhost:3000', // Address of your ARC Defender instance
  batchFlushIntervalMs: 1000,       // Buffers requests and flushes asynchronously
  maxBatchSize: 50                  // Flushes immediately when buffer reaches 50 events
});

// Attach middleware before your routes
app.use(arc.middleware());

// Your normal API routes
app.get('/api/v1/products', (req, res) => {
  res.json({ status: 'ok', data: ['Laptop', 'Firewall'] });
});

app.listen(8080, () => console.log('API protected by ARC Defender on port 8080'));
```

---

### Option B: Python / FastAPI & Flask Middleware
If your service runs in Python, use `src/sdk/arc_middleware.py`:

#### 1. FastAPI Integration
```python
from fastapi import FastAPI
from src.sdk.arc_middleware import ArcDefenderClient, get_fastapi_middleware

app = FastAPI(title="My Production Service")

# Point client to ARC Defender
arc_client = ArcDefenderClient(endpoint="http://localhost:3000")

# Attach non-blocking middleware
ArcFastAPIMiddleware = get_fastapi_middleware(arc_client)
app.add_middleware(ArcFastAPIMiddleware)

@app.get("/api/v1/checkout")
def checkout():
    return {"status": "success"}
```

#### 2. Flask Integration
```python
from flask import Flask, request
from src.sdk.arc_middleware import ArcDefenderClient
import time

app = Flask(__name__)
arc = ArcDefenderClient(endpoint="http://localhost:3000")

@app.before_request
def start_timer():
    request._arc_start = time.perf_counter()

@app.after_request
def send_telemetry(response):
    elapsed_ms = (time.perf_counter() - getattr(request, '_arc_start', time.perf_counter())) * 1000
    arc.record_event(
        ip=request.headers.get("X-Forwarded-For", request.remote_addr),
        method=request.method,
        path=request.path,
        status_code=response.status_code,
        response_time_ms=elapsed_ms,
        user_agent=request.headers.get("User-Agent", "")
    )
    return response
```

---

### Option C: Universal HTTP Ingestion API (`/arc/api/v1/ingest`)
Any language, CLI, or cloud function can push telemetry directly via standard HTTP POST:

```bash
curl -X POST http://localhost:3000/arc/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.42",
    "method": "POST",
    "path": "/api/v1/auth/login",
    "status_code": 401,
    "response_time_ms": 28.4,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "is_login_attempt": true,
    "login_success": false
  }'
```

**Response (`201 Created`):**
```json
{
  "success": true,
  "message": "Telemetry event recorded successfully",
  "event_id": 142,
  "timestamp": "2026-09-17T11:28:44.120Z"
}
```

#### High-Throughput Batch Ingestion (`POST /arc/api/v1/batch-ingest`)
For high-volume services, send arrays of up to 1,000 events in a single HTTP request:
```bash
curl -X POST http://localhost:3000/arc/api/v1/batch-ingest \
  -H "Content-Type: application/json" \
  -d '[
    {"ip": "198.51.100.1", "method": "GET", "path": "/api/feed", "status_code": 200, "response_time_ms": 11.2},
    {"ip": "198.51.100.2", "method": "GET", "path": "/api/cart", "status_code": 200, "response_time_ms": 14.8}
  ]'
```

---

### Option D: Go (Gin) & Microservices
```go
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
	"github.com/gin-gonic/gin"
)

func ArcDefenderMiddleware(endpoint string) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start).Milliseconds()

		// Dispatch telemetry asynchronously
		go func() {
			body, _ := json.Marshal(map[string]interface{}{
				"ip":               c.ClientIP(),
				"method":           c.Request.Method,
				"path":             c.FullPath(),
				"status_code":      c.Writer.Status(),
				"response_time_ms": latency,
				"user_agent":       c.Request.UserAgent(),
			})
			http.Post(endpoint+"/arc/api/v1/ingest", "application/json", bytes.NewBuffer(body))
		}()
	}
}
```

---

## 🧠 Threat Detection & Machine Learning Engine

### Rule-Based Heuristic Scanners
ARC Defender inspects sliding telemetry windows for classic attack signatures:
1. **Brute Force Scanner:** Triggers when an IP exceeds 5 failed login attempts (`401/403`) in a short window.
2. **High Request Rate (DoS):** Flags IPs exceeding standard velocity limits (>40 requests/min).
3. **Endpoint Reconnaissance:** Identifies automated vulnerability scanners triggering repetitive `404 Not Found` responses on administrative and sensitive paths (`/wp-admin`, `/.env`, `/config.json`).
4. **Error Spike Detector:** Detects server instability when error rates (`5xx`) exceed standard thresholds.

### Isolation Forest Anomaly Architecture
Heuristics can only catch attacks you anticipate. ARC Defender uses an unsupervised **Isolation Forest** ensemble ($N_{trees} = 100$) to detect unknown statistical anomalies.

#### The 9 Behavioral Dimensions
For every active client IP, the engine extracts a 9-dimensional behavioral feature vector:
1. `request_count`: Total volume of requests.
2. `failure_rate`: Ratio of client errors (`4xx`).
3. `error_rate`: Ratio of server errors (`5xx`).
4. `avg_latency`: Mean round-trip latency (ms).
5. `latency_variance`: Variance in response timings (identifies script-driven vs. human pacing).
6. `path_entropy`: Shannon entropy $H(X) = -\sum p(x) \log_2 p(x)$ of visited endpoints.
7. `method_diversity`: Ratio of distinct HTTP verbs used.
8. `login_ratio`: Proportion of traffic targeted at authentication endpoints.
9. `nighttime_ratio`: Percentage of requests sent during off-peak hours (02:00–06:00 UTC).

#### Mathematical Normalization ($c(n)$)
Isolation Forest isolates anomalies by recursively selecting a random feature and split value. Anomalies have low tree depth because their unique feature values are isolated in very few splits.

The average search depth of an unsuccessful search in a Binary Search Tree (BST) provides the theoretical baseline $c(n)$:
$$c(n) = 2 \left( \ln(n - 1) + \gamma \right) - \frac{2(n - 1)}{n}$$
where $\gamma \approx 0.5772156649$ (Euler-Mascheroni constant).

The anomaly score $s$ for sample $x$ is normalized:
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
- **$s \to 1$ ($Score \ge 70$):** High likelihood anomaly (abnormal behavioral footprint).
- **$s \approx 0.5$ ($Score \approx 50$):** Typical borderline instance.
- **$s \to 0$ ($Score < 40$):** Normal, benign cluster member.

---

## 🎯 Interactive Built-in Threat Simulator

ARC Defender features an attack simulation engine for testing and demonstrations:
- **Brute Force Attack:** Injects 15 rapid POST requests targeting `/api/v1/auth/login` with `401 Unauthorized` responses.
- **Endpoint Scan:** Simulates vulnerability crawlers hitting `/wp-admin`, `/.git/config`, `/.env`, and `/phpmyadmin`.
- **High Rate Flood:** Generates 50 requests in rapid succession to trigger rate limiting alerts.
- **5xx Error Spike:** Injects internal database failures (`500 Server Error`).
- **Normal Traffic:** Simulates legitimate human browser behavior across multiple endpoints.

Simulations can be triggered directly from the **Dashboard Header dropdown** or programmatically via:
```bash
curl -X POST http://localhost:3000/arc/api/simulator/simulate?type=brute_force
```

---

## 📡 API Endpoint Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/arc/dashboard` | `GET` | Main UI Dashboard |
| `/arc/api/v1/ingest` | `POST` | Ingest single external telemetry event |
| `/arc/api/v1/batch-ingest` | `POST` | Ingest array of telemetry events |
| `/arc/api/v1/schema` | `GET` | Machine-readable ingestion schema |
| `/arc/api/threat-status`| `GET` | Current threat level (NORMAL, ELEVATED, CRITICAL) |
| `/arc/api/overview` | `GET` | Aggregated dashboard KPI counters |
| `/arc/api/overview/requests-over-time` | `GET` | Time-series request volume points |
| `/arc/api/traffic/endpoints` | `GET` | Breakdown of top hit API endpoints |
| `/arc/api/traffic/status-codes` | `GET` | HTTP status code distributions (2xx, 3xx, 4xx, 5xx) |
| `/arc/api/traffic/latency` | `GET` | Latency distribution & percentiles (p50, p95, p99) |
| `/arc/api/traffic/clients` | `GET` | Client IP telemetry & individual client profiles |
| `/arc/api/security/alerts` | `GET` | Active and historical security alerts |
| `/arc/api/security/detect` | `POST` | Manually run rule-based detectors |
| `/arc/api/ml/results` | `GET` | Latest Isolation Forest client scores & features |
| `/arc/api/ml/run` | `POST` | Manually retrain and score ML model |
| `/arc/api/simulator/simulate` | `POST` | Trigger synthetic attack simulation |

---

## 📱 Responsive Design & Mobile Support

The dashboard provides a dedicated responsive layout crafted with mobile-first CSS media queries:
- **Desktop (>= 1200px):** 4-column KPI cards, multi-column analytics, side-by-side ML diagnostic inspectors.
- **Tablets & Laptops (768px - 1024px):** 2-column auto-wrapping grids, scrollable data tables, touch-friendly chart tooltips.
- **Mobile Phones (< 768px):** Single-column stacked layout, touch targets exceeding 44px, horizontally scrollable navigation bar, and collapsible modal inspectors.

---

## 📁 Project Structure

```
arc-defender/
├── server.ts                     # Main Express server, routing & CORS
├── src/
│   ├── api.ts                    # REST API endpoints & Ingestion handlers
│   ├── database.ts               # In-memory ARC telemetry store & aggregations
│   ├── detector.ts               # Deterministic heuristic security scanners
│   ├── mlEngine.ts               # Isolation Forest implementation (Liu et al.)
│   ├── monitor.ts                # In-process Express interception middleware
│   ├── simulator.ts              # Synthetic attack generator
│   └── sdk/
│       ├── arcClient.ts          # Drop-in TypeScript / Node.js client SDK
│       └── arc_middleware.py     # Drop-in Python FastAPI / Flask middleware
├── static/
│   ├── chart.umd.min.js          # Bundled offline Chart.js v4 runtime
│   ├── dashboard.js              # Resilient frontend controller & API client
│   └── style.css                 # GitHub Dark theme + Responsive styles
├── templates/
│   └── dashboard.html            # Main multi-view application shell
├── requirements.txt              # Python requirements for SDK & data science
├── package.json                  # Node project manifest
└── README.md                     # Documentation
```

---

## 📄 License
This project is licensed under the MIT License — see the LICENSE file for details.
