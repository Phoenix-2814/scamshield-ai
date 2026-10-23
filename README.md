# ScamShield

ScamShield is a scam-safety product prototype focused on analyzing intent and explaining warning signs across suspicious messages and conversation transcripts. The web app submits content to a same-origin Node API. Rules-based analysis is available by default; when the operator configures Groq or Gemini, semantic analysis runs automatically.

## Run locally

Requirements: Node.js 20.19+ and npm. The frontend dependencies are listed in `frontend/package-lock.json`.

```sh
npm ci --prefix frontend
npm run dev
```

Open the Vite URL shown in the terminal. The dev command starts both the API on `127.0.0.1:8787` and Vite, which proxies `/api` requests to the API. To build the frontend, run `npm run build`. Run `npm run lint` for lint and syntax checks.

## API

- `GET /api/health` returns service health.
- `POST /api/analyze` accepts `{"message":"..."}` and returns an analysis with a request ID.
- `POST /api/check-url` accepts `{"url":"https://example.com"}` and performs a separate VirusTotal reputation check.
- `POST /api/analyze-media` accepts multipart `file` and `frames` fields for image/video review. Media review requires `GROQ_API_KEY`.

Requests must be JSON. Messages are limited to 5,000 characters. The API enforces a request body limit, applies a small per-process rate limit, sends browser security headers, and does not log message contents. The rate limiter is an in-memory prototype guard; it resets at restart and is not suitable across multiple replicas.

URL reputation is available as its own tool and automatically during message review when a message contains links. Message review checks up to three URLs; if a URL is not known yet, it can submit one new URL per message for scanning and show a pending result at first. A user can also submit a standalone URL for lookup or scanning in the URL tool. VirusTotal warns that URLs queried or submitted through its API are added to its community dataset, so do not submit private, confidential, or password-reset links. The app displays this notice before message review and in the URL tool, and keeps the API key on the server. VirusTotal's free Public API is limited to 4 requests per minute and 500 per day, and must not be used in commercial products or services; use a licensed Private API key for commercial use.

```text
VIRUSTOTAL_API_KEY=<your server-side VirusTotal API key>
```

## Optional AI analysis

Rules-based analysis is the default. To enable Groq locally, copy `.env.example` to `.env`, uncomment the Groq settings, and set your key in `GROQ_API_KEY`. Alternatively, uncomment the Gemini settings and set `GEMINI_API_KEY`. The `npm run dev` and `npm start` commands load the root `.env` file. Keep provider keys server-side; never put them in frontend code or a `VITE_` variable.

Groq settings:

```text
SCAMSHIELD_AI_PROVIDER=groq
GROQ_API_KEY=<your server-side API key>
GROQ_MODEL=openai/gpt-oss-20b
GROQ_VISION_MODEL=qwen/qwen3.8-27b
```

Gemini settings:

```text
SCAMSHIELD_AI_PROVIDER=gemini
GEMINI_API_KEY=<your server-side API key>
GEMINI_MODEL=gemini-3.8-flash
```

When Groq is configured, each analysis is sent to Groq. Groq says inference inputs and outputs are not retained by default, though it may temporarily retain them for reliability or abuse investigations. The interface discloses the provider and links to [Groq data handling](https://console.groq.com/docs/your-data). Gemini analyses are sent to Google; the interface links to [Gemini API data handling](https://ai.google.dev/gemini-api/docs/zdr). If no AI provider is configured, only the rules-based scan is available.

Media review supports JPEG, PNG, WebP, GIF, MP4, WebM, MP3, M4A, WAV, OGG, and FLAC uploads up to 20 MB. Groq Vision reviews images and up to three browser-sampled video frames for visible text, claims, safety concerns, and tentative AI-generation clues, with explicit checks for anatomy, text, spatial geometry, lighting/reflections, and textures. Video and audio files are sent to Groq Whisper for transcription; audio transcript text is checked for scam-language patterns. The service does not detect AI-generated voices or verify audio authenticity, and sampled video frames cannot validate lip sync or motion continuity. The upload is processed in memory and is not saved by this service. Media review requires `GROQ_API_KEY` even when message analysis uses rules or Gemini; `GROQ_VISION_MODEL` defaults to `qwen/qwen3.8-27b`. Appearance-based origin estimates are not forensic detection and cannot establish authenticity. The interface discloses media processing and links to Groq data handling before upload.

## Run in a container

Build and run the single-container app:

```sh
docker build -t scamshield .
docker run --rm -p 8787:8787 scamshield
```

The container runs as the unprivileged `node` user and serves both the built frontend and API. Put it behind a TLS-enabled managed ingress in production. Configure `ALLOWED_ORIGINS` for any separate frontend origins. Environment settings are documented in `.env.example`.

## Deploy a public demo on Render

The included `render.yaml` configures a free Docker web service in Singapore, uses `/api/health` for health checks, and enables Groq analysis when `GROQ_API_KEY` is set. To deploy it:

1. Push this project to a GitHub or GitLab repository you control.
2. In Render, choose **New → Blueprint**, connect that repository, and apply the `render.yaml` configuration.
3. Add your Groq key as `GROQ_API_KEY` and, if you want the separate URL tool, your VirusTotal key as `VIRUSTOTAL_API_KEY` in the service's Environment settings; then save and redeploy.
4. Open the generated `onrender.com` URL and try a built-in example.
5. Copy the working URL into the hackathon submission.

Render's free web services sleep after 15 minutes without traffic and can take about a minute to wake up. Open the demo shortly before presenting it. See [Render's free instance limits](https://render.com/docs/free).

## Current detection scope

The shared rule engine is in `shared/detector.js`. It checks for credential requests, pressure tactics, payment fees, fake KYC, UPI collect/PIN-to-receive language, job-fee lures, remote-access requests, prize lures, and a small set of suspicious URL traits inside the message text. VirusTotal separately checks URLs found in the message when configured, and the URL tab accepts a standalone link. Groq or Gemini can analyze pasted conversation transcripts for a supported social-engineering sequence and quotes matching evidence. High-risk results include account or India-specific financial-fraud response guidance, and users can copy an assessment to share with a trusted contact. Scores and model risk labels are indicators, not proof or probabilities. A low result does not prove a message is safe.

## Production work still required

This is a deployable prototype, not yet an enterprise service. Before serving real users at scale, replace the per-process rate limiter with a shared gateway or store, add operational monitoring and alerting, define retention and incident-response policies, conduct a privacy/security review, and validate detection quality against a consented and labeled corpus. Any external URL reputation provider must be integrated server-side with timeouts, caching, data-minimization controls, and clear disclosure to users. Do not claim detection accuracy or impact until it has been measured.
