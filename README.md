# ScamShield

ScamShield is a scam-safety product prototype focused on analyzing intent and explaining warning signs across suspicious messages and conversation transcripts. The web app submits content to a same-origin Node API. Rules-based analysis is available by default; when the operator configures Gemini, semantic analysis runs automatically.

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

Requests must be JSON. Messages are limited to 5,000 characters. The API enforces a request body limit, applies a small per-process rate limit, sends browser security headers, and does not log message contents. The rate limiter is an in-memory prototype guard; it resets at restart and is not suitable across multiple replicas.

## Optional semantic analysis

Rules-based analysis works without external AI. To enable the semantic mode, configure these variables in the **server** environment before starting the app:

```text
SCAMSHIELD_AI_PROVIDER=gemini
GEMINI_API_KEY=<your server-side API key>
GEMINI_MODEL=gemini-3.8-flash
```

Never put the API key in frontend code or a `VITE_` variable. When Gemini is configured, each analysis is sent to Google Gemini. The interface discloses this and provides a link to [Gemini API data handling](https://ai.google.dev/gemini-api/docs/zdr). ScamShield sends `store: false` to opt out of saved interaction state; Google's abuse monitoring and other data policies still apply. If you do not configure the provider, only the rules-based scan is available.

## Run in a container

Build and run the single-container app:

```sh
docker build -t scamshield .
docker run --rm -p 8787:8787 scamshield
```

The container runs as the unprivileged `node` user and serves both the built frontend and API. Put it behind a TLS-enabled managed ingress in production. Configure `ALLOWED_ORIGINS` for any separate frontend origins. Environment settings are documented in `.env.example`.

## Deploy a public demo on Render

The included `render.yaml` configures a free Docker web service in Singapore, uses `/api/health` for health checks, and keeps analysis rules-based by default. To deploy it:

1. Push this project to a GitHub or GitLab repository you control.
2. In Render, choose **New → Blueprint**, connect that repository, and apply the `render.yaml` configuration.
3. Wait for the first deploy, then open the generated `onrender.com` URL and try a built-in example.
4. Copy the working URL into the hackathon submission.

Render's free web services sleep after 15 minutes without traffic and can take about a minute to wake up. Open the demo shortly before presenting it. See [Render's free instance limits](https://render.com/docs/free).

## Current detection scope

The shared rule engine is in `shared/detector.js`. It checks for credential requests, pressure tactics, payment fees, fake KYC, UPI collect/PIN-to-receive language, job-fee lures, remote-access requests, prize lures, and a small set of suspicious URL traits. Gemini can analyze pasted conversation transcripts for a supported social-engineering sequence and quotes matching evidence. High-risk results include account or India-specific financial-fraud response guidance, and users can copy an assessment to share with a trusted contact. Neither mode resolves redirects, queries live threat feeds, or validates senders. Scores and model risk labels are indicators, not proof or probabilities. A low result does not prove a message is safe.

## Production work still required

This is a deployable prototype, not yet an enterprise service. Before serving real users at scale, replace the per-process rate limiter with a shared gateway or store, add operational monitoring and alerting, define retention and incident-response policies, conduct a privacy/security review, and validate detection quality against a consented and labeled corpus. Any external URL reputation provider must be integrated server-side with timeouts, caching, data-minimization controls, and clear disclosure to users. Do not claim detection accuracy or impact until it has been measured.
