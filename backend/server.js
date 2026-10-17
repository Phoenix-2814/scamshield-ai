import { createServer } from 'node:http'
import { stat } from 'node:fs/promises'
import { createReadStream } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { analyzeMessage } from '../shared/detector.js'
import { classifyMessageWithGemini } from './gemini-classifier.js'

const projectRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
const staticRoot = resolve(projectRoot, 'frontend', 'dist')
const isProduction = process.env.NODE_ENV === 'production'
const aiProvider = process.env.SCAMSHIELD_AI_PROVIDER || 'rules'
if (!['rules', 'gemini'].includes(aiProvider)) throw new Error('SCAMSHIELD_AI_PROVIDER must be rules or gemini.')
if (aiProvider === 'gemini' && !process.env.GEMINI_API_KEY) throw new Error('SCAMSHIELD_AI_PROVIDER=gemini requires GEMINI_API_KEY.')
const geminiModel = process.env.GEMINI_MODEL || 'gemini-3.8-flash'
const port = readInteger(process.env.PORT, 8787, 1, 65535)
const host = process.env.HOST || '127.0.0.1'
const maxBodyBytes = readInteger(process.env.MAX_BODY_BYTES, 24000, 1024, 65536)
const rateWindowMs = readInteger(process.env.RATE_LIMIT_WINDOW_MS, 60000, 1000, 3600000)
const rateLimit = readInteger(process.env.RATE_LIMIT_MAX, 30, 1, 10000)
const allowedOrigins = new Set((process.env.ALLOWED_ORIGINS || (isProduction ? '' : 'http://localhost:5173,http://127.0.0.1:5173'))
  .split(',').map((origin) => origin.trim()).filter(Boolean))
const rateBuckets = new Map()
const mimeTypes = new Map([
  ['.html', 'text/html; charset=utf-8'], ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'], ['.svg', 'image/svg+xml'], ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'], ['.jpeg', 'image/jpeg'], ['.webp', 'image/webp'],
  ['.ico', 'image/x-icon'], ['.woff2', 'font/woff2'], ['.json', 'application/json; charset=utf-8']
])

function readInteger(value, fallback, min, max) {
  if (value === undefined || value === '') return fallback
  const parsed = Number(value)
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`Invalid configuration value: expected an integer from ${min} to ${max}.`)
  }
  return parsed
}

function writeJson(response, status, body, extraHeaders = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  })
  response.end(JSON.stringify(body))
}

function addSecurityHeaders(response) {
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.setHeader('Referrer-Policy', 'no-referrer')
  response.setHeader('X-Frame-Options', 'DENY')
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin')
  response.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
}

function originAllowed(request) {
  const origin = request.headers.origin
  if (!origin) return true
  if (allowedOrigins.has(origin)) return true
  try {
    return new URL(origin).host === request.headers.host
  } catch {
    return false
  }
}

function allowCors(request, response) {
  response.setHeader('Vary', 'Origin')
  if (request.headers.origin) {
    response.setHeader('Access-Control-Allow-Origin', request.headers.origin)
    response.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Request-ID')
    response.setHeader('Access-Control-Max-Age', '600')
  }
}

function consumeRateLimit(request) {
  const now = Date.now()
  const key = request.socket.remoteAddress || 'unknown'
  let bucket = rateBuckets.get(key)
  if (!bucket || bucket.resetAt <= now) bucket = { count: 0, resetAt: now + rateWindowMs }
  bucket.count += 1
  rateBuckets.set(key, bucket)
  if (rateBuckets.size > 5000) {
    for (const [address, entry] of rateBuckets) if (entry.resetAt <= now) rateBuckets.delete(address)
    if (rateBuckets.size > 5000) rateBuckets.clear()
  }
  return { allowed: bucket.count <= rateLimit, remaining: Math.max(0, rateLimit - bucket.count), resetAt: bucket.resetAt }
}

async function readJson(request) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.length
    if (size > maxBodyBytes) {
      request.resume()
      const error = new Error('Request body is too large.')
      error.status = 413
      throw error
    }
    chunks.push(chunk)
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    const error = new Error('Request body must be valid JSON.')
    error.status = 400
    throw error
  }
}

async function serveStatic(pathname, request, response) {
  let requestedPath
  try {
    requestedPath = pathname === '/' ? '/index.html' : decodeURIComponent(pathname)
  } catch {
    writeJson(response, 400, { error: { code: 'INVALID_PATH', message: 'Invalid path.' } })
    return
  }
  const filePath = resolve(staticRoot, `.${requestedPath}`)
  if (filePath !== staticRoot && !filePath.startsWith(`${staticRoot}${sep}`)) {
    writeJson(response, 400, { error: { code: 'INVALID_PATH', message: 'Invalid path.' } })
    return
  }
  try {
    const fileInfo = await stat(filePath)
    if (!fileInfo.isFile()) throw new Error('not a file')
    response.writeHead(200, {
      'Content-Type': mimeTypes.get(extname(filePath).toLowerCase()) || 'application/octet-stream',
      'Content-Length': fileInfo.size,
      'Cache-Control': filePath.endsWith('index.html') ? 'no-cache' : filePath.includes(`${sep}assets${sep}`) ? 'public, max-age=31536000, immutable' : 'public, max-age=300'
    })
    if (request.method === 'HEAD') response.end()
    else createReadStream(filePath).pipe(response)
  } catch {
    const accept = request.headers.accept || ''
    if (accept.includes('text/html')) return serveStatic('/index.html', request, response)
    writeJson(response, 404, { error: { code: 'NOT_FOUND', message: 'Not found.' } })
  }
}

const server = createServer(async (request, response) => {
  const requestId = randomUUID()
  response.setHeader('X-Request-ID', requestId)
  addSecurityHeaders(response)

  let pathname
  try {
    pathname = new URL(request.url, 'http://localhost').pathname
  } catch {
    writeJson(response, 400, { error: { code: 'INVALID_URL', message: 'Invalid request URL.', requestId } })
    return
  }

  if (pathname.startsWith('/api/')) {
    if (!originAllowed(request)) {
      writeJson(response, 403, { error: { code: 'ORIGIN_DENIED', message: 'This origin is not allowed.', requestId } })
      return
    }
    allowCors(request, response)
    if (request.method === 'OPTIONS') {
      response.writeHead(204)
      response.end()
      return
    }

    if (pathname === '/api/health' && request.method === 'GET') {
      writeJson(response, 200, { status: 'ok', service: 'scamshield-api', requestId })
      return
    }
    if (pathname === '/api/config' && request.method === 'GET') {
      writeJson(response, 200, {
        analysisModes: aiProvider === 'gemini' ? ['rules', 'ai-assisted'] : ['rules'],
        aiAssistedAvailable: aiProvider === 'gemini',
        externalProvider: aiProvider === 'gemini' ? 'Gemini' : null,
        requestId
      })
      return
    }
    if (pathname === '/api/analyze' && request.method === 'POST') {
      const limit = consumeRateLimit(request)
      response.setHeader('RateLimit-Limit', String(rateLimit))
      response.setHeader('RateLimit-Remaining', String(limit.remaining))
      response.setHeader('RateLimit-Reset', String(Math.ceil(limit.resetAt / 1000)))
      if (!limit.allowed) {
        request.resume()
        writeJson(response, 429, { error: { code: 'RATE_LIMITED', message: 'Too many checks. Wait a moment and try again.', requestId } }, { 'Retry-After': String(Math.ceil((limit.resetAt - Date.now()) / 1000)) })
        return
      }
      if (!String(request.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
        request.resume()
        writeJson(response, 415, { error: { code: 'UNSUPPORTED_MEDIA_TYPE', message: 'Send the request as JSON.', requestId } })
        return
      }
      try {
        const body = await readJson(request)
        if (body && typeof body === 'object' && Object.keys(body).some((key) => !['message', 'useAiAnalysis'].includes(key))) {
          writeJson(response, 400, { error: { code: 'INVALID_INPUT', message: 'The request contains an unsupported field.', requestId } })
          return
        }
        if (typeof body?.message !== 'string') {
          writeJson(response, 400, { error: { code: 'INVALID_INPUT', message: 'Message must be text.', requestId } })
          return
        }
        const message = body.message.normalize('NFC').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim()
        if (!message) {
          writeJson(response, 400, { error: { code: 'EMPTY_MESSAGE', message: 'Please enter a message to analyze.', requestId } })
          return
        }
        if (message.length > 5000) {
          writeJson(response, 413, { error: { code: 'MESSAGE_TOO_LONG', message: 'Messages must be 5,000 characters or fewer.', requestId } })
          return
        }
        if (body.useAiAnalysis !== undefined && typeof body.useAiAnalysis !== 'boolean') {
          writeJson(response, 400, { error: { code: 'INVALID_INPUT', message: 'useAiAnalysis must be a boolean.', requestId } })
          return
        }
        let analysis = { ...analyzeMessage(message), mode: 'rules' }
        if (body.useAiAnalysis === true) {
          if (aiProvider !== 'gemini') {
            writeJson(response, 503, { error: { code: 'AI_NOT_CONFIGURED', message: 'AI-assisted analysis is not configured on this service.', requestId } })
            return
          }
          const assessment = await classifyMessageWithGemini(message, { apiKey: process.env.GEMINI_API_KEY, model: geminiModel })
          const aiSignals = assessment.signals.map((signal) => ({
            name: signal.name,
            category: assessment.scamType,
            points: 0,
            evidence: signal.evidence,
            explanation: signal.explanation,
            advice: ''
          }))
          const combinedSignals = [...aiSignals, ...analysis.signals]
          const seenSignals = new Set()
          analysis = {
            ...analysis,
            mode: 'ai-assisted',
            level: assessment.riskLevel,
            categories: [...new Set([assessment.scamType, ...analysis.categories])],
            assessment: { scamType: assessment.scamType, summary: assessment.summary, attackChain: assessment.attackChain },
            signals: combinedSignals.filter((signal) => {
              const key = `${signal.name}:${signal.evidence}`
              if (seenSignals.has(key)) return false
              seenSignals.add(key)
              return true
            }),
            advice: [...new Set([...assessment.advice, ...analysis.advice])]
          }
        }
        writeJson(response, 200, { requestId, analysis })
      } catch (error) {
        const code = error.status === 413 ? 'BODY_TOO_LARGE' : error.status === 503 ? 'AI_PROVIDER_ERROR' : 'INVALID_JSON'
        if (error.providerStatus) {
          console.error(`[${requestId}] Gemini request failed: HTTP ${error.providerStatus}${error.providerCode ? ` code=${error.providerCode}` : ''}`)
        }
        writeJson(response, error.status || 400, { error: { code, message: error.message, requestId } })
      }
      return
    }
    writeJson(response, 404, { error: { code: 'NOT_FOUND', message: 'API route not found.', requestId } })
    return
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    writeJson(response, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.', requestId } }, { Allow: 'GET, HEAD' })
    return
  }
  await serveStatic(pathname, request, response)
})

server.listen(port, host, () => {
  console.log(`ScamShield API listening on http://${host}:${port}`)
})

function shutdown(signal) {
  console.log(`${signal}: closing ScamShield API`)
  server.close(() => process.exit(0))
  setTimeout(() => process.exit(1), 10000).unref()
}
process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
