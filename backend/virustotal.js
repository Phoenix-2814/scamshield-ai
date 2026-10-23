import { extractUrls } from '../shared/detector.js'

const maxUrlsPerMessage = 3
const cacheTtlMs = 15 * 60 * 1000
const cache = new Map()
const requestTimes = []
const requestsPerMinute = Number.parseInt(process.env.VIRUSTOTAL_REQUESTS_PER_MINUTE || '4', 10)

export async function checkMessageUrls(message, apiKey, { timeoutMs = 8000 } = {}) {
  const urls = extractUrls(message)
  if (!urls.length) return null
  if (!apiKey) return {
    configured: false,
    results: urls.slice(0, maxUrlsPerMessage).map((url) => ({ url: safeDisplayUrl(url), status: 'not_configured' })),
    skipped: Math.max(0, urls.length - maxUrlsPerMessage)
  }

  const selected = urls.slice(0, maxUrlsPerMessage)
  const results = []
  let scanSubmitted = false
  for (const url of selected) {
    const checked = await checkUrl(url, apiKey, timeoutMs, !scanSubmitted)
    results.push(checked.result)
    if (checked.submitted || checked.result.status === 'pending') scanSubmitted = true
  }
  return { configured: true, results, skipped: Math.max(0, urls.length - selected.length) }
}

export async function checkSingleUrl(input, apiKey, { timeoutMs = 8000 } = {}) {
  if (typeof input !== 'string' || input.length > 2048) {
    const error = new Error('Enter a valid web URL (up to 2,048 characters).')
    error.status = 400
    throw error
  }
  let parsed
  try {
    parsed = new URL(input.trim())
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) throw new Error('invalid')
  } catch {
    const error = new Error('Enter a complete http:// or https:// URL.')
    error.status = 400
    throw error
  }
  const url = parsed.href
  if (!apiKey) return { configured: false, results: [{ url: safeDisplayUrl(url), status: 'not_configured' }] }
  const checked = await checkUrl(url, apiKey, timeoutMs, true)
  return { configured: true, results: [checked.result] }
}

async function checkUrl(url, apiKey, timeoutMs, allowSubmit) {
  const cached = cache.get(url)
  if (cached && cached.expiresAt > Date.now()) return { result: cached.result, submitted: false }

  let checked
  try {
    checked = cached?.analysisId
      ? await readAnalysis(url, cached.analysisId, apiKey, timeoutMs)
      : await lookupOrSubmit(url, apiKey, timeoutMs, allowSubmit)
  } catch (error) {
    checked = { result: { url: safeDisplayUrl(url), status: 'unavailable', message: error.message } }
  }

  const result = checked.result
  cache.set(url, {
    result,
    analysisId: checked.analysisId,
    expiresAt: Date.now() + (result.status === 'pending' ? 30_000 : result.status === 'unavailable' ? 15_000 : cacheTtlMs)
  })
  return { result, submitted: checked.submitted === true }
}

async function lookupOrSubmit(url, apiKey, timeoutMs, allowSubmit) {
  const id = Buffer.from(url).toString('base64url')
  const headers = { 'x-apikey': apiKey, Accept: 'application/json' }
  const reportResponse = await fetchVirusTotal(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers,
    signal: AbortSignal.timeout(timeoutMs)
  })

  if (reportResponse.ok) {
    const report = await reportResponse.json()
    return { result: makeResult(url, report.data?.attributes?.last_analysis_stats, report.data?.id) }
  }
  if (reportResponse.status !== 404) throw apiError(reportResponse.status)
  if (!allowSubmit) return { result: { url: safeDisplayUrl(url), status: 'not_submitted' } }

  const scanResponse = await fetchVirusTotal('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }),
    signal: AbortSignal.timeout(timeoutMs)
  })
  if (!scanResponse.ok) throw apiError(scanResponse.status)
  const scan = await scanResponse.json()
  const analysisId = scan.data?.id
  return {
    result: { url: safeDisplayUrl(url), status: 'pending', detections: null, total: null },
    analysisId,
    submitted: true
  }
}

async function readAnalysis(url, analysisId, apiKey, timeoutMs) {
  const analysisResponse = await fetchVirusTotal(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, {
    headers: { 'x-apikey': apiKey, Accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs)
  })
  if (!analysisResponse.ok) {
    if (analysisResponse.status === 429) return { result: { url: safeDisplayUrl(url), status: 'pending', detections: null, total: null }, analysisId }
    throw apiError(analysisResponse.status)
  }
  const analysis = await analysisResponse.json()
  const attributes = analysis.data?.attributes
  if (attributes?.status !== 'completed' || !attributes?.stats) {
    return { result: { url: safeDisplayUrl(url), status: 'pending', detections: null, total: null }, analysisId }
  }
  return { result: makeResult(url, attributes.stats) }
}

function makeResult(url, stats, id) {
  if (!stats || typeof stats !== 'object') {
    return { url: safeDisplayUrl(url), status: 'pending', detections: null, total: null }
  }
  const malicious = finiteCount(stats.malicious)
  const suspicious = finiteCount(stats.suspicious)
  const harmless = finiteCount(stats.harmless)
  const undetected = finiteCount(stats.undetected)
  const total = malicious + suspicious + harmless + undetected
  const status = malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : total > 0 ? 'no_detections' : 'unrated'
  return {
    url: safeDisplayUrl(url),
    status,
    detections: malicious + suspicious,
    malicious,
    suspicious,
    harmless,
    undetected,
    total,
    reportUrl: id ? `https://www.virustotal.com/gui/url/${encodeURIComponent(id)}` : undefined
  }
}

function finiteCount(value) {
  return Number.isInteger(value) && value > 0 ? value : 0
}

function safeDisplayUrl(value) {
  try {
    const parsed = new URL(value)
    return `${parsed.origin}${parsed.pathname}`.slice(0, 300)
  } catch {
    return value.slice(0, 300)
  }
}

function apiError(status) {
  const messages = {
    401: 'VirusTotal rejected the API key. Check VIRUSTOTAL_API_KEY.',
    403: 'VirusTotal denied this API key or endpoint. Check your API access.',
    429: 'VirusTotal rate limit reached. Try again later.',
    500: 'VirusTotal is temporarily unavailable.',
    502: 'VirusTotal is temporarily unavailable.',
    503: 'VirusTotal is temporarily unavailable.'
  }
  const error = new Error(messages[status] || `VirusTotal returned HTTP ${status}.`)
  error.providerStatus = status
  throw error
}

async function fetchVirusTotal(url, options) {
  const now = Date.now()
  while (requestTimes.length && now - requestTimes[0] >= 60_000) requestTimes.shift()
  if (!Number.isInteger(requestsPerMinute) || requestsPerMinute < 1 || requestTimes.length >= requestsPerMinute) {
    const error = new Error('VirusTotal request limit reached. Try again in about a minute.')
    error.providerStatus = 429
    throw error
  }
  requestTimes.push(now)
  return fetch(url, options)
}
