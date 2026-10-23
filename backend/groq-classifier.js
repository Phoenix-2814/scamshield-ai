import { responseSchema, systemInstructions } from './gemini-classifier.js'

export async function classifyMessageWithGroq(message, { apiKey, model = 'openai/gpt-oss-20b', timeoutMs = 30000 }) {
  let response
  try {
    response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: `${systemInstructions} Return a JSON object matching the supplied schema.` },
          { role: 'user', content: message }
        ],
        max_completion_tokens: 2048,
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'scam_assessment',
            strict: true,
            schema: responseSchema
          }
        }
      }),
      signal: AbortSignal.timeout(timeoutMs)
    })
  } catch (cause) {
    const timedOut = cause?.name === 'TimeoutError' || cause?.name === 'AbortError'
    const error = new Error(timedOut
      ? 'Groq took too long to respond. Please try again.'
      : 'The AI analysis provider could not be reached. Please try again.')
    error.status = 503
    error.providerFailure = timedOut ? 'timeout' : 'network'
    throw error
  }

  if (!response.ok) {
    const providerError = await response.json().catch(() => null)
    const details = providerError?.error ?? {}
    const safeCode = typeof details.code === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(details.code)
      ? details.code
      : undefined
    const safeDetail = typeof details.message === 'string'
      ? details.message.replace(/[\r\n\u0000-\u001F]/g, ' ').replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').replace(/gsk_[a-zA-Z0-9_-]+/gi, '[redacted key]').slice(0, 240)
      : undefined
    const messages = {
      400: 'Groq rejected the request. Check GROQ_MODEL and structured output support.',
      401: 'Groq rejected the API key. Check that GROQ_API_KEY is valid.',
      402: 'The Groq API account needs available credits or billing.',
      403: 'Groq denied access to this API key or model. Check the key and model access.',
      404: 'Groq could not find the configured model or API resource. Check GROQ_MODEL and model access.',
      429: 'The Groq API rate limit or quota was reached. Wait before retrying.',
      500: 'Groq is temporarily unavailable. Please retry later.',
      502: 'Groq is temporarily unavailable. Please retry later.',
      503: 'Groq is temporarily unavailable. Please retry later.'
    }
    const error = new Error(response.status === 400 && safeDetail
      ? `Groq rejected the request: ${safeDetail}`
      : messages[response.status] || `Groq returned HTTP ${response.status}. Check the server log for its error code.`)
    error.status = 503
    error.providerStatus = response.status
    error.providerCode = safeCode
    throw error
  }

  let payload
  try {
    payload = await response.json()
  } catch {
    const error = new Error('The AI analysis provider returned an invalid response.')
    error.status = 503
    throw error
  }
  const text = payload.choices?.[0]?.message?.content
  if (!text) {
    const error = new Error('The AI analysis provider returned no result. Please try again.')
    error.status = 503
    throw error
  }

  let result
  try {
    result = JSON.parse(text)
  } catch {
    const error = new Error('The AI analysis provider returned an invalid result. Please try again.')
    error.status = 503
    throw error
  }
  if (!['High', 'Medium', 'Low'].includes(result.risk_level) || !Array.isArray(result.attack_chain) || !Array.isArray(result.signals) || !Array.isArray(result.recommended_actions)) {
    const error = new Error('The AI analysis provider returned an unsupported result. Please try again.')
    error.status = 503
    throw error
  }

  return {
    riskLevel: result.risk_level,
    scamType: String(result.scam_type || 'Unclear').slice(0, 80),
    summary: String(result.summary || '').slice(0, 500),
    attackChain: result.attack_chain.slice(0, 4).map((step) => ({
      stage: String(step.stage || 'Context cue').slice(0, 80),
      evidence: typeof step.evidence === 'string' && message.includes(step.evidence) ? step.evidence.slice(0, 240) : '',
      interpretation: String(step.interpretation || '').slice(0, 240)
    })).filter((step) => step.evidence),
    signals: result.signals.slice(0, 6).map((signal) => ({
      name: String(signal.name || 'Contextual warning').slice(0, 120),
      evidence: typeof signal.evidence === 'string' && message.includes(signal.evidence) ? signal.evidence.slice(0, 240) : '',
      explanation: String(signal.why_it_matters || '').slice(0, 300)
    })),
    advice: result.recommended_actions.slice(0, 5).map((item) => String(item).slice(0, 300))
  }
}
