import { responseSchema, systemInstructions } from './gemini-classifier.js'

export async function classifyMessageWithGrok(message, { apiKey, model = 'grok-4.7', timeoutMs = 30000 }) {
  let response
  try {
    response = await fetch('https://api.x.ai/v1/responses', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model,
        input: [
          { role: 'system', content: systemInstructions },
          { role: 'user', content: message }
        ],
        store: false,
        max_output_tokens: 2048,
        text: {
          format: {
            type: 'json_schema',
            name: 'scam_assessment',
            schema: responseSchema,
            strict: true
          }
        }
      }),
      signal: AbortSignal.timeout(timeoutMs)
    })
  } catch (cause) {
    const timedOut = cause?.name === 'TimeoutError' || cause?.name === 'AbortError'
    const error = new Error(timedOut
      ? 'Grok took too long to respond. Please try again.'
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
    const messages = {
      400: 'Grok rejected the request. Check GROK_MODEL and structured output support.',
      401: 'Grok rejected the API key. Check that XAI_API_KEY is valid.',
      402: 'The xAI API account needs available credits or billing.',
      403: 'Grok denied access to this API key or model. Check the key permissions and model access.',
      404: 'Grok could not find the configured model or API resource. Check GROK_MODEL and model access.',
      429: 'The xAI API rate limit or quota was reached. Wait before retrying.',
      500: 'Grok is temporarily unavailable. Please retry later.',
      502: 'Grok is temporarily unavailable. Please retry later.',
      503: 'Grok is temporarily unavailable. Please retry later.'
    }
    const error = new Error(messages[response.status] || `Grok returned HTTP ${response.status}. Check the server log for its error code.`)
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
  if (payload.status && payload.status !== 'completed') {
    const error = new Error('The AI analysis did not complete. Please try again.')
    error.status = 503
    error.providerFailure = `status=${String(payload.status).slice(0, 40)}`
    throw error
  }

  const text = payload.output
    ?.filter((item) => item.type === 'message')
    .flatMap((item) => item.content ?? [])
    .find((item) => item.type === 'output_text')?.text
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
