export async function getAnalyzerConfig() {
  const response = await fetch('/api/config', { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(5000) })
  if (!response.ok) throw new Error('Could not load analysis settings.')
  return response.json()
}

export async function analyzeMessageRequest(message, useAiAnalysis = false) {
  let response
  try {
    response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ message, useAiAnalysis }),
      signal: AbortSignal.timeout(65000)
    })
  } catch {
    throw new Error('ScamShield could not reach its analysis service. Check your connection and try again.')
  }

  const payload = await response.json().catch(() => null)
  if (!response.ok) {
    throw new Error(payload?.error?.message ?? 'The analysis service could not complete this request.')
  }
  if (!payload?.analysis || !Array.isArray(payload.analysis.signals)) {
    throw new Error('The analysis service returned an unexpected response.')
  }
  return payload.analysis
}
