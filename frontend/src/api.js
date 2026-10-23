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

export async function analyzeMediaRequest(file, frames, duration = null) {
  const form = new FormData()
  form.append('file', file)
  form.append('frames', JSON.stringify(frames))
  if (Number.isFinite(duration)) form.append('duration', String(duration))
  let response
  try {
    response = await fetch('/api/analyze-media', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      body: form,
      signal: AbortSignal.timeout(90000)
    })
  } catch {
    throw new Error('ScamShield could not reach its media analysis service. Check your connection and try again.')
  }
  const payload = await response.json().catch(() => null)
  if (!response.ok) throw new Error(payload?.error?.message ?? 'The media analysis service could not complete this request.')
  if (!payload?.mediaAnalysis || !Array.isArray(payload.mediaAnalysis.visibleText)) {
    throw new Error('The media analysis service returned an unexpected response.')
  }
  return payload.mediaAnalysis
}

export async function checkUrlRequest(url) {
  let response
  try {
    response = await fetch('/api/check-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(15000)
    })
  } catch {
    throw new Error('ScamShield could not reach its URL analysis service. Check your connection and try again.')
  }
  const payload = await response.json().catch(() => null)
  if (!response.ok) throw new Error(payload?.error?.message ?? 'The URL analysis service could not complete this request.')
  if (!payload?.urlChecks || !Array.isArray(payload.urlChecks.results)) {
    throw new Error('The URL analysis service returned an unexpected response.')
  }
  return payload.urlChecks
}
