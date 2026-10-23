const endpointByKind = {
  image: ['https://api.sightengine.com/1.0/check.json', 'media', 'genai'],
  video: ['https://api.sightengine.com/1.0/video/check-sync.json', 'media', 'genai'],
  audio: ['https://api.sightengine.com/1.0/audio/check.json', 'audio', 'ai_speech']
}

export function sightengineConfigured(env = process.env) {
  return Boolean(env.SIGHTENGINE_API_USER && env.SIGHTENGINE_API_SECRET)
}

export async function detectSyntheticMedia({ bytes, mimeType, fileName, mediaType, env = process.env }) {
  if (!sightengineConfigured(env)) return { status: 'not_configured', score: null, label: null }
  const [endpoint, fileField, model] = endpointByKind[mediaType] || []
  if (!endpoint) return { status: 'not_supported', score: null, label: null }

  const form = new FormData()
  form.append(fileField, new Blob([bytes], { type: mimeType }), safeFileName(fileName, mediaType))
  form.append('models', model)
  form.append('api_user', env.SIGHTENGINE_API_USER)
  form.append('api_secret', env.SIGHTENGINE_API_SECRET)

  let response
  try {
    response = await fetch(endpoint, { method: 'POST', body: form, signal: AbortSignal.timeout(mediaType === 'video' ? 75000 : 30000) })
  } catch {
    return { status: 'unavailable', score: null, label: null }
  }
  const payload = await response.json().catch(() => null)
  if (!response.ok || payload?.status !== 'success') {
    return { status: 'unavailable', score: null, label: null }
  }
  const scoreValue = mediaType === 'audio' ? payload?.type?.ai_speech : payload?.type?.ai_generated
  const score = Number(scoreValue)
  if (!Number.isFinite(score) || score < 0 || score > 1) return { status: 'unavailable', score: null, label: null }
  return {
    status: 'completed',
    score,
    label: score >= 0.8 ? 'likely_ai_generated' : score <= 0.2 ? 'no_strong_ai_signal' : 'inconclusive',
    model: mediaType === 'audio' ? 'Sightengine AI speech detection' : `Sightengine AI ${mediaType} detection`
  }
}

function safeFileName(fileName, mediaType) {
  const ext = String(fileName || '').match(/\.[a-z0-9]{1,8}$/i)?.[0] || (mediaType === 'video' ? '.mp4' : mediaType === 'audio' ? '.mp3' : '.jpg')
  return `upload${ext.toLowerCase()}`
}
