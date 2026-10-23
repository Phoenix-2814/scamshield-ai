const endpointByKind = {
  image: ['https://api.sightengine.com/1.0/check.json', 'media', 'genai'],
  video: ['https://api.sightengine.com/1.0/video/check-sync.json', 'media', 'genai'],
  audio: ['https://api.sightengine.com/1.0/audio/check.json', 'audio', 'ai_speech']
}

export function sightengineConfigured(env = process.env) {
  return Boolean(env.SIGHTENGINE_API_USER && env.SIGHTENGINE_API_SECRET)
}

export async function detectSyntheticMedia({ bytes, mimeType, fileName, mediaType, duration, env = process.env }) {
  if (!sightengineConfigured(env)) return { status: 'not_configured', score: null, label: null }
  if (mediaType === 'video' && Number.isFinite(Number(duration)) && Number(duration) >= 60) {
    return { status: 'duration_limit', score: null, label: null }
  }
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
    return { status: providerFailureStatus(response.status, payload?.error?.type), score: null, label: null }
  }
  const frameScores = mediaType === 'video' ? getVideoFrameScores(payload) : []
  const scoreValue = mediaType === 'audio'
    ? payload?.type?.ai_speech
    : mediaType === 'video' && frameScores.length
      ? frameScores.reduce((sum, item) => sum + item.score, 0) / frameScores.length
      : payload?.type?.ai_generated
  const score = Number(scoreValue)
  if (!Number.isFinite(score) || score < 0 || score > 1) return { status: 'unavailable', score: null, label: null }
  return {
    status: 'completed',
    score,
    label: score >= 0.8 ? 'likely_ai_generated' : score <= 0.2 ? 'no_strong_ai_signal' : 'inconclusive',
    model: mediaType === 'audio' ? 'Sightengine AI speech detection' : `Sightengine AI ${mediaType} detection`,
    ...(frameScores.length ? { frameScores } : {})
  }
}

function getVideoFrameScores(payload) {
  return (Array.isArray(payload?.data?.frames) ? payload.data.frames : [])
    .map((frame) => ({
      position: Number.isFinite(Number(frame?.info?.position)) ? Number(frame.info.position) : null,
      score: Number(frame?.type?.ai_generated)
    }))
    .filter(({ score }) => Number.isFinite(score) && score >= 0 && score <= 1)
}

function safeFileName(fileName, mediaType) {
  const ext = String(fileName || '').match(/\.[a-z0-9]{1,8}$/i)?.[0] || (mediaType === 'video' ? '.mp4' : mediaType === 'audio' ? '.mp3' : '.jpg')
  return `upload${ext.toLowerCase()}`
}

function providerFailureStatus(httpStatus, errorType) {
  if ([401, 403].includes(httpStatus) || errorType === 'credentials_error') return 'credentials_rejected'
  if (httpStatus === 402 || errorType === 'plan_error') return 'payment_required'
  if (httpStatus === 429 || errorType === 'usage_limit') return 'quota_reached'
  if (errorType === 'media_error') return 'unsupported_media'
  if (errorType === 'argument_error') return 'invalid_request'
  return 'unavailable'
}
