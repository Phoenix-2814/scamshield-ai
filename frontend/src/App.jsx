import { useEffect, useRef, useState } from 'react'
import { analyzeMediaRequest, analyzeMessageRequest, checkUrlRequest, getAnalyzerConfig } from './api'
import './App.css'

const examples = [
  { label: 'Fake bank alert', message: 'URGENT: Your bank account will be blocked. Share your OTP immediately: https://secure-check.example' },
  { label: 'UPI collect trick', message: 'Scan this QR to receive your refund. Approve the UPI collect request and enter your UPI PIN.' },
  { label: 'Family login request', message: 'Hi I am your brother. My phone is switched off can you send me the login details of my account?' },
  { label: 'New number conversation', message: 'Sender: It is your brother. This is my new number; the old phone is being repaired.\nSender: I cannot call right now, but I need a quick favor.\nMe: What do you need?\nSender: Open the bank app and read me the notification that appears. I will explain after.' },
  { label: 'Job fee message', message: 'Work from home! Earn 5000 per day. Pay a small registration fee for the job to start today.' },
  { label: 'Everyday message', message: 'Hi! Are we still meeting at the library at 4 PM?' },
]

const urlCheckLabels = {
  malicious: 'Malicious detections',
  suspicious: 'Suspicious detections',
  no_detections: 'No malicious detections',
  unrated: 'No vendor verdict yet',
  pending: 'Scan pending',
  unavailable: 'Check unavailable',
  not_configured: 'VirusTotal not configured'
}

const mediaOriginLabels = {
  likely_ai_generated: 'Visual evidence suggests possible AI generation',
  no_clear_ai_signs: 'No obvious visual signs · origin unverified',
  unclear: 'Origin unclear · cannot verify from appearance alone'
}

function canvasFrame(source) {
  const width = source.videoWidth || source.naturalWidth
  const height = source.videoHeight || source.naturalHeight
  const scale = Math.min(1, 1280 / Math.max(width, height))
  const canvas = document.createElement('canvas')
  canvas.width = Math.max(1, Math.round(width * scale))
  canvas.height = Math.max(1, Math.round(height * scale))
  const context = canvas.getContext('2d')
  if (!context) throw new Error('This browser could not prepare the media preview.')
  context.drawImage(source, 0, 0, canvas.width, canvas.height)
  return canvas.toDataURL('image/jpeg', 0.82)
}

async function prepareMediaFrames(file) {
  if (file.type.startsWith('audio/')) return []
  const objectUrl = URL.createObjectURL(file)
  try {
    if (file.type.startsWith('image/')) {
      const image = new Image()
      image.src = objectUrl
      await image.decode()
      return [canvasFrame(image)]
    }

    const video = document.createElement('video')
    video.preload = 'metadata'
    video.muted = true
    video.src = objectUrl
    await new Promise((resolve, reject) => {
      video.addEventListener('loadedmetadata', resolve, { once: true })
      video.addEventListener('error', () => reject(new Error('This video could not be opened in your browser.')), { once: true })
    })
    if (!Number.isFinite(video.duration) || video.duration <= 0) throw new Error('This video has no readable frames.')
    const times = [...new Set([video.duration * 0.1, video.duration * 0.5, video.duration * 0.9].map((time) => Math.min(Math.max(0, time), Math.max(0, video.duration - 0.05))))]
    const frames = []
    for (const time of times) {
      await new Promise((resolve, reject) => {
        video.addEventListener('seeked', resolve, { once: true })
        video.addEventListener('error', () => reject(new Error('A video frame could not be read.')), { once: true })
        video.currentTime = time
      })
      frames.push(canvasFrame(video))
    }
    return frames
  } finally {
    URL.revokeObjectURL(objectUrl)
  }
}

function App() {
  const [message, setMessage] = useState('')
  const [result, setResult] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [config, setConfig] = useState(null)
  const [copyState, setCopyState] = useState('')
  const [mediaFile, setMediaFile] = useState(null)
  const [mediaFrames, setMediaFrames] = useState([])
  const [mediaPreviewUrl, setMediaPreviewUrl] = useState('')
  const [mediaResult, setMediaResult] = useState(null)
  const [mediaError, setMediaError] = useState('')
  const [mediaPreparing, setMediaPreparing] = useState(false)
  const [activeTool, setActiveTool] = useState('message')
  const [urlInput, setUrlInput] = useState('')
  const [urlResult, setUrlResult] = useState(null)
  const [urlError, setUrlError] = useState('')
  const [urlChecking, setUrlChecking] = useState(false)
  const configRequest = useRef(null)

  useEffect(() => {
    configRequest.current = getAnalyzerConfig().catch(() => ({ aiAssistedAvailable: false }))
    configRequest.current.then(setConfig)
  }, [])

  useEffect(() => () => {
    if (mediaPreviewUrl) URL.revokeObjectURL(mediaPreviewUrl)
  }, [mediaPreviewUrl])

  async function handleMediaChange(event) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm', 'audio/mpeg', 'audio/mp4', 'audio/wav', 'audio/ogg', 'audio/flac', 'audio/webm']
    if (!allowedTypes.includes(file.type)) {
      setMediaError('Use a JPEG, PNG, WebP, GIF, MP4, or WebM file.')
      setMediaFile(null)
      setMediaFrames([])
      setMediaPreviewUrl('')
      setMediaResult(null)
      return
    }
    if (file.size > 20 * 1024 * 1024) {
      setMediaError('Media files must be 20 MB or smaller.')
      setMediaFile(null)
      setMediaFrames([])
      setMediaPreviewUrl('')
      setMediaResult(null)
      return
    }
    setMediaPreparing(true)
    setMediaError('')
    setMediaResult(null)
    try {
      const frames = await prepareMediaFrames(file)
      setMediaPreviewUrl(URL.createObjectURL(file))
      setMediaFile(file)
      setMediaFrames(frames)
    } catch (error) {
      setMediaFile(null)
      setMediaFrames([])
      setMediaPreviewUrl('')
      setMediaResult(null)
      setMediaError(error.message || 'Could not prepare this media file.')
    } finally {
      setMediaPreparing(false)
    }
  }

  async function handleAnalyzeMedia() {
    if (!mediaFile || (!mediaFrames.length && !mediaFile.type.startsWith('audio/'))) return
    setIsAnalyzing(true)
    setMediaError('')
    setMediaResult(null)
    try {
      const analyzerConfig = config ?? await (configRequest.current ?? getAnalyzerConfig())
      setConfig(analyzerConfig)
      if (!analyzerConfig.mediaAnalysisAvailable) throw new Error('Media analysis is not configured. Add GROQ_API_KEY to the server environment.')
      setMediaResult(await analyzeMediaRequest(mediaFile, mediaFrames))
    } catch (error) {
      setMediaError(error.message)
    } finally {
      setIsAnalyzing(false)
    }
  }

  async function handleCheckUrl(event) {
    event.preventDefault()
    setUrlChecking(true)
    setUrlResult(null)
    setUrlError('')
    try {
      setUrlResult(await checkUrlRequest(urlInput))
    } catch (error) {
      setUrlError(error.message || 'The URL could not be checked.')
    } finally {
      setUrlChecking(false)
    }
  }

  async function handleAnalyze(event) {
    event.preventDefault()
    setIsAnalyzing(true)
    try {
      const analyzerConfig = config ?? await (configRequest.current ?? getAnalyzerConfig())
      setConfig(analyzerConfig)
      setResult(await analyzeMessageRequest(message, analyzerConfig.aiAssistedAvailable === true))
    } catch (error) {
      setResult({ error: error.message })
    } finally {
      setIsAnalyzing(false)
    }
  }

  function handleChange(event) {
    setMessage(event.target.value)
    setResult(null)
  }

  function handleClear() {
    setMessage('')
    setResult(null)
    setMediaFile(null)
    setMediaFrames([])
    setMediaPreviewUrl('')
    setMediaResult(null)
    setMediaError('')
    setUrlInput('')
    setUrlResult(null)
    setUrlError('')
  }

  function loadExample(example) {
    setMessage(example.message)
    setResult(null)
    setMediaFile(null)
    setMediaFrames([])
    setMediaPreviewUrl('')
    setMediaResult(null)
    setMediaError('')
    setUrlInput('')
    setUrlResult(null)
    setUrlError('')
  }

  async function copyAssessment(analysis) {
    const lines = [
      `ScamShield assessment: ${analysis.level} risk`,
      analysis.assessment ? `${analysis.assessment.scamType}: ${analysis.assessment.summary}` : '',
      'Signals:',
      ...analysis.signals.map((signal) => `- ${signal.name}${signal.evidence ? ` | Evidence: ${signal.evidence}` : ''}${signal.explanation ? ` | ${signal.explanation}` : ''}`),
      ...(analysis.urlChecks?.results?.length ? ['VirusTotal URL checks:', ...analysis.urlChecks.results.map((item) => `- ${item.url}: ${urlCheckLabels[item.status] || item.status}${Number.isInteger(item.detections) ? ` (${item.detections}/${item.total} detections)` : ''}`)] : []),
      'Recommended actions:',
      ...analysis.advice.map((item) => `- ${item}`),
      'This is an automated indicator, not proof that a message is fraudulent.'
    ].filter(Boolean)
    try {
      await navigator.clipboard.writeText(lines.join('\n'))
      setCopyState('Copied')
      window.setTimeout(() => setCopyState(''), 2000)
    } catch {
      setCopyState('Copy unavailable')
      window.setTimeout(() => setCopyState(''), 2500)
    }
  }

  return (
    <div className="app" id="top">
      <header className="navbar">
        <a className="brand" href="#top" aria-label="ScamShield home">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>scam<span className="brand-accent">shield</span></span>
        </a>
        <nav className="nav-links" aria-label="Main navigation">
          <a href="#analyzer">Message check</a>
          <a href="#how-it-works">How it works</a>
        </nav>
        <span className="status"><span className="status-dot" /> No message history</span>
      </header>

      <main className="hero page-shell">
        <section className="hero-heading">
          <div className="eyebrow"><span className="eyebrow-dot" /> A CALMER WAY TO CHECK A MESSAGE</div>
          <h1>Pause. Look closer.<br /><span>Then decide.</span></h1>
          <p className="subtitle">Understand what an unexpected message is asking of you, with clear evidence and a safer next step.</p>
        </section>

        <div className="workspace-grid">
          <section className="story-card" aria-label="ScamShield example">
            <div className="story-topline"><span>CONTEXT MATTERS</span><span className="story-live"><span /> A closer look</span></div>
            <h2>A familiar name<br />doesn’t verify a request.</h2>
            <p>Pressure and pretexts can build across an ordinary-looking conversation.</p>
            <div className="message-preview">
              <div className="message-avatar" aria-hidden="true">R</div>
              <div className="message-bubble"><small>NEW NUMBER · 10:42 AM</small><span>Open your bank app and read me the notification?</span></div>
              <div className="message-warning"><span aria-hidden="true">!</span><span><strong>Pause before sharing</strong><small>Verify through a trusted channel.</small></span></div>
            </div>
            <div className="story-steps" id="how-it-works">
              <div><span>01</span><p><strong>Paste the message</strong><small>A single text or full conversation</small></p></div>
              <div><span>02</span><p><strong>Review the evidence</strong><small>See signals in their context</small></p></div>
              <div><span>03</span><p><strong>Choose a safer next step</strong><small>Verify before you act</small></p></div>
            </div>
          </section>

          <section className="analyzer" id="analyzer">
            <div className="analyzer-heading">
              <div><span className="section-kicker">SCAMSHIELD CHECKS</span><h2>Choose what you want to review</h2></div>
              <span className={`mode-pill${config?.aiAssistedAvailable ? ' mode-ai' : ''}`}><span />{config?.aiAssistedAvailable ? `${config.externalProvider} assisted` : 'Rules-based'}</span>
            </div>
            <div className="tool-tabs" role="tablist" aria-label="Choose a review tool">
              <button type="button" id="message-tab" role="tab" aria-controls="message-panel" aria-selected={activeTool === 'message'} className={activeTool === 'message' ? 'active' : ''} onClick={() => setActiveTool('message')}><strong>Message</strong><small>Scam and conversation signals</small></button>
              <button type="button" id="url-tab" role="tab" aria-controls="url-panel" aria-selected={activeTool === 'url'} className={activeTool === 'url' ? 'active' : ''} onClick={() => setActiveTool('url')}><strong>URL</strong><small>VirusTotal reputation check</small></button>
              <button type="button" id="media-tab" role="tab" aria-controls="media-panel" aria-selected={activeTool === 'media'} className={activeTool === 'media' ? 'active' : ''} onClick={() => setActiveTool('media')}><strong>Media</strong><small>Image, video, and audio review</small></button>
            </div>
            {activeTool === 'message' && <form id="message-panel" role="tabpanel" aria-labelledby="message-tab" onSubmit={handleAnalyze}>
              <div className="field-heading">
                <label htmlFor="message">Message or conversation</label>
                <span className="field-hint">Up to 5,000 characters</span>
              </div>
              <textarea
                id="message"
                value={message}
                onChange={handleChange}
                disabled={isAnalyzing}
                placeholder={'Paste the message here. You can include multiple messages to give it context...'}
                rows={7}
                maxLength={5000}
                aria-describedby="privacy-note"
              />
              <div className="form-footer">
                <span className="char-count">{message.length.toLocaleString()} / 5,000</span>
                <div className="actions">
                  <button type="button" className="secondary-button" onClick={handleClear} disabled={isAnalyzing || (!message && !result && !mediaFile && !mediaResult && !mediaError)}>Clear</button>
                  <button type="submit" className="primary-button" disabled={isAnalyzing}>{isAnalyzing ? 'Reviewing…' : <>Review message <span aria-hidden="true">↗</span></>}</button>
                </div>
              </div>
              <p className="privacy" id="privacy-note"><span aria-hidden="true">Privacy</span> {config?.aiAssistedAvailable ? config.externalProvider === 'Groq' ? <>Message sent to ScamShield and Groq. Inputs and outputs are not retained by default, but may be temporarily retained for reliability or abuse investigations. <a href="https://console.groq.com/docs/your-data" target="_blank" rel="noreferrer">See Groq data handling</a>.</> : <>Message sent to ScamShield and Google Gemini. Interaction storage is disabled; Google abuse monitoring still applies. <a href="https://ai.google.dev/gemini-api/docs/zdr" target="_blank" rel="noreferrer">See Gemini data handling</a>.</> : <>Message analyzed by ScamShield rules. Message history is not saved.</>} {config?.virusTotalAvailable ? <>URLs in messages are automatically sent to VirusTotal for reputation lookup or scanning. Submitted or queried URLs may be added to its community dataset. Avoid private or password-reset links. <a href="https://docs.virustotal.com/reference/scan-url" target="_blank" rel="noreferrer">VirusTotal data notice</a>. You can also check a URL separately in the URL tab.</> : <>Automatic VirusTotal checks are not configured on this service; suspicious URL patterns can still appear in message analysis. Use the URL tab to check one separately.</>}</p>

              {result && (
                <section className={`results${result.error ? ' results-error' : ''}`} aria-live="polite" aria-atomic="true">
                  {result.error ? <p className="error-message">{result.error}</p> : <>
                    <div className="result-topline">
                      <div>
                        <p className="result-kicker">{result.mode === 'ai-assisted' ? `${(config?.externalProvider || 'AI').toUpperCase()} + RULE ENGINE` : 'RULE ENGINE'}</p>
                        <h2>Your assessment</h2>
                      </div>
                      <div className={`risk-badge risk-${result.level.toLowerCase()}`}><span><small>RISK LEVEL</small><strong>{result.level}</strong></span></div>
                    </div>
                    {result.urlChecks && <section className="url-checks" aria-label="Automatic VirusTotal checks"><div className="url-checks-heading"><h3>Links found in this message</h3><span>{result.urlChecks.configured ? 'VirusTotal' : 'Not configured'}</span></div>{result.urlChecks.results.map((item, index) => <div className={`url-check-row url-check-${item.status}`} key={`${item.url}-${index}`}><div><code>{item.url}</code><strong>{urlCheckLabels[item.status] || item.status}</strong>{Number.isInteger(item.detections) && <small>{item.malicious} malicious · {item.suspicious} suspicious · {item.total} vendors</small>}{item.message && <small>{item.message}</small>}</div>{item.reportUrl && <a href={item.reportUrl} target="_blank" rel="noreferrer">VirusTotal report ↗</a>}</div>)}{result.urlChecks.results.some((item) => ['malicious', 'suspicious'].includes(item.status)) && <p className="url-check-note">VirusTotal findings affect the overall risk level. The pattern match score reflects ScamShield rules only.</p>}{result.urlChecks.skipped > 0 && <p className="url-check-note">{result.urlChecks.skipped} additional link{result.urlChecks.skipped === 1 ? '' : 's'} not checked (maximum 3 per message).</p>}{result.urlChecks.results.some((item) => item.status === 'not_submitted') && <p className="url-check-note">Only one new URL is submitted per message to stay within the free API quota. Review this message again later for updated results.</p>}{result.urlChecks.results.some((item) => item.status === 'pending') && <p className="url-check-note">A new URL was submitted for scanning. Review this message again in about 30 seconds for the report.</p>}{!result.urlChecks.configured && <p className="url-check-note">Add <code>VIRUSTOTAL_API_KEY</code> to the server environment to enable automatic checks.</p>}</section>}
                    {result.mode === 'ai-assisted' ? <><div className="assessment-summary"><strong>{result.assessment?.scamType}</strong><p>{result.assessment?.summary}</p><small>AI assessment may be wrong. Risk level is not a probability.</small></div>{result.assessment?.attackChain?.length > 0 && <div className="attack-chain"><h3>Social engineering sequence</h3><p className="chain-intro">How the conversation may be building toward an unsafe action</p><ol>{result.assessment.attackChain.map((step, index) => <li key={`${step.stage}-${index}`}><span className="chain-index">{String(index + 1).padStart(2, '0')}</span><span><strong>{step.stage}</strong><q>{step.evidence}</q><small>{step.interpretation}</small></span></li>)}</ol></div>}</> : <><div className="score-row"><span>Pattern match score</span><strong>{result.score}<span> / 100</span></strong></div><div className="score-track" role="progressbar" aria-label="Pattern match score" aria-valuenow={result.score} aria-valuemin="0" aria-valuemax="100"><span className={`score-fill fill-${result.level.toLowerCase()}`} style={{ width: `${result.score}%` }} /></div><p className="score-note">A pattern match score is not the probability that a message is a scam.</p></>}
                    {result.level === 'High' && (() => {
                      const financialRisk = [...(result.categories || []), result.assessment?.scamType || ''].some((category) => /payment|upi|financial/i.test(category))
                      return <div className="response-panel"><div><p className="result-kicker">RECOMMENDED RESPONSE</p><h3>{financialRisk ? 'If money or payment details were involved' : 'Secure the affected account or device'}</h3></div>{financialRisk ? <><p>If money has already been sent, contact your bank or payment provider using its official app or number, then report the financial fraud immediately.</p><div className="response-actions"><a href="tel:1930">Call India cyber fraud helpline: 1930</a><a href="https://www.cybercrime.gov.in/" target="_blank" rel="noreferrer">Open National Cyber Crime Reporting Portal</a></div></> : <p>Do not continue through the message. Open the service’s official app or website directly, secure the account, and contact its support channel if credentials or device access were shared.</p>}</div>
                    })()}
                    <div className="result-columns">
                      <div><h3>Signals identified <span className="count-pill">{result.signals.length}</span></h3>{result.signals.length ? <ul className="signal-list">{result.signals.map((signal, index) => <li key={`${signal.name}-${index}`}><span className="signal-check" aria-hidden="true">!</span><span><strong>{signal.name}</strong>{signal.evidence && <small>Evidence: &quot;{signal.evidence}&quot;</small>}{signal.explanation && <small>{signal.explanation}</small>}{signal.points > 0 && <small>Rule score: +{signal.points}</small>}</span></li>)}</ul> : <p className="quiet-copy">No configured warning patterns matched.</p>}</div>
                      <div className="advice-panel"><h3>What to do next</h3><ul>{result.advice.map((item) => <li key={item}>{item}</li>)}</ul></div>
                    </div>
                    <div className="result-tools"><span>Share this assessment with a trusted person or support team.</span><button type="button" onClick={() => copyAssessment(result)}>{copyState || 'Copy assessment'}</button></div>
                    <p className="result-footnote">{result.mode === 'ai-assisted' ? 'AI analysis can miss context or make mistakes. Verify unexpected requests independently.' : 'This scan checks configured rules only. No matched pattern does not mean a message is safe.'}</p>
                  </>}</section>
              )}
            </form>}
            {activeTool === 'url' && <section className="url-tool" role="tabpanel" id="url-panel" aria-labelledby="url-tab url-tool-title">
              <div><span className="section-kicker">URL CHECK</span><h3 id="url-tool-title">Check a link on its own</h3><p>Paste one complete web address. VirusTotal may look it up or submit it for scanning.</p></div>
              <form onSubmit={handleCheckUrl} className="url-tool-form">
                <label className="sr-only" htmlFor="url-input">URL to check</label>
                <input id="url-input" type="url" inputMode="url" placeholder="https://example.com" value={urlInput} onChange={(event) => { setUrlInput(event.target.value); setUrlResult(null); setUrlError('') }} maxLength={2048} required />
                <button type="submit" className="primary-button" disabled={urlChecking}>{urlChecking ? 'Checking…' : 'Check URL'} <span aria-hidden="true">↗</span></button>
              </form>
              <p className="url-disclosure">{config?.virusTotalAvailable ? <>The URL is sent to VirusTotal. Submitted or queried URLs are added to its community dataset. Don’t check private, confidential, or password-reset links. <a href="https://docs.virustotal.com/reference/scan-url" target="_blank" rel="noreferrer">VirusTotal data notice</a>.</> : <>URL checks need <code>VIRUSTOTAL_API_KEY</code> on the server.</>}</p>
              {urlError && <p className="media-error" role="alert">{urlError}</p>}
              {urlResult && urlResult.results.map((item, index) => <div className={`url-check-row url-check-${item.status} standalone-url-result`} key={`${item.url}-${index}`}><div><code>{item.url}</code><strong>{urlCheckLabels[item.status] || item.status}</strong>{Number.isInteger(item.detections) && <small>{item.malicious} malicious · {item.suspicious} suspicious · {item.total} vendors</small>}{item.message && <small>{item.message}</small>}</div>{item.reportUrl && <a href={item.reportUrl} target="_blank" rel="noreferrer">VirusTotal report ↗</a>}</div>)}
              {urlResult?.results.some((item) => item.status === 'pending') && <p className="url-check-note">Scan submitted. Check the link again in about 30 seconds to see the report.</p>}
            </section>}
            {activeTool === 'media' && <section className="media-tool" role="tabpanel" id="media-panel" aria-labelledby="media-tab">
              <section className="media-upload" aria-labelledby="media-heading">
                <div className="media-upload-heading"><div><span className="section-kicker">MEDIA CHECK</span><h3 id="media-heading">Review an image, video, or audio clip</h3><p>We’ll inspect visible clues, extract text, transcribe speech, and flag supported safety concerns.</p></div>
                  <label className="secondary-button media-pick" htmlFor="media-file">{mediaFile ? 'Choose another file' : 'Choose media'}</label>
                </div>
                <input id="media-file" className="media-input" type="file" accept="image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm,audio/mpeg,audio/mp4,audio/wav,audio/ogg,audio/flac,audio/webm" onChange={handleMediaChange} disabled={isAnalyzing || mediaPreparing} />
                {mediaPreparing && <p className="media-status" role="status">Preparing media preview…</p>}
                {mediaFile && <div className="media-preview">
                  {mediaFile.type.startsWith('video/') ? <video src={mediaPreviewUrl} controls preload="metadata" /> : mediaFile.type.startsWith('audio/') ? <audio src={mediaPreviewUrl} controls preload="metadata" /> : <img src={mediaPreviewUrl} alt="Selected media preview" />}
                  <div><strong>{mediaFile.name}</strong><small>{(mediaFile.size / (1024 * 1024)).toFixed(1)} MB · {mediaFile.type.startsWith('video/') ? `${mediaFrames.length} sampled frames` : mediaFile.type.startsWith('audio/') ? 'audio clip' : 'image preview'}</small></div>
                  <button type="button" className="media-remove" onClick={() => { setMediaFile(null); setMediaFrames([]); setMediaPreviewUrl(''); setMediaResult(null); setMediaError('') }} disabled={isAnalyzing}>Remove</button>
                </div>}
                <p className="media-disclosure">{config?.mediaAnalysisAvailable ? <>Selected media is sent to ScamShield and Groq for description and transcription. {config?.mediaAiDetectionAvailable && <>It is also sent to Sightengine for a separate AI-origin score; its audio model is available on paid plans.</>} Videos use sampled frames for Groq{config?.mediaAiDetectionAvailable ? ' and are submitted to Sightengine’s short-video detector' : ''}. Groq may temporarily retain inputs for abuse and reliability investigations. <a href="https://console.groq.com/docs/your-data" target="_blank" rel="noreferrer">Groq data handling</a>{config?.mediaAiDetectionAvailable && <> · <a href="https://sightengine.com/policies/privacy" target="_blank" rel="noreferrer">Sightengine privacy</a></>}.</> : <>Media review needs a server-side <code>GROQ_API_KEY</code>. Supported image, video, and audio uploads are limited to 20 MB.</>} {config?.mediaAiDetectionAvailable ? 'AI-origin scores are estimates, not proof.' : <>Add <code>SIGHTENGINE_API_USER</code> and <code>SIGHTENGINE_API_SECRET</code> to enable dedicated AI-origin scoring.</>} C2PA checks validate embedded credentials without fetching remote manifests. Audio transcription and AI-voice detection are separate checks.</p>
                {mediaError && <p className="media-error" role="alert">{mediaError}</p>}
                <button type="button" className="primary-button media-review" onClick={handleAnalyzeMedia} disabled={!mediaFile || (!mediaFrames.length && !mediaFile.type.startsWith('audio/')) || isAnalyzing || mediaPreparing}>{isAnalyzing && mediaFile ? 'Reviewing media…' : 'Review media'} <span aria-hidden="true">↗</span></button>
              </section>
              {mediaResult && <section className="results media-results" aria-live="polite" aria-atomic="true">
                <div className="result-topline"><div><p className="result-kicker">{mediaResult.mediaType === 'audio' ? 'GROQ WHISPER + RULE CHECKS' : `GROQ VISION${mediaResult.mediaType === 'video' ? ' + WHISPER' : ''}`}{mediaResult.aiDetection?.status === 'completed' && ' + SIGHTENGINE'}</p><h2>Media assessment</h2></div><span className={`origin-badge origin-${mediaResult.authenticity.verdict}`}>{mediaResult.mediaType === 'audio' ? mediaResult.aiDetection?.status === 'completed' ? `${mediaResult.aiDetection.label === 'likely_ai_generated' ? 'AI speech signal' : mediaResult.aiDetection.label === 'no_strong_ai_signal' ? 'No strong AI speech signal' : 'Voice origin inconclusive'} · ${(mediaResult.aiDetection.score * 100).toFixed(0)}%` : 'Audio origin not assessed' : `${mediaOriginLabels[mediaResult.authenticity.verdict] || 'Origin unclear'} · ${mediaResult.authenticity.confidence} confidence`}</span></div>
                <p className="media-summary">{mediaResult.summary || 'No clear description was returned.'}</p>
                {mediaResult.aiDetection?.status === 'completed' && <div className="media-result-block"><h3>AI origin estimate · {mediaResult.mediaType === 'audio' ? 'speech' : mediaResult.mediaType}</h3><div className="detection-score"><strong>{(mediaResult.aiDetection.score * 100).toFixed(0)}%</strong><span>{mediaResult.aiDetection.label === 'likely_ai_generated' ? 'Strong AI-generation signal' : mediaResult.aiDetection.label === 'no_strong_ai_signal' ? 'No strong AI-generation signal' : 'Inconclusive score'}</span></div><small>{mediaResult.aiDetection.model}. This is a model score, not proof. A low score does not establish that media is authentic.</small></div>}
                {mediaResult.aiDetection?.status === 'unavailable' && <p className="url-check-note">The separate AI-origin service was unavailable for this review; the content analysis is still shown.</p>}
                {mediaResult.provenance?.status !== 'unavailable' && <div className="media-result-block"><h3>Content Credentials (C2PA)</h3>{mediaResult.provenance?.status === 'found' ? <><p>Manifest detected · validation: <strong>{mediaResult.provenance.validation || 'unknown'}</strong></p>{mediaResult.provenance.signer && <p>Signer: {mediaResult.provenance.signer}</p>}{mediaResult.provenance.title && <p>Title: {mediaResult.provenance.title}</p>}{mediaResult.provenance.digitalSourceTypes?.length > 0 && <p>Digital source: {mediaResult.provenance.digitalSourceTypes.join(', ')}</p>}{mediaResult.provenance.actions?.length > 0 && <p>Recorded actions: {mediaResult.provenance.actions.join(', ')}</p>}<small>A valid signature supports the recorded provenance; it does not guarantee that the depicted claims are true.</small></> : mediaResult.provenance?.status === 'not_found' ? <p>No embedded Content Credentials were found. Many authentic files do not include C2PA credentials.</p> : <p>Credentials may be present, but they could not be validated or read.</p>}</div>}
                {mediaResult.authenticity.reasons.length > 0 && <div className="media-result-block"><h3>Origin clues</h3><ul>{mediaResult.authenticity.reasons.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
                {Object.keys(mediaResult.visualChecks || {}).length > 0 && <div className="media-result-block"><h3>Visual clues reviewed</h3>{Object.entries(mediaResult.visualChecks).map(([key, items]) => <p className="visual-check-row" key={key}><strong>{({ anatomy_details: 'Anatomy and fine details', text_and_symbols: 'Text and symbols', spatial_geometry: 'Spatial geometry', lighting_and_reflections: 'Lighting and reflections', texture_consistency: 'Texture consistency' })[key] || key}:</strong> {items.join('; ')}</p>)}<small>These are model observations from visible pixels, not forensic findings.</small></div>}
                {mediaResult.visibleText.length > 0 && <div className="media-result-block"><h3>Text found in media</h3><ul>{mediaResult.visibleText.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
                {mediaResult.claims.length > 0 && <div className="media-result-block"><h3>Claims shown</h3><ul>{mediaResult.claims.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
                {mediaResult.safetyConcerns.length > 0 && <div className="media-result-block media-concerns"><h3>Safety concerns</h3><ul>{mediaResult.safetyConcerns.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
                {mediaResult.transcriptStatus !== 'not_applicable' && <div className="media-result-block"><h3>Speech transcript</h3>{mediaResult.transcript ? <p>{mediaResult.transcript}</p> : <p>{mediaResult.transcriptStatus === 'no_speech_detected' ? 'No speech was detected.' : mediaResult.transcriptStatus || 'No transcript available.'}</p>}</div>}
                {mediaResult.metadataIndicators.length > 0 && <div className="media-result-block"><h3>Unverified metadata clues</h3><ul>{mediaResult.metadataIndicators.map((item, index) => <li key={index}>{item}</li>)}</ul><small>Metadata can be forged or copied; these markers are not proof of origin.</small></div>}
                {mediaResult.mediaType !== 'audio' && <p className="media-provenance-link">Optional external checks: <a href="https://synthid.com/" target="_blank" rel="noreferrer">Google SynthID Detector ↗</a> or <a href="https://lens.google.com/" target="_blank" rel="noreferrer">Google Lens ↗</a>. Upload the original only if you are comfortable sharing it with those services. ScamShield does not send your upload to them.</p>}
                <p className="result-footnote">{mediaResult.authenticity.caveat}{mediaResult.mediaType === 'video' && ' Video review only sees sampled frames and may miss events or lip-sync issues between them.'}{mediaResult.mediaType !== 'audio' && ' Appearance-based detection can be wrong; an inconclusive result does not mean the media is authentic.'}</p>
              </section>}
            </section>}
          </section>
        </div>

        {activeTool === 'message' && !result && <section className="examples" aria-label="Try a sample message"><div><span className="section-kicker">TRY A SAMPLE</span><p>Explore the prototype with a scenario</p></div><div className="example-list">{examples.map((example) => <button type="button" key={example.label} onClick={() => loadExample(example)}>{example.label}<span aria-hidden="true">↗</span></button>)}</div></section>}

        <aside className="reminder"><span className="reminder-icon" aria-hidden="true">✓</span><p><strong>When in doubt, verify independently.</strong> Contact the person or organization using details you already trust — not details in the message.</p></aside>
      </main>

      <footer><a className="footer-brand" href="#top">ScamShield</a><span>Clear signals. Safer next steps.</span><span>Automated indicators are not proof.</span></footer>
    </div>
  )
}

export default App
