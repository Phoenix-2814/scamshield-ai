import { useEffect, useRef, useState } from 'react'
import { analyzeMediaRequest, analyzeMessageRequest, checkUrlRequest, getAnalyzerConfig } from './api'
import './App.css'

const threatScenarios = [
  {
    category: 'Banking Alert',
    badge: 'Urgent',
    label: 'Fake bank account freeze',
    message: 'URGENT: Your bank account will be blocked within 2 hours due to KYC non-compliance. Share your OTP immediately to verify: https://secure-check.example'
  },
  {
    category: 'Payment Trap',
    badge: 'Financial',
    label: 'UPI QR collect fraud',
    message: 'Scan this QR code to receive your pending refund of Rs 4,800. Approve the UPI collect request and enter your UPI PIN to credit your bank.'
  },
  {
    category: 'Impersonation',
    badge: 'Identity',
    label: 'Family emergency account request',
    message: 'Hi I am your brother. My phone is switched off and I am stuck at the clinic, can you send me the login details and password of your netbanking account urgently?'
  },
  {
    category: 'Social Eng.',
    badge: 'Multi-turn',
    label: 'Number swap credential harvest',
    message: 'Sender: It is your brother. This is my new number; the old phone is being repaired.\nSender: I cannot call right now, but I need a quick favor.\nMe: What do you need?\nSender: Open the bank app and read me the notification that appears. I will explain after.'
  },
  {
    category: 'Job Scam',
    badge: 'Advance Fee',
    label: 'Work-from-home fee trap',
    message: 'Congratulations! Part-time work from home opportunity. Earn 5000-8000 per day by rating products. Pay a refundable onboarding registration fee of Rs 499 to start today.'
  },
  {
    category: 'Benign',
    badge: 'Clean',
    label: 'Routine calendar check',
    message: 'Hi! Are we still meeting at the public library reading hall at 4 PM for the project discussion? Let me know if the time works for you.'
  },
]

const urlCheckLabels = {
  malicious: 'Malicious detections',
  suspicious: 'Suspicious detections',
  no_detections: 'Clean · No threats detected',
  unrated: 'Unrated · No vendor verdict yet',
  pending: 'Scan in progress',
  unavailable: 'Threat feed unavailable',
  not_configured: 'VirusTotal API key not configured'
}

const mediaOriginLabels = {
  likely_ai_generated: 'Likely AI-Generated',
  no_strong_ai_signal: 'No Common AI Signs Found',
  inconclusive: 'AI Origin Uncertain',
  no_clear_ai_signs: 'No Obvious AI Signs',
  unclear: 'Origin Unverified'
}

const mediaDetectionErrors = {
  credentials_rejected: 'External AI verification service unavailable. File evaluated with local signatures.',
  payment_required: 'External AI verification service busy. File evaluated with local signatures.',
  quota_reached: 'Cloud AI scanner is temporarily busy. Analyzed via file metadata & signatures.',
  unsupported_media: 'Format unsupported. Please provide a standard MP4, WebM, JPEG, PNG, or audio file.',
  invalid_request: 'Cloud verification service could not process parameters.',
  duration_limit: 'Video is over 60 seconds. Visual review completed without AI video score.',
  unavailable: 'Cloud verification service temporarily unreachable. Content review displayed.',
  not_configured: 'Cloud scanner not configured. Showing local signature & content review.'
}

function canvasFrame(source) {
  const width = source.videoWidth || source.naturalWidth
  const height = source.videoHeight || source.naturalHeight
  const scale = Math.min(1, 1280 / Math.max(width, height))
  const canvas = document.createElement('canvas')
  canvas.width = Math.max(1, Math.round(width * scale))
  canvas.height = Math.max(1, Math.round(height * scale))
  const context = canvas.getContext('2d')
  if (!context) throw new Error('Browser unable to render canvas context for media analysis.')
  context.drawImage(source, 0, 0, canvas.width, canvas.height)
  return canvas.toDataURL('image/jpeg', 0.82)
}

async function prepareMediaFrames(file) {
  if (file.type.startsWith('audio/')) return { frames: [], duration: null }
  const objectUrl = URL.createObjectURL(file)
  try {
    if (file.type.startsWith('image/')) {
      const image = new Image()
      image.src = objectUrl
      await image.decode()
      return { frames: [canvasFrame(image)], duration: null }
    }

    const video = document.createElement('video')
    video.preload = 'metadata'
    video.muted = true
    video.src = objectUrl
    await new Promise((resolve, reject) => {
      video.addEventListener('loadedmetadata', resolve, { once: true })
      video.addEventListener('error', () => reject(new Error('This video could not be decoded by the browser.')), { once: true })
    })
    if (!Number.isFinite(video.duration) || video.duration <= 0) throw new Error('Video has no readable temporal frames.')
    const times = [...new Set([video.duration * 0.1, video.duration * 0.5, video.duration * 0.9].map((time) => Math.min(Math.max(0, time), Math.max(0, video.duration - 0.05))))]
    const frames = []
    for (const time of times) {
      await new Promise((resolve, reject) => {
        video.addEventListener('seeked', resolve, { once: true })
        video.addEventListener('error', () => reject(new Error('A video frame could not be extracted.')), { once: true })
        video.currentTime = time
      })
      frames.push(canvasFrame(video))
    }
    return { frames, duration: video.duration }
  } finally {
    URL.revokeObjectURL(objectUrl)
  }
}

// Inline sleek SVG Icons
const ShieldIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
)

const ShieldAlertIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <line x1="12" y1="8" x2="12" y2="12"/>
    <line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
)

const ShieldCheckIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <polyline points="9 12 11 14 15 10"/>
  </svg>
)

const MessageSquareIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
  </svg>
)

const GlobeIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="2" y1="12" x2="22" y2="12"/>
    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
  </svg>
)

const MediaIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"/>
    <line x1="7" y1="2" x2="7" y2="22"/>
    <line x1="17" y1="2" x2="17" y2="22"/>
    <line x1="2" y1="12" x2="22" y2="12"/>
    <line x1="2" y1="7" x2="7" y2="7"/>
    <line x1="2" y1="17" x2="7" y2="17"/>
    <line x1="17" y1="17" x2="22" y2="17"/>
    <line x1="17" y1="7" x2="22" y2="7"/>
  </svg>
)

const CopyIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
  </svg>
)

const CheckIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
)

const ArrowUpRightIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="7" y1="17" x2="17" y2="7"/>
    <polyline points="7 7 17 7 17 17"/>
  </svg>
)

const AlertCircleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="12" y1="8" x2="12" y2="12"/>
    <line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
)

const SparklesIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/>
  </svg>
)

const UploadIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
    <polyline points="17 8 12 3 7 8"/>
    <line x1="12" y1="3" x2="12" y2="15"/>
  </svg>
)

function App() {
  const [message, setMessage] = useState('')
  const [result, setResult] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [config, setConfig] = useState(null)
  const [copyState, setCopyState] = useState('')
  const [mediaFile, setMediaFile] = useState(null)
  const [mediaFrames, setMediaFrames] = useState([])
  const [mediaDuration, setMediaDuration] = useState(null)
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
      setMediaError('Supported file formats: JPEG, PNG, WebP, GIF, MP4, WebM, or Audio (MP3, WAV, M4A, OGG).')
      setMediaFile(null)
      setMediaFrames([])
      setMediaDuration(null)
      setMediaPreviewUrl('')
      setMediaResult(null)
      return
    }
    if (file.size > 20 * 1024 * 1024) {
      setMediaError('File size limit exceeded. Upload media smaller than 20 MB.')
      setMediaFile(null)
      setMediaFrames([])
      setMediaDuration(null)
      setMediaPreviewUrl('')
      setMediaResult(null)
      return
    }
    setMediaPreparing(true)
    setMediaError('')
    setMediaResult(null)
    try {
      const prepared = await prepareMediaFrames(file)
      setMediaPreviewUrl(URL.createObjectURL(file))
      setMediaFile(file)
      setMediaFrames(prepared.frames)
      setMediaDuration(prepared.duration)
    } catch (error) {
      setMediaFile(null)
      setMediaFrames([])
      setMediaDuration(null)
      setMediaPreviewUrl('')
      setMediaResult(null)
      setMediaError(error.message || 'Could not parse media frames for inspection.')
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
      if (!analyzerConfig.mediaAnalysisAvailable) {
        throw new Error('Media threat analysis engine not initialized. Please verify GROQ_API_KEY on the server.')
      }
      setMediaResult(await analyzeMediaRequest(mediaFile, mediaFrames, mediaDuration))
    } catch (error) {
      setMediaError(error.message)
    } finally {
      setIsAnalyzing(false)
    }
  }

  async function handleCheckUrl(event) {
    event.preventDefault()
    if (!urlInput.trim()) return
    setUrlChecking(true)
    setUrlResult(null)
    setUrlError('')
    try {
      setUrlResult(await checkUrlRequest(urlInput.trim()))
    } catch (error) {
      setUrlError(error.message || 'The specified URL could not be evaluated by security feeds.')
    } finally {
      setUrlChecking(false)
    }
  }

  async function handleAnalyze(event) {
    if (event) event.preventDefault()
    if (!message.trim()) return
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

  function handleKeyDown(event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      handleAnalyze()
    }
  }

  function handleChange(event) {
    setMessage(event.target.value)
    if (result) setResult(null)
  }

  function handleClear() {
    setMessage('')
    setResult(null)
    setMediaFile(null)
    setMediaFrames([])
    setMediaDuration(null)
    setMediaPreviewUrl('')
    setMediaResult(null)
    setMediaError('')
    setUrlInput('')
    setUrlResult(null)
    setUrlError('')
  }

  function loadExample(scenario) {
    setMessage(scenario.message)
    setResult(null)
    setMediaFile(null)
    setMediaFrames([])
    setMediaDuration(null)
    setMediaPreviewUrl('')
    setMediaResult(null)
    setMediaError('')
    setUrlInput('')
    setUrlResult(null)
    setUrlError('')
    // smooth scroll to form if needed
    const panel = document.getElementById('analyzer-panel')
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  async function handlePaste() {
    try {
      const text = await navigator.clipboard.readText()
      if (text) {
        setMessage(text)
        setResult(null)
      }
    } catch {
      // ignore clipboard permission error
    }
  }

  async function copyAssessment(analysis) {
    const lines = [
      `=========================================`,
      `SCAMSHIELD AI THREAT INTELLIGENCE REPORT`,
      `Assessed Risk Level: ${analysis.level?.toUpperCase()}`,
      `Detection Engine: ${analysis.mode === 'ai-assisted' ? (config?.externalProvider || 'Multi-Modal AI') : 'Heuristic Rules Engine'}`,
      `=========================================`,
      analysis.assessment ? `\nPrimary Threat Category: ${analysis.assessment.scamType}\nExecutive Summary: ${analysis.assessment.summary}` : '',
      `\nKey Deception Signals Identified:`,
      ...analysis.signals.map((signal, i) => `${i + 1}. [${signal.name}] ${signal.evidence ? `"${signal.evidence}"` : ''} - ${signal.explanation || ''}`),
      ...(analysis.urlChecks?.results?.length ? [
        `\nURL Reputation Feeds:`,
        ...analysis.urlChecks.results.map((item) => `- ${item.url}: ${urlCheckLabels[item.status] || item.status} (${item.detections ?? 0}/${item.total ?? 0} security vendors flagged)`)
      ] : []),
      `\nRecommended Action Protocol:`,
      ...analysis.advice.map((item, i) => `${i + 1}. ${item}`),
      `\nNotice: Automated intelligence assessment generated for incident response and risk mitigation. Verify critical requests through trusted, out-of-band channels.`
    ].filter(Boolean)
    try {
      await navigator.clipboard.writeText(lines.join('\n'))
      setCopyState('Report Copied to Clipboard!')
      window.setTimeout(() => setCopyState(''), 2500)
    } catch {
      setCopyState('Copy failed')
      window.setTimeout(() => setCopyState(''), 2500)
    }
  }

  return (
    <div className="app" id="top">
      {/* Top Professional Navigation */}
      <header className="navbar">
        <div className="navbar-container">
          <a className="brand" href="#top" aria-label="ScamShield AI Platform">
            <span className="brand-mark" aria-hidden="true">
              <ShieldIcon />
            </span>
            <div className="brand-text">
              <span className="brand-title">SCAM<span className="brand-highlight">SHIELD</span></span>
              <span className="brand-badge">AI PLATFORM</span>
            </div>
          </a>

          <nav className="nav-links" aria-label="Primary navigation">
            <a href="#analyzer-panel">Analyzer</a>
            <a href="#how-it-works">How It Works</a>
            <a href="#scenarios">Threat Scenarios</a>
          </nav>

          <div className="nav-actions">
            <div className="engine-status-pill" title="Real-time multi-modal detection engine active">
              <span className="pulse-dot" />
              <span className="status-text">Engine Online</span>
              <span className="privacy-pill">Zero Retention</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Hero & Console Section */}
      <main className="page-shell">
        <section className="hero-heading">
          <div className="eyebrow">
            <span className="eyebrow-icon"><ShieldCheckIcon /></span>
            <span>ENTERPRISE FRAUD & CYBER INTELLIGENCE</span>
          </div>
          <h1>
            Inspect Before You Trust.<br />
            <span className="gradient-text">Detect Deception in Real Time.</span>
          </h1>
          <p className="subtitle">
            Instantly evaluate suspicious messages, phishing domains, synthetic voice clips, and deepfakes with multi-modal AI heuristics and forensic evidence chains.
          </p>

          <div className="trust-metrics-strip">
            <div className="metric-chip">
              <span className="metric-dot blue" />
              <strong>Multi-Modal AI</strong>
              <small>{config?.externalProvider || 'Groq Vision & Whisper'} + Rules</small>
            </div>
            <div className="metric-chip">
              <span className="metric-dot green" />
              <strong>VirusTotal Threat Feeds</strong>
              <small>70+ Vendor Lookups</small>
            </div>
            <div className="metric-chip">
              <span className="metric-dot amber" />
              <strong>C2PA Provenance</strong>
              <small>Content Credentials Audit</small>
            </div>
            <div className="metric-chip">
              <span className="metric-dot cyan" />
              <strong>Privacy Guaranteed</strong>
              <small>Zero-Knowledge / Ephemeral</small>
            </div>
          </div>
        </section>

        {/* Workspace Layout */}
        <div className="workspace-grid" id="analyzer-panel">
          {/* Left Threat Architecture Card */}
          <section className="story-card" aria-label="Threat Deconstruction Blueprint" id="how-it-works">
            <div className="story-topline">
              <span className="card-kicker">THREAT RADAR</span>
              <span className="story-live"><span /> Social Engineering Anatomy</span>
            </div>

            <h2>Deconstructing the Anatomy of Modern Attacks</h2>
            <p>
              Attackers exploit cognitive blindspots through simulated authority, sudden urgency, and familiar pretexts. ScamShield deconstructs each conversational layer.
            </p>

            <div className="threat-breakdown-card">
              <div className="threat-header">
                <span className="avatar-chip">SMS / Chat</span>
                <span className="threat-tag">Social Engineering Simulation</span>
              </div>
              <div className="mock-chat-bubble">
                <div className="mock-meta">UNVERIFIED CONTACT · 10:42 AM</div>
                <div className="mock-text">“Your banking token expired. Click to reactivate and read out the confirmation SMS code to our agent.”</div>
              </div>
              <div className="threat-warning-pill">
                <AlertCircleIcon />
                <div>
                  <strong>High Probability Credential Harvesting</strong>
                  <p>Artificial urgency paired with out-of-band credential extraction request.</p>
                </div>
              </div>
            </div>

            <div className="story-steps">
              <div className="step-row">
                <div className="step-num">01</div>
                <div className="step-content">
                  <strong>Multi-Channel Ingestion</strong>
                  <p>Directly inspect messages, multi-turn chat threads, raw URLs, or media files.</p>
                </div>
              </div>
              <div className="step-row">
                <div className="step-num">02</div>
                <div className="step-content">
                  <strong>Deep Signal Extraction</strong>
                  <p>Correlates urgency pressure, payment redirections, AI voice traits, and malicious links.</p>
                </div>
              </div>
              <div className="step-row">
                <div className="step-num">03</div>
                <div className="step-content">
                  <strong>Prescriptive Defense Steps</strong>
                  <p>Provides vetted containment advice, verification protocols, and national reporting hotlines.</p>
                </div>
              </div>
            </div>

            <div className="story-footer-tip">
              <strong>Security Protocol Tip:</strong> Never verify an account using phone numbers, links, or contacts sent within the suspicious message itself. Always use bookmarked, official channels.
            </div>
          </section>

          {/* Right Core Analyzer Console */}
          <section className="analyzer">
            <div className="analyzer-header">
              <div>
                <span className="section-kicker">ANALYZER WORKSPACE</span>
                <h2>Select Inspection Vector</h2>
              </div>
              <div className={`engine-badge${config?.aiAssistedAvailable ? ' engine-ai' : ''}`}>
                <SparklesIcon />
                <span>{config?.aiAssistedAvailable ? `${config.externalProvider} Multi-Modal Enabled` : 'Deterministic Rules Engine'}</span>
              </div>
            </div>

            {/* Mode Switcher Tabs */}
            <div className="tool-tabs" role="tablist" aria-label="Inspection Vector Selection">
              <button
                type="button"
                id="message-tab"
                role="tab"
                aria-controls="message-panel"
                aria-selected={activeTool === 'message'}
                className={`tab-btn ${activeTool === 'message' ? 'active' : ''}`}
                onClick={() => setActiveTool('message')}
              >
                <div className="tab-icon"><MessageSquareIcon /></div>
                <div className="tab-details">
                  <strong>Message & Chat</strong>
                  <small>NLP, urgency & scam patterns</small>
                </div>
              </button>

              <button
                type="button"
                id="url-tab"
                role="tab"
                aria-controls="url-panel"
                aria-selected={activeTool === 'url'}
                className={`tab-btn ${activeTool === 'url' ? 'active' : ''}`}
                onClick={() => setActiveTool('url')}
              >
                <div className="tab-icon"><GlobeIcon /></div>
                <div className="tab-details">
                  <strong>URL Reputation</strong>
                  <small>VirusTotal 70+ scanner checks</small>
                </div>
              </button>

              <button
                type="button"
                id="media-tab"
                role="tab"
                aria-controls="media-panel"
                aria-selected={activeTool === 'media'}
                className={`tab-btn ${activeTool === 'media' ? 'active' : ''}`}
                onClick={() => setActiveTool('media')}
              >
                <div className="tab-icon"><MediaIcon /></div>
                <div className="tab-details">
                  <strong>Deepfake & Media</strong>
                  <small>Vision, C2PA, Whisper speech</small>
                </div>
              </button>
            </div>

            {/* MESSAGE TAB */}
            {activeTool === 'message' && (
              <form id="message-panel" role="tabpanel" aria-labelledby="message-tab" onSubmit={handleAnalyze}>
                <div className="field-heading">
                  <label htmlFor="message">Suspicious Message or Conversation Transcript</label>
                  <div className="field-tools">
                    <button type="button" className="ghost-btn" onClick={handlePaste} title="Paste from clipboard">
                      <CopyIcon /> Paste
                    </button>
                    <span className="field-hint">{message.length.toLocaleString()} / 5,000 characters</span>
                  </div>
                </div>

                <div className="textarea-wrapper">
                  <textarea
                    id="message"
                    value={message}
                    onChange={handleChange}
                    onKeyDown={handleKeyDown}
                    disabled={isAnalyzing}
                    placeholder="Paste the email, SMS, WhatsApp exchange, or social DM here. You can include entire conversation transcripts to provide full conversational context..."
                    rows={6}
                    maxLength={5000}
                    aria-describedby="privacy-note"
                  />
                </div>

                <div className="form-footer">
                  <div className="shortcut-hint">
                    <kbd>Ctrl</kbd> + <kbd>Enter</kbd> to analyze
                  </div>
                  <div className="actions">
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={handleClear}
                      disabled={isAnalyzing || (!message && !result)}
                    >
                      Clear
                    </button>
                    <button type="submit" className="primary-button" disabled={isAnalyzing || !message.trim()}>
                      {isAnalyzing ? (
                        <>
                          <span className="btn-spinner" /> Running Security Scan…
                        </>
                      ) : (
                        <>
                          Analyze Message Threat <ArrowUpRightIcon />
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <p className="privacy" id="privacy-note">
                  <span className="privacy-label">PRIVACY GUARANTEE:</span>{' '}
                  {config?.aiAssistedAvailable ? (
                    config.externalProvider === 'Groq' ? (
                      <>
                        Inspected via ScamShield rules and Groq accelerated inference. Content is processed in-memory with zero default persistence. <a href="https://console.groq.com/docs/your-data" target="_blank" rel="noreferrer">Review Groq enterprise data policies</a>.
                      </>
                    ) : (
                      <>
                        Evaluated via ScamShield rules and Google Gemini. Zero Data Retention (ZDR) configuration active. <a href="https://ai.google.dev/gemini-api/docs/zdr" target="_blank" rel="noreferrer">Review Gemini data handling</a>.
                      </>
                    )
                  ) : (
                    <>Analyzed purely using ScamShield deterministic heuristics. Your data never leaves your environment.</>
                  )}
                  {config?.virusTotalAvailable && <> Embedded links are checked against the VirusTotal threat registry.</>}
                </p>

                {/* RESULTS SECTION */}
                {result && (
                  <section className={`results-card ${result.error ? 'results-card-error' : ''}`} aria-live="polite">
                    {result.error ? (
                      <div className="error-alert">
                        <AlertCircleIcon />
                        <p>{result.error}</p>
                      </div>
                    ) : (
                      <>
                        <div className="result-topline">
                          <div>
                            <span className="result-kicker">
                              {result.mode === 'ai-assisted' ? `${(config?.externalProvider || 'AI').toUpperCase()} + HEURISTIC ENGINE` : 'DETERMINISTIC HEURISTIC ENGINE'}
                            </span>
                            <h2>Threat Assessment Findings</h2>
                          </div>
                          <div className={`risk-badge risk-${result.level?.toLowerCase()}`}>
                            <div className="risk-badge-icon">
                              {result.level?.toLowerCase() === 'high' ? <ShieldAlertIcon /> : result.level?.toLowerCase() === 'low' ? <ShieldCheckIcon /> : <AlertCircleIcon />}
                            </div>
                            <div className="risk-badge-text">
                              <small>ASSESSED RISK</small>
                              <strong>{result.level?.toUpperCase()}</strong>
                            </div>
                          </div>
                        </div>

                        {/* URL Checks if present */}
                        {result.urlChecks && (
                          <div className="url-checks-container">
                            <div className="url-checks-header">
                              <div className="url-checks-title">
                                <GlobeIcon />
                                <h3>Embedded Links Threat Intelligence</h3>
                              </div>
                              <span className="vendor-tag">{result.urlChecks.configured ? 'VirusTotal Live Feed' : 'Offline / Unconfigured'}</span>
                            </div>
                            <div className="url-checks-list">
                              {result.urlChecks.results.map((item, index) => (
                                <div className={`url-check-item url-status-${item.status}`} key={`${item.url}-${index}`}>
                                  <div className="url-info">
                                    <code className="url-code">{item.url}</code>
                                    <div className="url-verdict">
                                      <span className="verdict-label">{urlCheckLabels[item.status] || item.status}</span>
                                      {Number.isInteger(item.detections) && (
                                        <span className="vendor-stats">
                                          {item.malicious} malicious · {item.suspicious} suspicious out of {item.total} AV engines
                                        </span>
                                      )}
                                      {item.message && <span className="item-msg">{item.message}</span>}
                                    </div>
                                  </div>
                                  {item.reportUrl && (
                                    <a className="report-link" href={item.reportUrl} target="_blank" rel="noreferrer">
                                      VirusTotal Dossier <ArrowUpRightIcon />
                                    </a>
                                  )}
                                </div>
                              ))}
                            </div>
                            {result.urlChecks.skipped > 0 && (
                              <p className="url-check-note">{result.urlChecks.skipped} additional links queued to respect API rate boundaries.</p>
                            )}
                          </div>
                        )}

                        {/* AI Summary or Heuristic Score */}
                        {result.mode === 'ai-assisted' ? (
                          <div className="assessment-summary-card">
                            <div className="summary-badge-row">
                              <span className="threat-type-pill">{result.assessment?.scamType || 'Suspicious Pattern'}</span>
                              <span className="ai-disclaimer">Automated Threat Synthesis</span>
                            </div>
                            <p className="summary-text">{result.assessment?.summary}</p>

                            {/* Attack Sequence Chain */}
                            {result.assessment?.attackChain?.length > 0 && (
                              <div className="attack-chain-section">
                                <h3>Social Engineering Attack Sequence</h3>
                                <p className="chain-subhead">Step-by-step breakdown of how the conversation establishes manipulation</p>
                                <div className="chain-timeline">
                                  {result.assessment.attackChain.map((step, index) => (
                                    <div className="chain-step-card" key={`${step.stage}-${index}`}>
                                      <div className="step-indicator">
                                        <span className="step-index">{String(index + 1).padStart(2, '0')}</span>
                                        <span className="step-line" />
                                      </div>
                                      <div className="step-body">
                                        <strong>{step.stage}</strong>
                                        <q className="step-quote">&ldquo;{step.evidence}&rdquo;</q>
                                        <small className="step-interp">{step.interpretation}</small>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="score-summary-card">
                            <div className="score-header">
                              <span>Heuristic Threat Metric Score</span>
                              <strong>{result.score} <span className="score-denominator">/ 100</span></strong>
                            </div>
                            <div className="score-track" role="progressbar" aria-valuenow={result.score} aria-valuemin="0" aria-valuemax="100">
                              <div className={`score-fill fill-${result.level?.toLowerCase()}`} style={{ width: `${Math.min(100, Math.max(5, result.score))}%` }} />
                            </div>
                            <small className="score-note">Rule-based score matches weighted heuristic indicators. High score indicates elevated social engineering signals.</small>
                          </div>
                        )}

                        {/* High Risk Critical Incident Response Panel */}
                        {result.level === 'High' && (() => {
                          const financialRisk = [...(result.categories || []), result.assessment?.scamType || ''].some((category) => /payment|upi|financial|bank/i.test(category))
                          return (
                            <div className="emergency-response-panel">
                              <div className="emergency-header">
                                <span className="emergency-icon"><AlertCircleIcon /></span>
                                <div>
                                  <span className="emergency-kicker">CRITICAL ACTION PROTOCOL</span>
                                  <h3>{financialRisk ? 'Immediate Financial Defense & Fraud Containment' : 'Account & Device Containment Protocol'}</h3>
                                </div>
                              </div>
                              <p className="emergency-description">
                                {financialRisk
                                  ? 'If banking details or OTP was shared, immediately contact your bank’s 24x7 emergency fraud line to freeze affected accounts/cards, then report directly to the official cyber fraud authorities.'
                                  : 'Immediately stop engagement. Do not click links or install remote access software. Access the affected platform via official verified applications to change passwords and revoke active sessions.'}
                              </p>
                              {financialRisk && (
                                <div className="emergency-action-buttons">
                                  <a href="tel:1930" className="helpline-btn">
                                    <span className="helpline-badge">CALL HELPLINE</span>
                                    <strong>National Cyber Crime Helpline: 1930</strong>
                                  </a>
                                  <a href="https://www.cybercrime.gov.in/" target="_blank" rel="noreferrer" className="portal-btn">
                                    National Cybercrime Reporting Portal <ArrowUpRightIcon />
                                  </a>
                                </div>
                              )}
                            </div>
                          )
                        })()}

                        {/* Two Columns: Signals & Advice */}
                        <div className="findings-grid">
                          <div className="signals-panel">
                            <div className="panel-header">
                              <h3>Identified Threat Signals</h3>
                              <span className="signal-count">{result.signals.length} Flags</span>
                            </div>
                            {result.signals.length ? (
                              <ul className="signal-cards-list">
                                {result.signals.map((signal, index) => (
                                  <li className="signal-card" key={`${signal.name}-${index}`}>
                                    <div className="signal-marker">!</div>
                                    <div className="signal-content">
                                      <div className="signal-title-row">
                                        <strong>{signal.name}</strong>
                                        {signal.points > 0 && <span className="signal-points">+{signal.points} pts</span>}
                                      </div>
                                      {signal.evidence && (
                                        <div className="signal-quote">
                                          <span>Evidence:</span> &ldquo;{signal.evidence}&rdquo;
                                        </div>
                                      )}
                                      {signal.explanation && <p className="signal-desc">{signal.explanation}</p>}
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <div className="clean-signals">
                                <ShieldCheckIcon />
                                <p>No overt social engineering or suspicious patterns matched configured threat heuristics.</p>
                              </div>
                            )}
                          </div>

                          <div className="advice-panel">
                            <div className="panel-header">
                              <h3>Recommended Security Protocol</h3>
                              <span className="advice-badge">Action Plan</span>
                            </div>
                            <ol className="advice-list">
                              {result.advice.map((item, index) => (
                                <li key={index}>
                                  <span className="advice-num">{index + 1}</span>
                                  <p>{item}</p>
                                </li>
                              ))}
                            </ol>
                          </div>
                        </div>

                        {/* Bottom Utility Bar */}
                        <div className="report-action-bar">
                          <span className="action-bar-label">Export or forward this assessment to your security team or trusted contact.</span>
                          <button type="button" className="copy-report-btn" onClick={() => copyAssessment(result)}>
                            {copyState ? <CheckIcon /> : <CopyIcon />} {copyState || 'Copy Full Intelligence Report'}
                          </button>
                        </div>
                      </>
                    )}
                  </section>
                )}
              </form>
            )}

            {/* URL TAB */}
            {activeTool === 'url' && (
              <section className="url-tool-container" role="tabpanel" id="url-panel" aria-labelledby="url-tab">
                <div className="tool-intro">
                  <span className="section-kicker">URL REPUTATION INSPECTOR</span>
                  <h3>Direct Domain & Link Security Lookup</h3>
                  <p>Submit a complete web address for multi-engine reputation analysis and malware taxonomy through VirusTotal.</p>
                </div>

                <form onSubmit={handleCheckUrl} className="url-lookup-form">
                  <div className="url-input-group">
                    <span className="input-prefix-icon"><GlobeIcon /></span>
                    <input
                      id="url-input"
                      type="url"
                      inputMode="url"
                      placeholder="https://example.com/login-verify"
                      value={urlInput}
                      onChange={(event) => {
                        setUrlInput(event.target.value)
                        setUrlResult(null)
                        setUrlError('')
                      }}
                      maxLength={2048}
                      required
                    />
                  </div>
                  <button type="submit" className="primary-button" disabled={urlChecking || !urlInput.trim()}>
                    {urlChecking ? <><span className="btn-spinner" /> Scanning…</> : <>Inspect URL <ArrowUpRightIcon /></>}
                  </button>
                </form>

                <p className="tool-disclosure">
                  {config?.virusTotalAvailable ? (
                    <>Live VirusTotal integration enabled. Queries check malware signatures, phishing heuristics, and community reports. Avoid submitting private password-reset tokens.</>
                  ) : (
                    <>VirusTotal API key is not configured on the server. Configure <code>VIRUSTOTAL_API_KEY</code> in <code>.env</code> for live intelligence.</>
                  )}
                </p>

                {urlError && <div className="error-alert" role="alert"><AlertCircleIcon /><p>{urlError}</p></div>}

                {urlResult && (
                  <div className="url-standalone-results">
                    {urlResult.results.map((item, index) => (
                      <div className={`url-check-item url-status-${item.status}`} key={`${item.url}-${index}`}>
                        <div className="url-info">
                          <code className="url-code">{item.url}</code>
                          <div className="url-verdict">
                            <strong className="verdict-label">{urlCheckLabels[item.status] || item.status}</strong>
                            {Number.isInteger(item.detections) && (
                              <span className="vendor-stats">
                                {item.malicious} malicious · {item.suspicious} suspicious across {item.total} security scanners
                              </span>
                            )}
                            {item.message && <span className="item-msg">{item.message}</span>}
                          </div>
                        </div>
                        {item.reportUrl && (
                          <a className="report-link" href={item.reportUrl} target="_blank" rel="noreferrer">
                            View VirusTotal Report <ArrowUpRightIcon />
                          </a>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </section>
            )}

            {/* MEDIA TAB */}
            {activeTool === 'media' && (
              <section className="media-tool-container" role="tabpanel" id="media-panel" aria-labelledby="media-tab">
                <div className="tool-intro">
                  <span className="section-kicker">MULTI-MODAL FORENSICS</span>
                  <h3>Synthetic Media & Deepfake Inspector</h3>
                  <p>Examine video clips, audio voice notes, and images for AI-generation artifacts, optical anomalies, C2PA digital provenance, and fraudulent claims.</p>
                </div>

                <div className="media-dropzone">
                  <input
                    id="media-file"
                    className="sr-only"
                    type="file"
                    accept="image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm,audio/mpeg,audio/mp4,audio/wav,audio/ogg,audio/flac,audio/webm"
                    onChange={handleMediaChange}
                    disabled={isAnalyzing || mediaPreparing}
                  />
                  <label htmlFor="media-file" className="dropzone-label">
                    <span className="dropzone-icon"><UploadIcon /></span>
                    <strong>{mediaFile ? 'Choose a Different Media File' : 'Click to Upload Media or Drag & Drop'}</strong>
                    <small>Supports MP4, WebM, JPEG, PNG, MP3, WAV (Max 20 MB)</small>
                  </label>
                </div>

                {mediaPreparing && <div className="media-loading-status"><span className="btn-spinner" /> Preparing media frames for forensic review…</div>}

                {mediaFile && (
                  <div className="media-preview-card">
                    <div className="preview-media-container">
                      {mediaFile.type.startsWith('video/') ? (
                        <video src={mediaPreviewUrl} controls preload="metadata" />
                      ) : mediaFile.type.startsWith('audio/') ? (
                        <audio src={mediaPreviewUrl} controls preload="metadata" />
                      ) : (
                        <img src={mediaPreviewUrl} alt="Upload preview" />
                      )}
                    </div>
                    <div className="preview-meta">
                      <strong>{mediaFile.name}</strong>
                      <small>{(mediaFile.size / (1024 * 1024)).toFixed(2)} MB · {mediaFile.type.startsWith('video/') ? `${mediaFrames.length} sampled temporal frames` : mediaFile.type.startsWith('audio/') ? 'Audio file for Whisper analysis' : 'High-resolution still image'}</small>
                    </div>
                    <button
                      type="button"
                      className="remove-btn"
                      onClick={() => {
                        setMediaFile(null)
                        setMediaFrames([])
                        setMediaDuration(null)
                        setMediaPreviewUrl('')
                        setMediaResult(null)
                        setMediaError('')
                      }}
                      disabled={isAnalyzing}
                    >
                      Remove
                    </button>
                  </div>
                )}

                <div className="media-action-row">
                  <button
                    type="button"
                    className="primary-button"
                    onClick={handleAnalyzeMedia}
                    disabled={!mediaFile || (!mediaFrames.length && !mediaFile.type.startsWith('audio/')) || isAnalyzing || mediaPreparing}
                  >
                    {isAnalyzing ? <><span className="btn-spinner" /> Inspecting Media Content…</> : <>Execute Multi-Modal Analysis <ArrowUpRightIcon /></>}
                  </button>
                </div>

                {mediaError && <div className="error-alert" role="alert"><AlertCircleIcon /><p>{mediaError}</p></div>}

                {/* Media Analysis Result */}
                {mediaResult && (
                  <section className="results-card media-results-card" aria-live="polite">
                    <div className="result-topline">
                      <div>
                        <span className="result-kicker">
                          {mediaResult.mediaType.toUpperCase()} CHECK RESULT
                        </span>
                        <h2>Media Assessment</h2>
                      </div>
                      <div className={`origin-badge origin-${mediaResult.authenticity?.verdict}`}>
                        {mediaResult.authenticity?.verdict === 'likely_ai_generated' ? (
                          <>🔴 {mediaOriginLabels.likely_ai_generated}</>
                        ) : mediaResult.authenticity?.verdict === 'no_strong_ai_signal' ? (
                          <>🟢 {mediaOriginLabels.no_strong_ai_signal}</>
                        ) : (
                          <>🟡 {mediaOriginLabels[mediaResult.authenticity?.verdict] || mediaOriginLabels.unclear}</>
                        )}
                      </div>
                    </div>

                    {/* Simple summary banner */}
                    <div className={`simple-verdict-card verdict-${mediaResult.authenticity?.verdict}`}>
                      <div className="verdict-main">
                        <strong>
                          {mediaResult.authenticity?.verdict === 'likely_ai_generated'
                            ? 'Warning: High chance this audio/media was generated by an AI tool.'
                            : mediaResult.authenticity?.verdict === 'no_strong_ai_signal'
                              ? 'Looks clean: No common AI generator markers found.'
                              : 'Could not verify origin: Audio sound alone cannot prove if this is real or synthetic.'}
                        </strong>
                        <p>{mediaResult.summary}</p>
                      </div>
                    </div>

                    {mediaResult.aiDetection?.status && mediaResult.aiDetection.status !== 'completed' && mediaResult.aiDetection.status !== 'not_supported' && mediaDetectionErrors[mediaResult.aiDetection.status] && (
                      <div className="provider-status-note">
                        <small>ℹ️ {mediaDetectionErrors[mediaResult.aiDetection.status]}</small>
                      </div>
                    )}

                    {/* Quick Human-Readable Highlights */}
                    <div className="media-quick-grid">
                      {/* Detection clues */}
                      {mediaResult.authenticity?.reasons?.length > 0 && (
                        <div className="quick-info-card highlight-card">
                          <span className="card-mini-title">AI DETECTION CLUES</span>
                          <ul className="simple-bullet-list">
                            {mediaResult.authenticity.reasons.map((reason, idx) => (
                              <li key={idx}><strong>{reason}</strong></li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Speech / Transcript */}
                      <div className="quick-info-card">
                        <span className="card-mini-title">SPOKEN WORDS / TRANSCRIPT</span>
                        {mediaResult.transcript ? (
                          <blockquote className="simple-transcript">&ldquo;{mediaResult.transcript}&rdquo;</blockquote>
                        ) : (
                          <p className="dim-text">No spoken words detected (sound effects, robotic sounds, or silence).</p>
                        )}
                      </div>

                      {/* Scam Warnings in audio */}
                      <div className="quick-info-card">
                        <span className="card-mini-title">SCAM OR THREAT DETECTED?</span>
                        {mediaResult.safetyConcerns?.length > 0 ? (
                          <ul className="simple-bullet-list warning-list">
                            {mediaResult.safetyConcerns.map((concern, idx) => (
                              <li key={idx}>{concern}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="clean-text">✓ No scam requests, OTP demands, or payment fraud found.</p>
                        )}
                      </div>

                      {/* What you should do */}
                      <div className="quick-info-card action-card">
                        <span className="card-mini-title">WHAT YOU SHOULD DO</span>
                        <p>
                          {mediaResult.authenticity?.verdict === 'likely_ai_generated'
                            ? 'Never send money, OTPs, or passwords based on voice notes alone. Always call the real person directly on their trusted phone number to verify.'
                            : 'If anyone unexpected asks for sudden favors or financial assistance, verify their identity independently before taking action.'}
                        </p>
                      </div>
                    </div>

                    {/* Visual details for images/videos */}
                    {Object.keys(mediaResult.visualChecks || {}).length > 0 && (
                      <div className="forensic-block">
                        <div className="block-title">
                          <MediaIcon />
                          <h3>Visual Forensic Observations</h3>
                        </div>
                        <div className="visual-checks-grid">
                          {Object.entries(mediaResult.visualChecks).map(([key, items]) => (
                            <div className="visual-check-card" key={key}>
                              <strong>{({ anatomy_details: 'Anatomy & Biometrics', text_and_symbols: 'Text & Typography', spatial_geometry: 'Spatial Geometry', lighting_and_reflections: 'Lighting & Physics', texture_consistency: 'Texture Consistency' })[key] || key}</strong>
                              <p>{items.join('; ')}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </section>
                )}
              </section>
            )}
          </section>
        </div>

        {/* Curated Threat Scenario Presets */}
        {activeTool === 'message' && !result && (
          <section className="scenarios-section" id="scenarios" aria-label="Curated Threat Scenarios">
            <div className="scenarios-header">
              <span className="section-kicker">THREAT LIBRARY</span>
              <h3>Explore Common Attack Vectors</h3>
              <p>Test the detection engine against realistic fraudulent scenarios observed in the wild:</p>
            </div>
            <div className="scenarios-grid">
              {threatScenarios.map((scenario) => (
                <button
                  type="button"
                  key={scenario.label}
                  className="scenario-card-btn"
                  onClick={() => loadExample(scenario)}
                >
                  <div className="scenario-top">
                    <span className="scenario-badge">{scenario.badge}</span>
                    <span className="scenario-category">{scenario.category}</span>
                  </div>
                  <strong>{scenario.label}</strong>
                  <p>&ldquo;{scenario.message.slice(0, 85)}…&rdquo;</p>
                  <span className="scenario-action">Load into Analyzer <ArrowUpRightIcon /></span>
                </button>
              ))}
            </div>
          </section>
        )}

        {/* Security Assurance Banner */}
        <aside className="security-banner">
          <div className="banner-icon"><ShieldCheckIcon /></div>
          <div className="banner-text">
            <strong>When in doubt, verify independently through trusted out-of-band channels.</strong>
            <p>ScamShield AI provides automated heuristic signals and confidence ratings. Never use telephone numbers or URLs contained in suspicious messages to verify authenticity.</p>
          </div>
        </aside>
      </main>

      {/* Enterprise Footer */}
      <footer className="footer">
        <div className="footer-container">
          <div className="footer-brand-col">
            <div className="brand footer-brand">
              <span className="brand-mark"><ShieldIcon /></span>
              <span>SCAM<span className="brand-highlight">SHIELD</span></span>
            </div>
            <p>Enterprise threat intelligence and fraud prevention platform built with zero-knowledge architecture.</p>
          </div>

          <div className="footer-links-col">
            <h4>Security Architecture</h4>
            <span>Multi-Modal Groq / Gemini AI</span>
            <span>VirusTotal Threat Intelligence</span>
            <span>C2PA Digital Provenance</span>
          </div>

          <div className="footer-links-col">
            <h4>Incident Hotlines</h4>
            <a href="tel:1930">India Cyber Fraud: 1930</a>
            <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">cybercrime.gov.in</a>
            <a href="https://reportfraud.ftc.gov" target="_blank" rel="noreferrer">US FTC Report Fraud</a>
          </div>
        </div>
        <div className="footer-bottom">
          <span>&copy; {new Date().getFullYear()} ScamShield AI Defense Systems. All rights reserved.</span>
          <span>Zero-Log Architecture · Client-Side Frame Sampling · End-to-End Encrypted Feeds</span>
        </div>
      </footer>
    </div>
  )
}

export default App