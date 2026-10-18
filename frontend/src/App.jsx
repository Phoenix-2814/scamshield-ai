import { useEffect, useRef, useState } from 'react'
import { analyzeMessageRequest, getAnalyzerConfig } from './api'
import './App.css'

const examples = [
  { label: 'Fake bank alert', message: 'URGENT: Your bank account will be blocked. Share your OTP immediately: https://secure-check.example' },
  { label: 'UPI collect trick', message: 'Scan this QR to receive your refund. Approve the UPI collect request and enter your UPI PIN.' },
  { label: 'Family login request', message: 'Hi I am your brother. My phone is switched off can you send me the login details of my account?' },
  { label: 'New number conversation', message: 'Sender: It is your brother. This is my new number; the old phone is being repaired.\nSender: I cannot call right now, but I need a quick favor.\nMe: What do you need?\nSender: Open the bank app and read me the notification that appears. I will explain after.' },
  { label: 'Job fee message', message: 'Work from home! Earn 5000 per day. Pay a small registration fee for the job to start today.' },
  { label: 'Everyday message', message: 'Hi! Are we still meeting at the library at 4 PM?' },
]

function App() {
  const [message, setMessage] = useState('')
  const [result, setResult] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [config, setConfig] = useState(null)
  const [copyState, setCopyState] = useState('')
  const configRequest = useRef(null)

  useEffect(() => {
    configRequest.current = getAnalyzerConfig().catch(() => ({ aiAssistedAvailable: false }))
    configRequest.current.then(setConfig)
  }, [])

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
  }

  function loadExample(example) {
    setMessage(example.message)
    setResult(null)
  }

  async function copyAssessment(analysis) {
    const lines = [
      `ScamShield assessment: ${analysis.level} risk`,
      analysis.assessment ? `${analysis.assessment.scamType}: ${analysis.assessment.summary}` : '',
      'Signals:',
      ...analysis.signals.map((signal) => `- ${signal.name}${signal.evidence ? ` | Evidence: ${signal.evidence}` : ''}${signal.explanation ? ` | ${signal.explanation}` : ''}`),
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
    <div className="app">
      <header className="navbar">
        <a className="brand" href="#top" aria-label="ScamShield home">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>scam<span className="brand-accent">shield</span></span>
        </a>
        <span className="status"><span className="status-dot" /> Message history disabled</span>
      </header>

      <main className="hero" id="top">
        <div className="eyebrow">SCAMSHIELD <span>/</span> MESSAGE RISK ANALYSIS</div>
        <h1>Analyze a suspicious message</h1>
        <p className="subtitle">Trace impersonation, pretexts, and unsafe requests across a conversation, even when the sender avoids obvious scam keywords.</p>

        <form className="analyzer" onSubmit={handleAnalyze}>
          <div className="field-heading">
            <label htmlFor="message">Message or conversation</label>
            <span className="field-hint">Paste multiple messages to analyze context</span>
          </div>
          <textarea
            id="message"
            value={message}
            onChange={handleChange}
            disabled={isAnalyzing}
            placeholder={'Paste a message or a conversation transcript...'}
            rows={6}
            maxLength={5000}
            aria-describedby="privacy-note"
          />
          <div className="form-footer">
            <span className="char-count">{message.length.toLocaleString()} / 5,000</span>
            <div className="actions">
              <button type="button" className="secondary-button" onClick={handleClear} disabled={isAnalyzing || (!message && !result)}>Clear</button>
              <button type="submit" className="primary-button" disabled={isAnalyzing}>{isAnalyzing ? 'Analyzing...' : 'Analyze message'}</button>
            </div>
          </div>
          <p className="privacy" id="privacy-note"><span aria-hidden="true">Privacy:</span> {config?.aiAssistedAvailable ? <>Sent to ScamShield and Google Gemini for analysis. Gemini interaction state storage is disabled; Google abuse monitoring and data policies still apply. <a href="https://ai.google.dev/gemini-api/docs/zdr" target="_blank" rel="noreferrer">Review Gemini data handling</a>. ScamShield does not save message history.</> : <>Sent to ScamShield for rules-based analysis. ScamShield does not save message history.</>}</p>

          {result && (
            <section className={`results${result.error ? ' results-error' : ''}`} aria-live="polite" aria-atomic="true">
              {result.error ? <p className="error-message">{result.error}</p> : <>
                <div className="result-topline">
                  <div>
                    <p className="result-kicker">{result.mode === 'ai-assisted' ? 'GEMINI + RULE ENGINE' : 'RULE ENGINE'}</p>
                    <h2>Assessment</h2>
                  </div>
                  <div className={`risk-badge risk-${result.level.toLowerCase()}`}><span><small>RISK LEVEL</small><strong>{result.level}</strong></span></div>
                </div>
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
        </form>

        {!result && <div className="examples"><span>LOAD EXAMPLE</span>{examples.map((example) => <button type="button" key={example.label} onClick={() => loadExample(example)}>{example.label}</button>)}</div>}

        <aside className="reminder"><span className="reminder-label">SAFETY GUIDANCE</span><p><strong>Verify unexpected requests through a trusted channel.</strong> Contact the person or organization using independently verified details.</p></aside>
      </main>

      <footer><span>Â© {new Date().getFullYear()} ScamShield</span><span>Think clearly. Click carefully.</span></footer>
    </div>
  )
}

export default App
