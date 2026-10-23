const rules = [
  { name: 'Asks you to send account login details', category: 'Credential request', pattern: /\b(?:send|share|give|tell|forward|text|message)\b.{0,60}\b(?:login details|log[ -]?in (?:details|credentials|information|info)|account credentials|account password|username and password|user id and password)\b|\b(?:login details|log[ -]?in (?:details|credentials|information|info)|account credentials|account password|username and password|user id and password)\b.{0,40}\b(?:send|share|give|tell|forward|text|message)\b/i, points: 40, advice: 'Never send account login details in a message. Verify the person using a number or channel you already know; if their phone is unavailable, contact them another way.' },
  { name: 'Asks for a secret code or credential', category: 'Credential theft', pattern: /\b(otp|one[- ]time password|upi pin|atm pin|card pin|cvv|password|passcode)\b/i, points: 30, advice: 'Never share an OTP, UPI PIN, card PIN, CVV, or password. A UPI PIN is used to send money, not receive it.' },
  { name: 'Creates urgency or threatens account action', category: 'Pressure tactic', pattern: /\b(urgent|immediately|within \d+ minutes?|account blocked|account suspended|will be blocked|act now|expires today|last warning|final notice)\b/i, points: 20, advice: 'Pause. Contact the organization using its official app or a number you find independently.' },
  { name: 'Requests a payment, fee, or transfer', category: 'Payment request', pattern: /\b(send money|transfer money|pay now|processing fee|pay (?:a |the )?fee|deposit now|pay to receive|release fee|customs fee|delivery fee|registration fee)\b/i, points: 25, advice: 'Do not pay through message instructions. Check fees in the official service or app.' },
  { name: 'Promises a prize or unexpected reward', category: 'Unexpected reward', pattern: /\b(you (?:have )?won|claim your prize|free gift|cashback reward|lottery winner|congratulations.{0,30}prize|lucky draw)\b/i, points: 20, advice: 'Treat unexpected prizes with suspicion, especially if a fee or personal details are requested.' },
  { name: 'Uses KYC or account-verification pressure', category: 'Account impersonation', pattern: /\b(verify your account|kyc (?:update|expired|verification|suspended)|update your kyc|click here to verify|pan card.{0,20}(?:block|expire|update))\b/i, points: 25, advice: 'Check KYC status only in the official app or website. Do not follow a message link to sign in.' },
  { name: 'Uses a UPI collect request or payment QR to send money', category: 'UPI payment trick', pattern: /\b(upi collect request|collect request|scan (?:this )?(?:qr|qr code) to (?:receive|get|claim)|enter (?:your )?upi pin to (?:receive|get)|approve (?:the )?upi request|request money on upi)\b/i, points: 30, advice: 'Receiving money does not require your UPI PIN. Decline unexpected collect requests and QR payment prompts.' },
  { name: 'Requests remote access or an app installation', category: 'Device takeover', pattern: /\b(install (?:this )?(?:apk|app)|download (?:this )?apk|screen sharing app|share your screen|remote access app|anydesk|teamviewer|quick.?support)\b/i, points: 30, advice: 'Do not install an app or share your screen at a stranger’s request. Use your device maker’s official support channel.' },
  { name: 'Offers a job with an upfront fee or guaranteed income', category: 'Job scam pattern', pattern: /\b(work from home|part[- ]time job|daily income|guaranteed (?:income|returns)|registration fee for (?:the )?job|pay to (?:get|start) (?:the )?job|earn \d+ per day)\b/i, points: 20, advice: 'Verify the employer through its official careers site. Be wary of upfront fees and guaranteed earnings.' },
  { name: 'Contains a web link', category: 'Link present', pattern: /(?:https?:\/\/|www\.)[^\s<>()]+/i, points: 8, advice: 'Do not open unexpected links. Check the full domain and visit the official site by typing its address yourself.' }
]

const shortenerHosts = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at'])

export function extractUrls(text) {
  const matches = text.match(/(?:https?:\/\/|www\.)[^\s<>()]+/gi) ?? []
  const urls = []
  const seen = new Set()

  for (const raw of matches) {
    const cleaned = raw.replace(/[.,!?;:)}\]]+$/, '')
    const normalized = cleaned.startsWith('www.') ? `http://${cleaned}` : cleaned
    try {
      const parsed = new URL(normalized)
      if (!['http:', 'https:'].includes(parsed.protocol) || seen.has(normalized)) continue
      seen.add(normalized)
      urls.push(normalized)
    } catch {
      // The rules engine separately reports malformed links.
    }
  }

  return urls
}

function inspectLinks(text) {
  const matches = text.match(/(?:https?:\/\/|www\.)[^\s<>()]+/gi) ?? []
  const findings = []

  for (const raw of matches) {
    const cleaned = raw.replace(/[.,!?;:)}\]]+$/, '')
    try {
      const parsed = new URL(cleaned.startsWith('www.') ? `http://${cleaned}` : cleaned)
      const host = parsed.hostname.toLowerCase()
      if (shortenerHosts.has(host)) {
        findings.push({ name: 'Link hides its final destination', category: 'Shortened link', points: 18, evidence: cleaned, advice: 'A shortened link hides the destination. Do not open it unless you can verify who sent it and where it leads.' })
      } else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
        findings.push({ name: 'Link uses a numeric IP address', category: 'Unusual link', points: 18, evidence: cleaned, advice: 'A numeric IP address is unusual for a customer-facing login. Do not enter credentials on this page.' })
      } else if (host.startsWith('xn--') || host.split('.').some((part) => part.startsWith('xn--'))) {
        findings.push({ name: 'Link contains an internationalized domain name', category: 'Unusual link', points: 18, evidence: cleaned, advice: 'Some lookalike domains use characters that resemble familiar letters. Verify the domain independently.' })
      }
    } catch {
      findings.push({ name: 'Link could not be parsed cleanly', category: 'Unusual link', points: 12, evidence: cleaned, advice: 'Treat malformed or incomplete links cautiously. Do not open the link to test it.' })
    }
  }
  return findings
}

export function analyzeMessage(message) {
  if (typeof message !== 'string' || !message.trim()) throw new Error('Please enter a message to analyze.')
  const text = message.trim()
  const signals = rules.filter((rule) => rule.pattern.test(text)).map((rule) => ({
    name: rule.name,
    category: rule.category,
    points: rule.points,
    evidence: text.match(rule.pattern)?.[0] ?? '',
    advice: rule.advice
  }))
  signals.push(...inspectLinks(text))

  const score = Math.min(signals.reduce((total, signal) => total + signal.points, 0), 100)
  const hasCredentialRequest = signals.some((signal) => signal.category === 'Credential theft')
  const hasExplicitCredentialRequest = signals.some((signal) => signal.category === 'Credential request')
  const hasPressureTactic = signals.some((signal) => signal.category === 'Pressure tactic')
  const hasPaymentTrick = signals.some((signal) => signal.category === 'UPI payment trick')
  const level = score >= 60 || hasExplicitCredentialRequest || (hasCredentialRequest && hasPressureTactic) || hasPaymentTrick
    ? 'High'
    : score >= 30 ? 'Medium' : 'Low'

  return {
    score,
    level,
    categories: [...new Set(signals.map((signal) => signal.category))],
    signals,
    advice: signals.length
      ? [...new Set(signals.map((signal) => signal.advice))]
      : ['No configured warning patterns were detected.', 'This does not prove the message is safe. Verify unexpected requests independently.']
  }
}
