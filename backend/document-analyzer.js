import AdmZip from 'adm-zip'
import { PDFParse } from 'pdf-parse'
import { analyzeMessage, extractUrls } from '../shared/detector.js'
import { checkMessageUrls } from './virustotal.js'
import { classifyMessageWithGemini } from './gemini-classifier.js'
import { classifyMessageWithGroq } from './groq-classifier.js'

const maxDocumentBytes = 25 * 1024 * 1024 // 25 MB limit
const maxExtractedTextChars = 15000

// Supported extensions mapping
const extensionTypes = {
  '.docx': 'Word Document',
  '.doc': 'Legacy Word Document',
  '.docm': 'Macro-Enabled Word Document',
  '.dotx': 'Word Template',
  '.dotm': 'Macro-Enabled Word Template',
  '.xlsx': 'Excel Spreadsheet',
  '.xls': 'Legacy Excel Spreadsheet',
  '.xlsm': 'Macro-Enabled Excel Spreadsheet',
  '.xltx': 'Excel Template',
  '.xltm': 'Macro-Enabled Excel Template',
  '.csv': 'CSV Data File',
  '.tsv': 'TSV Data File',
  '.pptx': 'PowerPoint Presentation',
  '.ppt': 'Legacy PowerPoint Presentation',
  '.pptm': 'Macro-Enabled PowerPoint Presentation',
  '.potx': 'PowerPoint Template',
  '.potm': 'Macro-Enabled PowerPoint Template',
  '.pdf': 'PDF Document',
  '.txt': 'Plain Text File',
  '.rtf': 'Rich Text Document',
  '.md': 'Markdown Document',
  '.markdown': 'Markdown Document',
  '.log': 'Log File',
  '.json': 'JSON Document',
  '.xml': 'XML Document',
  '.html': 'HTML Document',
  '.htm': 'HTML Document',
  '.eml': 'Email Message File',
  '.msg': 'Outlook Message File',
  '.zip': 'ZIP Archive'
}

const dangerousPayloadExtensions = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse',
  '.wsf', '.wsh', '.ps1', '.ps2', '.hta', '.jar', '.msi', '.reg',
  '.dll', '.cpl', '.iso', '.img', '.lnk', '.pif'
])

export function getSupportedExtensions() {
  return Object.keys(extensionTypes)
}

function getFileExtension(filename = '') {
  const match = filename.toLowerCase().match(/\.[a-z0-9]+$/)
  return match ? match[0] : ''
}

function stripXml(xml) {
  return xml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
}

function extractTextBetweenTags(xml, tagName) {
  const regex = new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)<\\/${tagName}>`, 'gi')
  const results = []
  let match
  while ((match = regex.exec(xml)) !== null) {
    const text = match[1].replace(/<[^>]+>/g, '').trim()
    if (text) results.push(text)
  }
  return results
}

function cleanExtractedText(text) {
  return text
    .normalize('NFC')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * Inspect raw buffer for dangerous executables masquerading as documents.
 */
function inspectMagicBytes(bytes, filename) {
  if (bytes.length < 4) return null
  // Windows MZ header (EXE / DLL / SCR)
  if (bytes[0] === 0x4D && bytes[1] === 0x5A) {
    return {
      name: 'Disguised Windows Executable (PE/MZ)',
      category: 'File Spoofing',
      points: 95,
      evidence: `${filename} begins with MZ executable magic header`,
      explanation: 'The file has a document extension but contains a Windows executable binary. This is a severe technique used to deliver malware.',
      advice: 'Do not open or execute this file. Immediately isolate and delete it.'
    }
  }
  // Linux ELF
  if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) {
    return {
      name: 'Disguised Linux ELF Binary',
      category: 'File Spoofing',
      points: 95,
      evidence: `${filename} begins with ELF binary magic header`,
      explanation: 'The file is an ELF executable binary disguised with a document extension.',
      advice: 'Do not run or execute this file.'
    }
  }
  return null
}

/**
 * Check for double extensions like invoice.pdf.exe or invoice.xlsx.vbs
 */
function inspectFilenameSpoofing(filename) {
  const lower = filename.toLowerCase()
  if (filename.includes('\u202E')) {
    return {
      name: 'Right-to-Left Override (RTLO) Spoofing',
      category: 'File Spoofing',
      points: 95,
      evidence: 'Contains Unicode character U+202E (Right-to-Left Override)',
      explanation: 'Attackers use the RTLO character to reverse the visible extension, making an executable look like an innocent document (e.g. invoice[RTLO]fdp.exe appears as invoiceexe.pdf).',
      advice: 'Do not open this file. This is a deliberate concealment technique.'
    }
  }
  const doubleExtRegex = /(?:\.pdf|\.docx?|\.xlsx?|\.pptx?|\.txt|\.csv|\.rtf)\.(?:exe|vbs|bat|cmd|js|ps1|hta|scr|pif|msi|jar|iso|lnk)$/i
  if (doubleExtRegex.test(lower)) {
    return {
      name: 'Dangerous Double Extension',
      category: 'File Spoofing',
      points: 95,
      evidence: filename,
      explanation: 'The file hides an executable or script extension behind an apparent document name to trick users into executing code.',
      advice: 'Never click or launch this file. Verify real file extensions in your system settings.'
    }
  }
  return null
}

/**
 * Parse modern Office OpenXML (docx, xlsx, pptx) using AdmZip
 */
function parseOfficeXml(bytes, ext) {
  const zip = new AdmZip(bytes)
  const entries = zip.getEntries()
  const textParts = []
  const urls = new Set()
  const structuralSignals = []
  const embeddedObjects = []
  let hasVba = false
  let vbaRoutines = []
  let sheetCount = 0
  let slideCount = 0

  for (const entry of entries) {
    const entryName = entry.entryName
    const lowerName = entryName.toLowerCase()

    // 1. Detect VBA Macro Projects
    if (lowerName.includes('vbaproject.bin') || lowerName.includes('vbadata.xml')) {
      hasVba = true
      const vbaContent = entry.getData().toString('binary')
      const suspiciousRoutines = [
        'AutoOpen', 'AutoExec', 'Document_Open', 'Workbook_Open', 'Auto_Close', 'Workbook_BeforeClose',
        'Shell', 'WScript.Shell', 'PowerShell', 'URLDownloadToFile', 'VirtualAlloc', 'RtlMoveMemory',
        'CreateObject', 'cmd.exe', 'bitsadmin', 'certutil'
      ]
      const foundRoutines = suspiciousRoutines.filter((routine) => {
        const regex = new RegExp(`\\b${routine}\\b`, 'i')
        return regex.test(vbaContent)
      })
      if (foundRoutines.length > 0) {
        vbaRoutines = [...new Set([...vbaRoutines, ...foundRoutines])]
      }
    }

    // 2. Detect Embedded Objects & Executables
    if (lowerName.includes('embeddings/') || lowerName.includes('oleobject') || lowerName.includes('package.bin')) {
      embeddedObjects.push(entryName)
      const objExt = getFileExtension(entryName)
      if (dangerousPayloadExtensions.has(objExt) || lowerName.endsWith('.bin')) {
        structuralSignals.push({
          name: 'Suspicious Embedded Object / Payload',
          category: 'Embedded Object',
          points: 80,
          evidence: entryName,
          explanation: `Document packages an embedded object (${entryName}). Embedded binaries can execute arbitrary code upon user interaction.`,
          advice: 'Do not click or double-click embedded objects or icons inside this document.'
        })
      }
    }

    // 3. Extract External Relationships / Hyperlinks
    if (lowerName.endsWith('.rels')) {
      try {
        const relXml = entry.getData().toString('utf8')
        const relRegex = /<Relationship[^>]+Target="([^"]+)"[^>]*TargetMode="External"[^>]*\/>/gi
        let match
        while ((match = relRegex.exec(relXml)) !== null) {
          const target = match[1].trim()
          if (/^https?:\/\//i.test(target)) urls.add(target)
        }
      } catch {
        // ignore parse error on corrupt rels
      }
    }

    // 4. Word Text Extraction
    if (['.docx', '.docm', '.dotx', '.dotm'].includes(ext)) {
      if (lowerName === 'word/document.xml' || lowerName.startsWith('word/header') || lowerName.startsWith('word/footer')) {
        try {
          const xml = entry.getData().toString('utf8')
          const tTags = extractTextBetweenTags(xml, 'w:t')
          if (tTags.length) textParts.push(tTags.join(' '))
        } catch {
          // ignore
        }
      }
    }

    // 5. Excel Shared Strings, Sheets & Formula Inspection
    if (['.xlsx', '.xlsm', '.xltx', '.xltm'].includes(ext)) {
      if (lowerName === 'xl/sharedstrings.xml') {
        try {
          const xml = entry.getData().toString('utf8')
          const tTags = extractTextBetweenTags(xml, 't')
          if (tTags.length) textParts.push(tTags.join(' '))
        } catch {
          // ignore
        }
      }
      if (lowerName.startsWith('xl/worksheets/sheet') && lowerName.endsWith('.xml')) {
        sheetCount++
        try {
          const xml = entry.getData().toString('utf8')
          // Check for hidden or veryHidden sheets
          if (/state="(?:hidden|veryHidden)"/i.test(xml)) {
            structuralSignals.push({
              name: 'Hidden Worksheet Detected',
              category: 'Concealed Content',
              points: 35,
              evidence: entryName,
              explanation: 'Spreadsheet conceals one or more sheets (hidden or veryHidden). Attackers use hidden sheets to stash credential lures or staging formulas.',
              advice: 'Inspect all workbook sheets carefully before enabling formulas or editing.'
            })
          }
          // Inspect formulas for DDE / Formula Injection
          const formulas = extractTextBetweenTags(xml, 'f')
          for (const formula of formulas) {
            if (/^[=+\-@|%]?\s*(?:cmd|powershell|cscript|wscript|mshta|certutil|rundll32|regsvr32|bitsadmin|curl|wget)\b/i.test(formula) ||
                /DDEAUTO|DDE\(|EXEC\(/i.test(formula) ||
                /WEBSERVICE\([^)]*https?:\/\//i.test(formula)) {
              structuralSignals.push({
                name: 'Excel DDE / Formula Injection Command',
                category: 'Formula Injection',
                points: 90,
                evidence: formula.slice(0, 80),
                explanation: 'A formula invokes operating system commands or remote web services (CSV/DDE injection). Opening this can run arbitrary commands on your computer.',
                advice: 'Do not allow formulas to update or connect to external data. Close the file immediately.'
              })
              break
            }
          }
        } catch {
          // ignore
        }
      }
    }

    // 6. PowerPoint Slide Text Extraction
    if (['.pptx', '.pptm', '.potx', '.potm'].includes(ext)) {
      if (lowerName.startsWith('ppt/slides/slide') && lowerName.endsWith('.xml')) {
        slideCount++
        try {
          const xml = entry.getData().toString('utf8')
          const aTags = extractTextBetweenTags(xml, 'a:t')
          if (aTags.length) textParts.push(aTags.join(' '))
        } catch {
          // ignore
        }
      }
    }
  }

  // Evaluate VBA Macro Findings
  if (hasVba) {
    if (vbaRoutines.length > 0) {
      structuralSignals.push({
        name: 'VBA Macro with Auto-Execution Capability',
        category: 'Malicious Macro',
        points: 85,
        evidence: `Triggers: ${vbaRoutines.slice(0, 6).join(', ')}`,
        explanation: `Document contains embedded Visual Basic for Applications (VBA) code with auto-run triggers (${vbaRoutines.join(', ')}). Malicious macros are the leading vector for document-delivered ransomware and trojans.`,
        advice: 'Never click "Enable Content" or "Enable Macros". Standard business documents do not require macros to view.'
      })
    } else {
      structuralSignals.push({
        name: 'Embedded VBA Macro Project Detected',
        category: 'Macro Code',
        points: 50,
        evidence: 'vbaProject.bin present',
        explanation: 'Document contains an active macro project. Macros can execute code when opened in office applications.',
        advice: 'Open in Protected View only. Do not enable macros unless the author and source are fully verified.'
      })
    }
  }

  return {
    text: cleanExtractedText(textParts.join('\n')),
    urls: [...urls],
    structuralSignals,
    embeddedObjects,
    metadata: {
      hasVba,
      vbaRoutines,
      sheetCount: sheetCount || undefined,
      slideCount: slideCount || undefined
    }
  }
}

/**
 * Parse PDF document using pdf-parse and raw stream analysis
 */
async function parsePdf(bytes) {
  const structuralSignals = []
  const urls = new Set()
  let text = ''
  let pageCount = 0
  let pdfInfo = {}

  // 1. Text & metadata extraction via PDFParse
  try {
    const parser = new PDFParse({ data: bytes })
    const parsedText = await parser.getText()
    text = cleanExtractedText(parsedText.text || '')
    pageCount = parsedText.pages?.length || parsedText.total || 0
    try {
      const hyperlinks = await parser.getHyperlinks()
      if (Array.isArray(hyperlinks)) {
        for (const link of hyperlinks) {
          const href = typeof link === 'string' ? link : link?.url || link?.uri || ''
          if (/^https?:\/\//i.test(href)) urls.add(href)
        }
      }
    } catch {
      // getHyperlinks optional
    }
    try {
      pdfInfo = (await parser.getInfo())?.info || {}
    } catch {
      // getInfo optional
    }
  } catch {
    // If PDF text parsing fails due to obfuscation, continue with raw byte scan
  }

  // 2. Deep raw byte analysis for suspicious PDF objects
  const rawString = bytes.toString('binary')

  // Check /JavaScript or /JS
  if (/\/JavaScript\b|\/JS\b/i.test(rawString)) {
    structuralSignals.push({
      name: 'PDF Embedded JavaScript (/JavaScript)',
      category: 'Script Execution',
      points: 85,
      evidence: '/JavaScript object present in PDF structure',
      explanation: 'PDF contains embedded JavaScript code. Attackers use PDF scripts to exploit PDF reader vulnerabilities or redirect users to malicious portals.',
      advice: 'Disable JavaScript in your PDF reader settings before opening.'
    })
  }

  // Check /Launch (initiates external programs)
  if (/\/Launch\b/i.test(rawString)) {
    structuralSignals.push({
      name: 'PDF External Process Launch Action (/Launch)',
      category: 'Process Launch',
      points: 90,
      evidence: '/Launch object present',
      explanation: 'PDF contains a command instructing the PDF reader to launch an external executable or shell process on your computer.',
      advice: 'Do not open this PDF. Discard the file immediately.'
    })
  }

  // Check /OpenAction or /AA (auto-executes without click)
  if (/\/OpenAction\b|\/AA\b/i.test(rawString)) {
    structuralSignals.push({
      name: 'PDF Automatic Execution Action (/OpenAction)',
      category: 'Auto Action',
      points: 60,
      evidence: '/OpenAction or /AA trigger present',
      explanation: 'PDF is configured to automatically trigger an action, script, or URL redirect the moment the file is viewed.',
      advice: 'Open only in sandboxed viewers with active scripting disabled.'
    })
  }

  // Check /EmbeddedFiles
  if (/\/EmbeddedFiles\b/i.test(rawString)) {
    structuralSignals.push({
      name: 'PDF Hidden Embedded File Attachment',
      category: 'Embedded Payload',
      points: 65,
      evidence: '/EmbeddedFiles object present',
      explanation: 'PDF contains hidden file attachments embedded directly inside the document.',
      advice: 'Do not extract or execute attachments embedded inside the PDF.'
    })
  }

  // Extract raw /URI links
  const uriMatches = rawString.match(/\/URI\s*\(([^)]+)\)|\/URI\s*<([^>]+)>/gi) || []
  for (const match of uriMatches) {
    const cleanUrl = match.replace(/^\/URI\s*[<(]/i, '').replace(/[>)]$/, '').trim()
    if (/^https?:\/\//i.test(cleanUrl)) urls.add(cleanUrl)
  }

  return {
    text,
    urls: [...urls],
    structuralSignals,
    metadata: {
      pageCount,
      producer: pdfInfo.Producer || pdfInfo.Creator || undefined,
      creationDate: pdfInfo.CreationDate || undefined
    }
  }
}

/**
 * Parse CSV or TSV tabular files and scan for formula injection
 */
function parseCsv(bytes) {
  const content = bytes.toString('utf8')
  const lines = content.split(/\r?\n/)
  const structuralSignals = []
  const textParts = []

  for (let i = 0; i < Math.min(lines.length, 1000); i++) {
    const line = lines[i].trim()
    if (!line) continue
    textParts.push(line)

    // Formula injection regex: cells starting with =, +, -, @, | followed by commands
    const cells = line.split(/[,;\t]/)
    for (const cell of cells) {
      const trimmed = cell.trim().replace(/^["']|["']$/g, '')
      if (/^[=+\-@|%]\s*(?:cmd|powershell|cscript|wscript|mshta|certutil|rundll32|regsvr32|bitsadmin|curl|wget)\b/i.test(trimmed) ||
          /^[=+\-@|%]\s*(?:DDE|DDEAUTO|EXEC)\(/i.test(trimmed) ||
          /^[=+\-@|%]\s*WEBSERVICE\([^)]*https?:\/\//i.test(trimmed)) {
        structuralSignals.push({
          name: 'CSV / Spreadsheet Formula Injection (DDE)',
          category: 'Formula Injection',
          points: 90,
          evidence: trimmed.slice(0, 60),
          explanation: `Line ${i + 1} contains a formula injection payload designed to execute command shell scripts when opened in Microsoft Excel.`,
          advice: 'Open CSV files with a plain text editor (e.g. Notepad) instead of spreadsheet software.'
        })
        break
      }
    }
  }

  return {
    text: cleanExtractedText(textParts.join('\n')),
    urls: extractUrls(content),
    structuralSignals,
    metadata: { rowCount: lines.length }
  }
}

/**
 * Parse RTF file
 */
function parseRtf(bytes) {
  const raw = bytes.toString('latin1')
  const structuralSignals = []
  const urls = new Set()

  if (/\\object\\objemb/i.test(raw) || /\\objclass/i.test(raw)) {
    structuralSignals.push({
      name: 'RTF Embedded OLE Object',
      category: 'Embedded Object',
      points: 75,
      evidence: 'Contains \\object\\objemb tag',
      explanation: 'RTF document embeds an OLE object. Attackers frequently use RTF OLE packages to trigger Equation Editor and memory corruption exploits (e.g. CVE-2017-11882).',
      advice: 'Do not view this RTF document in Microsoft Word. View only in plain text mode.'
    })
  }

  const cleanText = raw
    .replace(/\\par[d]?/g, '\n')
    .replace(/\\[a-z0-9-]+[ ]?/gi, '')
    .replace(/[{}]/g, '')
    .trim()

  for (const url of extractUrls(raw)) urls.add(url)

  return {
    text: cleanExtractedText(cleanText),
    urls: [...urls],
    structuralSignals,
    metadata: {}
  }
}

/**
 * Parse Legacy Office files (.doc, .xls, .ppt)
 */
function parseLegacyOffice(bytes, ext) {
  const raw = bytes.toString('latin1')
  const structuralSignals = []
  const urls = new Set()

  // Detect VBA in OLE streams
  if (/_VBA_PROJECT_CUR|VBA|Attribut|AutoOpen|Workbook_Open|Document_Open/i.test(raw)) {
    structuralSignals.push({
      name: 'Legacy Office Embedded VBA Macro',
      category: 'Macro Code',
      points: 80,
      evidence: 'Legacy OLE VBA stream signatures present',
      explanation: 'Legacy binary document (.doc/.xls/.ppt) contains active macro streams with execution triggers.',
      advice: 'Never enable content or macros on legacy office binary files.'
    })
  }

  // Extract URLs
  for (const url of extractUrls(raw)) urls.add(url)

  // Clean ASCII/UTF-16 printable strings
  const printable = raw.replace(/[^\x20-\x7E\r\n\t]/g, ' ')
  return {
    text: cleanExtractedText(printable),
    urls: [...urls],
    structuralSignals,
    metadata: { legacyFormat: true, format: ext }
  }
}

/**
 * Parse Plain Text, Markdown, Logs, JSON, XML, EML
 */
function parseTextDocument(bytes, ext) {
  const content = bytes.toString('utf8')
  const structuralSignals = []

  // Check for disguised scripts in text files
  if (['.txt', '.log', '.md', '.markdown'].includes(ext)) {
    if (/\b(?:powershell(?:\.exe)?\s+-[eE](?:nc(?:odedcommand)?)?|Invoke-Expression|IEX\b|DownloadString|certutil\s+-urlcache|bitsadmin\s+\/transfer)/i.test(content)) {
      structuralSignals.push({
        name: 'Malicious PowerShell / Script Cradle in Text File',
        category: 'Disguised Script',
        points: 85,
        evidence: content.match(/\b(?:powershell[^\r\n]{0,50}|certutil[^\r\n]{0,50}|bitsadmin[^\r\n]{0,50})/i)?.[0] || 'PowerShell cradle pattern',
        explanation: 'Text file contains automated download commands or obfuscated PowerShell execution instructions.',
        advice: 'Do not copy-paste or execute scripts found inside this document.'
      })
    }
  }

  return {
    text: cleanExtractedText(content),
    urls: extractUrls(content),
    structuralSignals,
    metadata: { characterCount: content.length }
  }
}

/**
 * Inspect document text for specific social engineering and lure patterns
 */
function inspectDocumentContentLures(text) {
  const findings = []

  // Deceptive macro enablement lures
  if (/\b(?:enable (?:content|editing|macros)|yellow (?:security )?bar|click enable|protected document.{0,30}enable)\b/i.test(text)) {
    findings.push({
      name: 'Deceptive "Enable Content / Macros" Prompt',
      category: 'Social Engineering Lure',
      points: 75,
      evidence: text.match(/\b(?:enable (?:content|editing|macros)|yellow (?:security )?bar|click enable|protected document.{0,30}enable)\b/i)?.[0] || '',
      explanation: 'Document text instructs the recipient to click "Enable Editing" or "Enable Content". This is the signature lure used to activate malicious background macros.',
      advice: 'Never click Enable Content or Enable Editing when prompted by a document from an external source.'
    })
  }

  // Fake Invoice / Wire Transfer Pressure
  if (/\b(?:invoice (?:due|overdue|attached|amount)|wire transfer (?:details|instructions)|routing number|swift code|bank transfer|payment overdue|outstanding balance|remittance advice|settle payment)\b/i.test(text)) {
    findings.push({
      name: 'Invoice / Wire Transfer Lure',
      category: 'Financial Phishing',
      points: 35,
      evidence: text.match(/\b(?:invoice (?:due|overdue|attached|amount)|wire transfer|routing number|payment overdue)\b/i)?.[0] || '',
      explanation: 'Document is styled as an urgent invoice or wire transfer instruction. Fraudsters use fake invoices to trick accounts departments into rerouting payments.',
      advice: 'Verify invoice payment details via voice call to the known, trusted vendor phone number.'
    })
  }

  // Cloud / Office 365 Credential Gateway Phishing
  if (/\b(?:sign in to view|login with (?:microsoft|office 365|google workspace)|enter your credentials to decrypt|verify your identity to access this document|view secure message|docusign.{0,30}review document)\b/i.test(text)) {
    findings.push({
      name: 'Credential Harvesting Gateway Lure',
      category: 'Phishing Gateway',
      points: 70,
      evidence: text.match(/\b(?:sign in to view|login with (?:microsoft|office 365|google workspace)|enter your credentials to decrypt|verify your identity)\b/i)?.[0] || '',
      explanation: 'Document instructs the recipient to sign in with work or email credentials to view protected content. This is a common credential harvesting gateway.',
      advice: 'Never enter your corporate password on external links provided inside a document.'
    })
  }

  return findings
}

/**
 * Main orchestrator for comprehensive document inspection
 */
export async function analyzeDocument({
  bytes,
  fileName,
  mimeType,
  apiKey,
  aiProvider = 'rules',
  aiModel,
  useAiAnalysis = false
}) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
    const error = new Error('Please choose a document to inspect.')
    error.status = 400
    throw error
  }
  if (bytes.length > maxDocumentBytes) {
    const error = new Error('Document must be 25 MB or smaller.')
    error.status = 413
    throw error
  }

  const ext = getFileExtension(fileName)
  const isSupportedExt = Boolean(extensionTypes[ext])

  // 1. Check Magic Bytes for disguised executables
  const magicByteAlert = inspectMagicBytes(bytes, fileName)
  // 2. Check for filename / RTLO spoofing
  const filenameAlert = inspectFilenameSpoofing(fileName)

  let parseResult = { text: '', urls: [], structuralSignals: [], metadata: {} }

  if (!magicByteAlert) {
    if (['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.dotx', '.dotm', '.xltx', '.xltm', '.potx', '.potm', '.zip'].includes(ext)) {
      try {
        parseResult = parseOfficeXml(bytes, ext)
      } catch (err) {
        // If zip parsing fails, could be corrupt or disguised
        parseResult.structuralSignals.push({
          name: 'Office Package Structure Anomaly',
          category: 'Format Anomaly',
          points: 30,
          evidence: err.message || 'ZIP structure could not be parsed',
          explanation: 'Document header is marked as Office XML but the internal ZIP package is malformed or encrypted.',
          advice: 'Exercise caution. Malformed packages are sometimes crafted to crash desktop office viewers.'
        })
      }
    } else if (ext === '.pdf') {
      parseResult = await parsePdf(bytes)
    } else if (['.csv', '.tsv'].includes(ext)) {
      parseResult = parseCsv(bytes)
    } else if (ext === '.rtf') {
      parseResult = parseRtf(bytes)
    } else if (['.doc', '.xls', '.ppt'].includes(ext)) {
      parseResult = parseLegacyOffice(bytes, ext)
    } else if (['.txt', '.md', '.markdown', '.log', '.json', '.xml', '.html', '.htm', '.eml', '.msg'].includes(ext)) {
      parseResult = parseTextDocument(bytes, ext)
    } else if (!isSupportedExt) {
      // Fallback text extraction if unknown extension
      parseResult = parseTextDocument(bytes, ext)
    }
  }

  const allSignals = []
  if (magicByteAlert) allSignals.push(magicByteAlert)
  if (filenameAlert) allSignals.push(filenameAlert)
  allSignals.push(...parseResult.structuralSignals)

  // 3. Document text content threat analysis
  const textContent = (parseResult.text || '').slice(0, maxExtractedTextChars)
  const contentLures = inspectDocumentContentLures(textContent)
  allSignals.push(...contentLures)

  // 4. Pass extracted text through ScamShield heuristic message detector
  let textAnalysis = null
  if (textContent.trim()) {
    try {
      textAnalysis = analyzeMessage(textContent)
      // Add text signals that are not duplicate
      for (const sig of textAnalysis.signals) {
        if (!allSignals.some((existing) => existing.name === sig.name)) {
          allSignals.push(sig)
        }
      }
    } catch {
      // ignore
    }
  }

  // 5. Deduplicate and collect all extracted URLs
  const uniqueUrls = [...new Set([...(parseResult.urls || []), ...extractUrls(textContent)])]

  // 6. Check URLs against VirusTotal if configured
  let urlChecks = null
  if (uniqueUrls.length > 0) {
    try {
      urlChecks = await checkMessageUrls(uniqueUrls.join(' '), process.env.VIRUSTOTAL_API_KEY)
      if (urlChecks?.results) {
        for (const res of urlChecks.results) {
          if (res.status === 'malicious') {
            allSignals.push({
              name: 'Document Contains Malicious Link (VirusTotal Flagged)',
              category: 'Malicious URL',
              points: 90,
              evidence: res.url,
              explanation: `${res.malicious} of ${res.total} security engines flagged this document link as malicious.`,
              advice: 'Never click or visit this link. It leads to active phishing or malware distribution.'
            })
          } else if (res.status === 'suspicious') {
            allSignals.push({
              name: 'Document Contains Suspicious Link',
              category: 'Suspicious URL',
              points: 40,
              evidence: res.url,
              explanation: 'Security vendors flagged this link as suspicious.',
              advice: 'Avoid clicking this destination.'
            })
          }
        }
      }
    } catch {
      // ignore VT failure
    }
  }

  // 7. Calculate aggregate risk score & level
  const totalPoints = allSignals.reduce((sum, sig) => sum + (sig.points || 0), 0)
  const score = Math.min(100, totalPoints)

  const hasHighSeveritySignal = allSignals.some((s) => s.points >= 75)
  const hasMediumSeveritySignal = allSignals.some((s) => s.points >= 35)

  let level = 'Low'
  if (score >= 60 || hasHighSeveritySignal) {
    level = 'High'
  } else if (score >= 25 || hasMediumSeveritySignal) {
    level = 'Medium'
  }

  // 8. Optional AI-Assisted Assessment on Document Text
  let aiAssessment = null
  if (useAiAnalysis && textContent.length > 30 && (aiProvider === 'gemini' || aiProvider === 'groq')) {
    try {
      const prompt = `Analyze this extracted document text for fraud, phishing, fake invoices, or social engineering attacks. Document name: "${fileName}".\n\nExtracted Document Content:\n${textContent.slice(0, 4000)}`
      aiAssessment = aiProvider === 'gemini'
        ? await classifyMessageWithGemini(prompt, { apiKey: process.env.GEMINI_API_KEY, model: aiModel })
        : await classifyMessageWithGroq(prompt, { apiKey: process.env.GROQ_API_KEY, model: aiModel })

      if (aiAssessment?.riskLevel === 'High' && level !== 'High') level = 'High'
      if (aiAssessment?.riskLevel === 'Medium' && level === 'Low') level = 'Medium'
    } catch (err) {
      console.warn('AI document classification skipped:', err.message)
    }
  }

  // 9. Synthesize Actionable Advice
  const adviceList = []
  for (const sig of allSignals) {
    if (sig.advice && !adviceList.includes(sig.advice)) {
      adviceList.push(sig.advice)
    }
  }
  if (!adviceList.length) {
    adviceList.push('No malicious macros, formula injections, or phishing patterns were detected.')
    adviceList.push('Verify unexpected files with the sender through an official, verified phone or chat channel.')
  }

  return {
    fileName,
    fileType: extensionTypes[ext] || 'Unknown Document',
    fileSize: bytes.length,
    level,
    score,
    mode: useAiAnalysis && aiAssessment ? 'ai-assisted' : 'rules',
    categories: [...new Set(allSignals.map((s) => s.category))],
    signals: allSignals,
    advice: adviceList,
    extractedUrls: uniqueUrls,
    urlChecks,
    assessment: aiAssessment ? {
      scamType: aiAssessment.scamType,
      summary: aiAssessment.summary,
      attackChain: aiAssessment.attackChain
    } : null,
    textPreview: textContent ? textContent.slice(0, 1000) : null,
    metadata: {
      ...parseResult.metadata,
      embeddedObjectCount: parseResult.embeddedObjects?.length || 0,
      extractedUrlCount: uniqueUrls.length,
      hasText: Boolean(textContent.length)
    }
  }
}
