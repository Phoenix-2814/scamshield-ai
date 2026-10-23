import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import AdmZip from 'adm-zip'

let serverProcess

before(async () => {
  serverProcess = spawn('node', ['backend/server.js'], {
    env: { ...process.env, PORT: '8799', HOST: '127.0.0.1' },
    stdio: 'pipe'
  })
  // Wait for server ready
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Server start timed out')), 5000)
    serverProcess.stdout.on('data', (data) => {
      if (data.toString().includes('ScamShield API listening')) {
        clearTimeout(timeout)
        resolve()
      }
    })
    serverProcess.stderr.on('data', (err) => console.error('Server err:', err.toString()))
  })
})

after(() => {
  if (serverProcess) serverProcess.kill()
})

describe('End-to-End Document Analysis API', () => {
  it('checks GET /api/config reports documentAnalysisAvailable', async () => {
    const res = await fetch('http://127.0.0.1:8799/api/config')
    assert.equal(res.status, 200)
    const json = await res.json()
    assert.equal(json.documentAnalysisAvailable, true)
    assert.ok(Array.isArray(json.supportedDocumentExtensions))
    assert.ok(json.supportedDocumentExtensions.includes('.pdf'))
    assert.ok(json.supportedDocumentExtensions.includes('.docx'))
    assert.ok(json.supportedDocumentExtensions.includes('.xlsx'))
    assert.ok(json.supportedDocumentExtensions.includes('.pptx'))
  })

  it('audits a clean text file via POST /api/analyze-document', async () => {
    const form = new FormData()
    const file = new File(['Routine status update: All deliverables are on schedule.'], 'notes.txt', { type: 'text/plain' })
    form.append('file', file)

    const res = await fetch('http://127.0.0.1:8799/api/analyze-document', {
      method: 'POST',
      body: form
    })

    assert.equal(res.status, 200)
    const json = await res.json()
    assert.equal(json.documentAnalysis.level, 'Low')
    assert.equal(json.documentAnalysis.fileName, 'notes.txt')
  })

  it('audits a malicious macro invoice via POST /api/analyze-document', async () => {
    const zip = new AdmZip()
    zip.addFile('word/document.xml', Buffer.from('<w:document><w:body><w:p><w:r><w:t>Please enable macros to decrypt the invoice.</w:t></w:r></w:p></w:body></w:document>'))
    zip.addFile('word/vbaProject.bin', Buffer.from('Sub AutoOpen() Shell("powershell.exe -enc ...") End Sub'))

    const form = new FormData()
    const file = new File([zip.toBuffer()], 'Invoice_9823.docm', { type: 'application/vnd.ms-word.document.macroEnabled.12' })
    form.append('file', file)

    const res = await fetch('http://127.0.0.1:8799/api/analyze-document', {
      method: 'POST',
      body: form
    })

    assert.equal(res.status, 200)
    const json = await res.json()
    assert.equal(json.documentAnalysis.level, 'High')
    assert.ok(json.documentAnalysis.signals.some((s) => s.category === 'Malicious Macro'))
  })

  it('audits an Excel spreadsheet with DDE command injection', async () => {
    const form = new FormData()
    const file = new File(['Item,Qty,Formula\nWidget,10,=cmd|\'/C calc\'!A0\n'], 'Inventory.csv', { type: 'text/csv' })
    form.append('file', file)

    const res = await fetch('http://127.0.0.1:8799/api/analyze-document', {
      method: 'POST',
      body: form
    })

    assert.equal(res.status, 200)
    const json = await res.json()
    assert.equal(json.documentAnalysis.level, 'High')
    assert.ok(json.documentAnalysis.signals.some((s) => s.category === 'Formula Injection'))
  })
})
