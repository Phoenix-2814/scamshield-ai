import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import AdmZip from 'adm-zip'
import { analyzeDocument, getSupportedExtensions } from '../backend/document-analyzer.js'

describe('Document Analyzer', () => {
  it('supports daily file extensions (PPT, Word, Excel, PDF, Text, CSV, etc.)', () => {
    const exts = getSupportedExtensions()
    assert.ok(exts.includes('.pdf'), 'must support PDF')
    assert.ok(exts.includes('.docx'), 'must support Word docx')
    assert.ok(exts.includes('.pptx'), 'must support PPT pptx')
    assert.ok(exts.includes('.xlsx'), 'must support Excel xlsx')
    assert.ok(exts.includes('.csv'), 'must support CSV')
    assert.ok(exts.includes('.txt'), 'must support TXT')
  })

  it('detects dangerous double extension spoofing', async () => {
    const bytes = Buffer.from('fake document content')
    const result = await analyzeDocument({
      bytes,
      fileName: 'invoice_2026.pdf.exe',
      mimeType: 'application/octet-stream'
    })

    assert.equal(result.level, 'High')
    assert.ok(result.signals.some((s) => s.category === 'File Spoofing'))
  })

  it('detects disguised Windows executable binary', async () => {
    const bytes = Buffer.from('MZ\x90\x00\x03\x00\x00\x00This program cannot be run in DOS mode')
    const result = await analyzeDocument({
      bytes,
      fileName: 'QuarterlyReport.docx',
      mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    })

    assert.equal(result.level, 'High')
    assert.ok(result.signals.some((s) => s.name.includes('PE/MZ')))
  })

  it('detects malicious macro with auto-execution in Office document', async () => {
    const zip = new AdmZip()
    zip.addFile('word/document.xml', Buffer.from('<w:document><w:body><w:p><w:r><w:t>Please enable content to view invoice</w:t></w:r></w:p></w:body></w:document>'))
    zip.addFile('word/vbaProject.bin', Buffer.from('Sub AutoOpen() Shell("powershell.exe -enc ...") End Sub'))
    const bytes = zip.toBuffer()

    const result = await analyzeDocument({
      bytes,
      fileName: 'Overdue_Invoice.docm',
      mimeType: 'application/vnd.ms-word.document.macroEnabled.12'
    })

    assert.equal(result.level, 'High')
    assert.ok(result.signals.some((s) => s.category === 'Malicious Macro'))
    assert.ok(result.signals.some((s) => s.category === 'Social Engineering Lure'))
  })

  it('detects CSV and Excel formula injection (DDE commands)', async () => {
    const csvContent = 'ID,Name,Amount\n1,Alice,100\n2,Bob,=cmd|\'/C calc\'!A0\n'
    const bytes = Buffer.from(csvContent, 'utf8')

    const result = await analyzeDocument({
      bytes,
      fileName: 'payroll_report.csv',
      mimeType: 'text/csv'
    })

    assert.equal(result.level, 'High')
    assert.ok(result.signals.some((s) => s.category === 'Formula Injection'))
  })

  it('inspects PowerPoint presentations and extracts text safely', async () => {
    const zip = new AdmZip()
    zip.addFile('ppt/slides/slide1.xml', Buffer.from('<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Q3 Sales Review Meeting Agenda</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>'))
    const bytes = zip.toBuffer()

    const result = await analyzeDocument({
      bytes,
      fileName: 'Sales_Strategy.pptx',
      mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    })

    assert.equal(result.level, 'Low')
    assert.equal(result.score, 0)
    assert.ok(result.textPreview.includes('Q3 Sales Review Meeting Agenda'))
  })

  it('detects suspicious PDF objects like /Launch or /JavaScript', async () => {
    const pdfData = `%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF`
    const bytes = Buffer.from(pdfData, 'latin1')

    const result = await analyzeDocument({
      bytes,
      fileName: 'Confidential_Contract.pdf',
      mimeType: 'application/pdf'
    })

    assert.equal(result.level, 'High')
    assert.ok(result.signals.some((s) => s.category === 'Process Launch'))
  })

  it('marks a clean text file as Low risk', async () => {
    const bytes = Buffer.from('Meeting notes:\n- Review sprint backlog\n- Discuss frontend styling\n- Plan next release date.\n')
    const result = await analyzeDocument({
      bytes,
      fileName: 'notes.txt',
      mimeType: 'text/plain'
    })

    assert.equal(result.level, 'Low')
    assert.equal(result.score, 0)
    assert.equal(result.signals.length, 0)
  })
})
