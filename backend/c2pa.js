let readerModulePromise

export async function inspectC2pa(bytes, mimeType) {
  try {
    readerModulePromise ||= import('@contentauth/c2pa-node')
    const { Reader, Context } = await readerModulePromise
    // Uploaded media is untrusted. Disable remote manifests and OCSP lookups so
    // embedded URLs cannot make the API fetch attacker-selected network targets.
    const context = new Context({ verify: { verifyAfterReading: true, verifyTrust: true, remoteManifestFetch: false, ocspFetch: false } })
    const reader = await Reader.fromAsset({ buffer: bytes, mimeType }, context)
    if (!reader) return { status: 'not_found', validation: null, title: '', signer: '', actions: [], digitalSourceTypes: [] }

    try {
      const store = reader.json() || {}
      const active = reader.getActive() || {}
      const validation = String(store.validation_state || store.validationState || 'Unknown')
      const assertions = Object.values(active.assertions || {})
      const actions = assertions
        .filter((item) => /c2pa\.actions/i.test(item.label || ''))
        .flatMap((item) => Array.isArray(item.data?.actions) ? item.data.actions.map((action) => String(action.action || '').slice(0, 120)) : [])
        .slice(0, 20)
      const digitalSourceTypes = assertions
        .flatMap((item) => findDigitalSourceTypes(item.data))
        .slice(0, 10)

      return {
        status: 'found',
        validation,
        title: String(active.title || '').slice(0, 300),
        signer: String(active.signature_info?.issuer || active.signature_info?.common_name || '').slice(0, 300),
        actions: [...new Set(actions)],
        digitalSourceTypes: [...new Set(digitalSourceTypes)]
      }
    } finally {
      reader.free?.()
    }
  } catch (error) {
    if (['ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND', 'ERR_DLOPEN_FAILED'].includes(error?.code)) {
      return { status: 'unavailable', validation: null, title: '', signer: '', actions: [], digitalSourceTypes: [] }
    }
    return { status: 'invalid_or_unreadable', validation: null, title: '', signer: '', actions: [], digitalSourceTypes: [] }
  }
}

function findDigitalSourceTypes(value, results = []) {
  if (!value || typeof value !== 'object') return results
  for (const [key, child] of Object.entries(value)) {
    if (/digitalSourceType/i.test(key) && typeof child === 'string') results.push(child.slice(0, 300))
    else if (child && typeof child === 'object') findDigitalSourceTypes(child, results)
  }
  return results
}
