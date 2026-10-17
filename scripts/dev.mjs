import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const children = [
  spawn(process.execPath, ['backend/server.js'], { cwd: root, stdio: 'inherit', env: { ...process.env, HOST: '127.0.0.1', PORT: process.env.PORT || '8787' } }),
  spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '127.0.0.1'], { cwd: resolve(root, 'frontend'), stdio: 'inherit', env: process.env })
]

let stopping = false
function stop(code = 0) {
  if (stopping) return
  stopping = true
  for (const child of children) if (child.exitCode === null) child.kill('SIGTERM')
  setTimeout(() => process.exit(code), 1500).unref()
}

for (const child of children) {
  child.on('error', (error) => {
    console.error(`Could not start a ScamShield service: ${error.message}`)
    stop(1)
  })
  child.on('exit', (code) => {
    if (!stopping) stop(code || 0)
  })
}
process.on('SIGINT', () => stop(0))
process.on('SIGTERM', () => stop(0))
