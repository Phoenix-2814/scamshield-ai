
import { describe, it, expect } from 'vitest'
import { analyzeMessage } from './detector'

describe('ScamShield message detector', () => {
  it('flags a message requesting an OTP', () => {
    const result = analyzeMessage(
      'Share your OTP immediately or your account will be blocked'
    )

    expect(result.signals.length).toBeGreaterThan(0)
    expect(result.level).toBe('High')
  })

  it('does not flag an ordinary meeting message', () => {
    const result = analyzeMessage(
      'Hi, are we meeting at the library at 4 PM?'
    )

    expect(result.signals).toHaveLength(0)
    expect(result.level).toBe('Low')
  })

  it('rejects an empty message', () => {
    expect(() => analyzeMessage('  ')).toThrow(
      'Please enter a message to analyze.'
    )
  })

  it('keeps the score within 0 to 100', () => {
    const result = analyzeMessage(
      'URGENT OTP password CVV pay now transfer money ' +
      'verify your account https://example.com'
    )

    expect(result.score).toBeGreaterThanOrEqual(0)
    expect(result.score).toBeLessThanOrEqual(100)
  })
})
