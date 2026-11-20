import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'
import * as undici from 'undici'

function setup() {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const mockAgent = agent.get('https://as.example.com')

  let tokenEndpointHits = 0
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      200,
      () => {
        tokenEndpointHits++
        return {
          access_token: 'test-access-token',
          token_type: 'bearer',
          expires_in: 3600,
        }
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )
    .persist()

  const config = new client.Configuration(
    {
      issuer: 'https://as.example.com',
      token_endpoint: 'https://as.example.com/token',
    },
    'test-client-id',
    undefined,
    client.None(),
  )

  // @ts-ignore
  config[client.customFetch] = (url, options) => {
    return undici.fetch(url, { ...options, dispatcher: agent })
  }

  return { config, tokenEndpointHits: () => tokenEndpointHits }
}

function callbackUrl(code: string, state?: string) {
  const url = new URL('https://rp.example.com/callback')
  url.searchParams.set('code', code)
  if (state !== undefined) {
    url.searchParams.set('state', state)
  }
  return url
}

test('repeated callback is rejected after consumption', async () => {
  const { config, tokenEndpointHits } = setup()

  const url = callbackUrl('code-1', 'state-1')
  const checks = { expectedState: 'state-1', pkceCodeVerifier: 'verifier-1' }

  const tokens = await client.authorizationCodeGrant(config, url, checks)
  assert.strictEqual(tokens.access_token, 'test-access-token')
  assert.strictEqual(tokenEndpointHits(), 1)

  // Same browser submitting the same callback again
  await assert.rejects(
    client.authorizationCodeGrant(config, url, checks),
    (err: Error) => {
      assert.ok(err instanceof client.ClientError)
      assert.strictEqual(
        (err as client.ClientError).code,
        'OAUTH_AUTHORIZATION_CODE_REPLAY',
      )
      return true
    },
  )
  assert.strictEqual(tokenEndpointHits(), 1)
})

test('cross-session replay of the same response is rejected', async () => {
  const { config, tokenEndpointHits } = setup()

  const url = callbackUrl('code-2', 'state-2')

  await client.authorizationCodeGrant(config, url, {
    expectedState: 'state-2',
    pkceCodeVerifier: 'verifier-session-a',
  })
  assert.strictEqual(tokenEndpointHits(), 1)

  // Another session presenting the victim's full callback URL with its own
  // session-bound checks
  await assert.rejects(
    client.authorizationCodeGrant(config, url, {
      expectedState: 'state-2',
      pkceCodeVerifier: 'verifier-session-b',
    }),
    (err: Error) => {
      assert.ok(err instanceof client.ClientError)
      assert.strictEqual(
        (err as client.ClientError).code,
        'OAUTH_AUTHORIZATION_CODE_REPLAY',
      )
      return true
    },
  )
  assert.strictEqual(tokenEndpointHits(), 1)
})

test('skipStateCheck callbacks work and are consumed once', async () => {
  const { config, tokenEndpointHits } = setup()

  const url = callbackUrl('code-3', 'state-3')
  const checks = { expectedState: client.skipStateCheck }

  const tokens = await client.authorizationCodeGrant(config, url, checks)
  assert.strictEqual(tokens.access_token, 'test-access-token')
  assert.strictEqual(tokenEndpointHits(), 1)

  await assert.rejects(
    client.authorizationCodeGrant(config, url, checks),
    (err: Error) => {
      assert.ok(err instanceof client.ClientError)
      assert.strictEqual(
        (err as client.ClientError).code,
        'OAUTH_AUTHORIZATION_CODE_REPLAY',
      )
      return true
    },
  )
  assert.strictEqual(tokenEndpointHits(), 1)
})

test('plain code flow without state is consumed once', async () => {
  const { config, tokenEndpointHits } = setup()

  const url = callbackUrl('code-4')

  const tokens = await client.authorizationCodeGrant(config, url)
  assert.strictEqual(tokens.access_token, 'test-access-token')
  assert.strictEqual(tokenEndpointHits(), 1)

  await assert.rejects(
    client.authorizationCodeGrant(config, url),
    (err: Error) => {
      assert.ok(err instanceof client.ClientError)
      assert.strictEqual(
        (err as client.ClientError).code,
        'OAUTH_AUTHORIZATION_CODE_REPLAY',
      )
      return true
    },
  )
  assert.strictEqual(tokenEndpointHits(), 1)
})

test('consumption is per code, not a global lockout', async () => {
  const { config, tokenEndpointHits } = setup()

  await client.authorizationCodeGrant(
    config,
    callbackUrl('code-5', 'state-5'),
    { expectedState: 'state-5' },
  )

  // A fresh ceremony with a new code still succeeds
  const tokens = await client.authorizationCodeGrant(
    config,
    callbackUrl('code-6', 'state-6'),
    { expectedState: 'state-6' },
  )
  assert.strictEqual(tokens.access_token, 'test-access-token')
  assert.strictEqual(tokenEndpointHits(), 2)
})
