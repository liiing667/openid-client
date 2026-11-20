import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'

const issuer = 'https://as.example.com'
const revocation_endpoint = 'https://as.example.com/revoke'
const resource = new URL('https://rs.example.com/resource')

interface RequestLog {
  url: string
  body: string
}

function configWith(
  server: Partial<client.ServerMetadata>,
  fetch: client.CustomFetch,
) {
  const config = new client.Configuration(
    { issuer, ...server },
    'client',
    'client-secret',
  )
  config[client.customFetch] = fetch
  return config
}

function successfulFetch(
  log: RequestLog[],
  response = new Response(),
): client.CustomFetch {
  return async (url, options) => {
    log.push({
      url: String(url),
      body: await new Response(options.body as BodyInit).text(),
    })
    return response
  }
}

test('a revoked access token is rejected by fetchProtectedResource without a network call', async () => {
  const log: RequestLog[] = []
  const config = configWith({ revocation_endpoint }, successfulFetch(log))

  const accessToken = 'access-token-value'
  await client.tokenRevocation(config, accessToken, {
    token_type_hint: 'access_token',
  })

  assert.equal(client.isTokenRevoked(config, accessToken), true)
  await assert.rejects(
    client.fetchProtectedResource(config, accessToken, resource, 'GET'),
    (err: unknown) => {
      assert.ok(err instanceof client.RevokedTokenError)
      assert.equal(err.code, 'ERR_TOKEN_REVOKED')
      assert.equal(err.token, accessToken)
      assert.ok(err.message.includes('revoked'))
      return true
    },
  )

  // only the revocation request went out, no protected resource request
  assert.equal(log.length, 1)
  assert.equal(log[0].url, revocation_endpoint)
  const body = new URLSearchParams(log[0].body)
  assert.equal(body.get('token'), accessToken)
  assert.equal(body.get('token_type_hint'), 'access_token')
})

test('an unrevoked token still reaches the protected resource', async () => {
  const log: RequestLog[] = []
  const ok = new Response('payload')
  const config = configWith({ revocation_endpoint }, async (url, options) => {
    log.push({
      url: String(url),
      body: await new Response(options.body as BodyInit).text(),
    })
    return ok
  })

  const response = await client.fetchProtectedResource(
    config,
    'fresh-access-token',
    resource,
    'GET',
  )
  assert.equal(response, ok)
  assert.equal(log.length, 1)
  assert.equal(log[0].url, resource.href)
  assert.equal(client.isTokenRevoked(config, 'fresh-access-token'), false)
})

test('multiple tokens are tracked independently', async () => {
  const log: RequestLog[] = []
  const config = configWith({ revocation_endpoint }, successfulFetch(log))

  await client.tokenRevocation(config, 'token-one', {
    token_type_hint: 'access_token',
  })
  await client.tokenRevocation(config, 'token-two', {
    token_type_hint: 'refresh_token',
  })

  const records = client.getTokenRevocationRecords(config)
  assert.equal(records.length, 2)
  assert.deepEqual(
    records.map((record) => [record.token, record.credential, record.ok]),
    [
      ['token-one', 'access_token', true],
      ['token-two', 'refresh_token', true],
    ],
  )
  for (const record of records) {
    assert.equal(record.endpoint, revocation_endpoint)
    assert.equal(record.attempt, 1)
    assert.equal(record.duplicate, false)
    assert.equal(record.error, undefined)
    assert.ok(Object.isFrozen(record))
  }

  assert.equal(client.isTokenRevoked(config, 'token-one'), true)
  assert.equal(client.isTokenRevoked(config, 'token-two'), true)
  assert.equal(client.isTokenRevoked(config, 'token-three'), false)

  await assert.rejects(
    client.fetchProtectedResource(config, 'token-one', resource, 'GET'),
    client.RevokedTokenError,
  )
  await assert.rejects(
    client.fetchProtectedResource(config, 'token-two', resource, 'GET'),
    client.RevokedTokenError,
  )
})

test('a failed revocation identifies the credential and does not mark it revoked', async () => {
  const config = configWith(
    { revocation_endpoint },
    async () =>
      new Response(JSON.stringify({ error: 'invalid_token' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }),
  )

  const token = 'doomed-access-token'
  await assert.rejects(
    client.tokenRevocation(config, token, {
      token_type_hint: 'access_token',
    }),
    (err: unknown) => {
      assert.ok(err instanceof client.TokenRevocationError)
      assert.equal(err.code, 'ERR_TOKEN_REVOCATION_FAILED')
      assert.equal(err.credential, 'access_token')
      assert.equal(err.token, token)
      assert.ok(err.message.includes('access_token'))
      assert.ok(err.message.includes(revocation_endpoint))
      assert.ok(err.cause instanceof client.ResponseBodyError)
      return true
    },
  )

  assert.equal(client.isTokenRevoked(config, token), false)
  const [record] = client.getTokenRevocationRecords(config)
  assert.equal(record.ok, false)
  assert.equal(record.token, token)
  assert.equal(record.credential, 'access_token')
  assert.equal(record.attempt, 1)
  assert.equal(record.duplicate, false)
  assert.equal(record.endpoint, revocation_endpoint)
  assert.ok(record.error)
  assert.equal(record.error?.name, 'ResponseBodyError')
  assert.ok(record.error?.message)

  // the token was never confirmed revoked, so resource access is still attempted
  const ok = new Response()
  config[client.customFetch] = successfulFetch([], ok)
  assert.equal(
    await client.fetchProtectedResource(config, token, resource, 'GET'),
    ok,
  )
})

test('a missing revocation endpoint is recorded per token with a typed error', async () => {
  const config = configWith({}, successfulFetch([]))

  for (const token of ['first-token', 'second-token']) {
    await assert.rejects(
      client.tokenRevocation(config, token),
      (err: unknown) => {
        assert.ok(err instanceof client.TokenRevocationError)
        assert.equal(err.credential, 'token')
        assert.equal(err.token, token)
        assert.ok(err.message.includes('revocation endpoint'))
        return true
      },
    )
  }

  const records = client.getTokenRevocationRecords(config)
  assert.equal(records.length, 2)
  for (const [index, record] of records.entries()) {
    assert.equal(record.ok, false)
    assert.equal(record.endpoint, undefined)
    assert.equal(record.credential, 'token')
    assert.equal(record.token, index === 0 ? 'first-token' : 'second-token')
    assert.equal(record.error?.code, 'OAUTH_MISSING_SERVER_METADATA')
  }
  assert.equal(client.isTokenRevoked(config, 'first-token'), false)
})

test('a malformed revocation endpoint and a network failure are recorded individually', async () => {
  const malformed = configWith(
    { revocation_endpoint: 'not a url' },
    successfulFetch([]),
  )
  await assert.rejects(
    client.tokenRevocation(malformed, 'malformed-token'),
    (err: unknown) => {
      assert.ok(err instanceof client.TokenRevocationError)
      assert.equal(err.token, 'malformed-token')
      assert.ok(err.message.includes('revocation endpoint'))
      return true
    },
  )
  const malformedRecord = client.getTokenRevocationRecords(malformed)[0]
  assert.equal(malformedRecord.ok, false)
  assert.equal(malformedRecord.endpoint, undefined)
  assert.ok(malformedRecord.error)

  const networkFailure = configWith({ revocation_endpoint }, async () => {
    throw new TypeError('fetch failed')
  })
  await assert.rejects(
    client.tokenRevocation(networkFailure, 'offline-token'),
    (err: unknown) => {
      assert.ok(err instanceof client.TokenRevocationError)
      assert.equal(err.token, 'offline-token')
      assert.ok(err.cause instanceof TypeError)
      return true
    },
  )
  const networkRecord = client.getTokenRevocationRecords(networkFailure)[0]
  assert.equal(networkRecord.ok, false)
  assert.equal(networkRecord.endpoint, revocation_endpoint)
  assert.equal(networkRecord.error?.name, 'TypeError')
  assert.equal(networkRecord.error?.message, 'fetch failed')
  assert.equal(client.isTokenRevoked(networkFailure, 'offline-token'), false)
})

test('repeated revocations are still sent and recorded as duplicates', async () => {
  const log: RequestLog[] = []
  const config = configWith({ revocation_endpoint }, successfulFetch(log))

  const token = 'repeated-token'
  await client.tokenRevocation(config, token, {
    token_type_hint: 'access_token',
  })
  await client.tokenRevocation(config, token, {
    token_type_hint: 'access_token',
  })
  await client.tokenRevocation(config, token)

  assert.equal(log.length, 3)
  const records = client.getTokenRevocationRecords(config)
  assert.deepEqual(
    records.map((record) => [record.attempt, record.duplicate, record.ok]),
    [
      [1, false, true],
      [2, true, true],
      [3, true, true],
    ],
  )
  assert.equal(records[2].credential, 'token')
  assert.equal(client.isTokenRevoked(config, token), true)
})

test('records are isolated between Configuration instances', async () => {
  const configA = configWith({ revocation_endpoint }, successfulFetch([]))
  const configB = configWith({ revocation_endpoint }, successfulFetch([]))

  await client.tokenRevocation(configA, 'token-a')

  assert.equal(client.getTokenRevocationRecords(configA).length, 1)
  assert.equal(client.getTokenRevocationRecords(configB).length, 0)
  assert.equal(client.isTokenRevoked(configB, 'token-a'), false)
})

test('tokenRevocation validates its inputs and keeps the client authentication intact', async () => {
  const log: RequestLog[] = []
  const config = configWith({ revocation_endpoint }, successfulFetch(log))

  await assert.rejects(client.tokenRevocation(config, ''), (err: unknown) => {
    assert.ok(err instanceof TypeError)
    assert.equal((err as { code?: string }).code, 'ERR_INVALID_ARG_VALUE')
    return true
  })
  assert.equal(client.getTokenRevocationRecords(config).length, 0)

  await client.tokenRevocation(config, 'secret-token')
  const body = new URLSearchParams(log[0].body)
  // default ClientSecretPost authentication is still applied
  assert.equal(body.get('client_id'), 'client')
  assert.equal(body.get('client_secret'), 'client-secret')
  assert.equal(body.get('token'), 'secret-token')
})

test('buildEndSessionUrl remains a plain URL builder and records nothing', async () => {
  const config = configWith(
    {
      end_session_endpoint: 'https://as.example.com/logout',
      revocation_endpoint,
    },
    successfulFetch([]),
  )

  const url = client.buildEndSessionUrl(config, {
    id_token_hint: 'id-token',
    post_logout_redirect_uri: 'https://rp.example.com/logged-out',
  })

  assert.equal(url.origin, 'https://as.example.com')
  assert.equal(url.pathname, '/logout')
  assert.equal(url.searchParams.get('client_id'), 'client')
  assert.equal(url.searchParams.get('id_token_hint'), 'id-token')
  assert.equal(
    url.searchParams.get('post_logout_redirect_uri'),
    'https://rp.example.com/logged-out',
  )
  assert.equal(client.getTokenRevocationRecords(config).length, 0)
})
