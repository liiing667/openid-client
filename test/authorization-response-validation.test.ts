import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'
import * as jose from 'jose'

const issuer = new URL('https://as.example.com')
const signing = await jose.generateKeyPair('ES256')
const jwks = { keys: [await jose.exportJWK(signing.publicKey)] }
const encoder = new TextEncoder()

function configuration() {
  const config = new client.Configuration(
    {
      issuer: issuer.href,
      token_endpoint: `${issuer.origin}/token`,
      jwks_uri: `${issuer.origin}/jwks`,
      id_token_signing_alg_values_supported: ['ES256'],
    },
    'client',
    undefined,
    client.None(),
  )
  config[client.customFetch] = async (url) => {
    if (new URL(url).pathname === '/jwks') {
      return Response.json(jwks)
    }
    return Response.json({
      access_token: 'access_token',
      token_type: 'bearer',
      id_token: await sign({ nonce: 'nonce' }),
    })
  }
  return config
}

async function hash(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value))
  return jose.base64url.encode(new Uint8Array(digest).subarray(0, 16))
}

function sign(claims: jose.JWTPayload = {}, iss = issuer.href) {
  return new jose.SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(iss)
    .setAudience('client')
    .setSubject('subject')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(signing.privateKey)
}

function fragmentCallback(parameters: Record<string, string>, suffix = '') {
  const url = new URL('https://rp.example.com/cb')
  url.hash = new URLSearchParams(parameters).toString() + suffix
  return url
}

async function hybridIdToken(claims: jose.JWTPayload = {}) {
  return sign({ nonce: 'nonce', c_hash: await hash('code'), ...claims })
}

const hybridChecks = { expectedNonce: 'nonce', expectedState: 'state' }

for (const detached of [false, true]) {
  test(`${detached ? 'detached signature' : 'hybrid'} flow accepts a complete response`, async () => {
    const config = configuration()
    client.useCodeIdTokenResponseType(config)
    if (detached) {
      client.enableDetachedSignatureResponseChecks(config)
    }
    const id_token = await hybridIdToken(
      detached ? { s_hash: await hash('state') } : {},
    )
    const result = await client.authorizationCodeGrant(
      config,
      fragmentCallback({ code: 'code', state: 'state', id_token }),
      hybridChecks,
    )
    assert.equal(result.access_token, 'access_token')
  })
}

test('implicit (id_token) flow accepts a complete response', async () => {
  const config = configuration()
  client.useIdTokenResponseType(config)
  const id_token = await sign({ nonce: 'nonce' })
  const claims = await client.implicitAuthentication(
    config,
    fragmentCallback({ state: 'state', id_token }),
    'nonce',
    { expectedState: 'state' },
  )
  assert.equal(claims.sub, 'subject')
})

for (const detached of [false, true]) {
  const kind = detached ? 'detached signature' : 'hybrid'

  test(`${kind} flow rejects a response missing the code`, async () => {
    const config = configuration()
    client.useCodeIdTokenResponseType(config)
    if (detached) {
      client.enableDetachedSignatureResponseChecks(config)
    }
    const id_token = await hybridIdToken(
      detached ? { s_hash: await hash('state') } : {},
    )
    await assert.rejects(
      client.authorizationCodeGrant(
        config,
        fragmentCallback({ state: 'state', id_token }),
        hybridChecks,
      ),
      { code: 'OAUTH_INVALID_RESPONSE' },
    )
  })

  test(`${kind} flow rejects a response missing the id_token`, async () => {
    const config = configuration()
    client.useCodeIdTokenResponseType(config)
    if (detached) {
      client.enableDetachedSignatureResponseChecks(config)
    }
    await assert.rejects(
      client.authorizationCodeGrant(
        config,
        fragmentCallback({ code: 'code', state: 'state' }),
        hybridChecks,
      ),
      { code: 'OAUTH_INVALID_RESPONSE' },
    )
  })

  test(`${kind} flow rejects a tampered id_token signature fragment`, async () => {
    const config = configuration()
    client.useCodeIdTokenResponseType(config)
    if (detached) {
      client.enableDetachedSignatureResponseChecks(config)
    }
    const id_token = await hybridIdToken(
      detached ? { s_hash: await hash('state') } : {},
    )
    const tampered = `${id_token.slice(0, -2)}${
      id_token.slice(-2) === 'aa' ? 'bb' : 'aa'
    }`
    await assert.rejects(
      client.authorizationCodeGrant(
        config,
        fragmentCallback({ code: 'code', state: 'state', id_token: tampered }),
        hybridChecks,
      ),
      { code: 'OAUTH_INVALID_RESPONSE' },
    )
  })

  test(`${kind} flow rejects a c_hash that does not match the code`, async () => {
    const config = configuration()
    client.useCodeIdTokenResponseType(config)
    if (detached) {
      client.enableDetachedSignatureResponseChecks(config)
    }
    const id_token = await hybridIdToken({
      c_hash: await hash('a-different-code'),
      ...(detached ? { s_hash: await hash('state') } : {}),
    })
    await assert.rejects(
      client.authorizationCodeGrant(
        config,
        fragmentCallback({ code: 'code', state: 'state', id_token }),
        hybridChecks,
      ),
      { code: 'OAUTH_JWT_CLAIM_COMPARISON_FAILED' },
    )
  })

  test(`${kind} flow rejects an id_token issued by another issuer`, async () => {
    const config = configuration()
    client.useCodeIdTokenResponseType(config)
    if (detached) {
      client.enableDetachedSignatureResponseChecks(config)
    }
    const id_token = await hybridIdToken(
      detached ? { s_hash: await hash('state') } : {},
    ).then((jwt) =>
      sign(
        {
          nonce: 'nonce',
          c_hash: jose.decodeJwt(jwt).c_hash,
          ...(detached ? { s_hash: jose.decodeJwt(jwt).s_hash } : {}),
        },
        'https://attacker.example.com',
      ),
    )
    await assert.rejects(
      client.authorizationCodeGrant(
        config,
        fragmentCallback({ code: 'code', state: 'state', id_token }),
        hybridChecks,
      ),
      { code: 'OAUTH_JWT_CLAIM_COMPARISON_FAILED' },
    )
  })

  for (const suffix of ['&extra=leftover', '&extra=', '&response=jarm-like']) {
    test(`${kind} flow rejects trailing response data (${suffix})`, async () => {
      const config = configuration()
      client.useCodeIdTokenResponseType(config)
      if (detached) {
        client.enableDetachedSignatureResponseChecks(config)
      }
      const id_token = await hybridIdToken(
        detached ? { s_hash: await hash('state') } : {},
      )
      await assert.rejects(
        client.authorizationCodeGrant(
          config,
          fragmentCallback({ code: 'code', state: 'state', id_token }, suffix),
          hybridChecks,
        ),
        { code: 'OAUTH_INVALID_RESPONSE' },
      )
    })
  }

  test(`${kind} flow rejects an unknown parameter between known parameters`, async () => {
    const config = configuration()
    client.useCodeIdTokenResponseType(config)
    if (detached) {
      client.enableDetachedSignatureResponseChecks(config)
    }
    const id_token = await hybridIdToken(
      detached ? { s_hash: await hash('state') } : {},
    )
    const url = new URL('https://rp.example.com/cb')
    url.hash = `code=code&extra=1&state=state&id_token=${encodeURIComponent(
      id_token,
    )}`
    await assert.rejects(
      client.authorizationCodeGrant(config, url, hybridChecks),
      { code: 'OAUTH_INVALID_RESPONSE' },
    )
  })
}

test('implicit flow rejects trailing response data', async () => {
  const config = configuration()
  client.useIdTokenResponseType(config)
  const id_token = await sign({ nonce: 'nonce' })
  await assert.rejects(
    client.implicitAuthentication(
      config,
      fragmentCallback({ state: 'state', id_token }, '&extra=leftover'),
      'nonce',
      { expectedState: 'state' },
    ),
    { code: 'OAUTH_INVALID_RESPONSE' },
  )
})

test('implicit flow rejects a tampered id_token signature fragment', async () => {
  const config = configuration()
  client.useIdTokenResponseType(config)
  const id_token = await sign({ nonce: 'nonce' })
  const tampered = `${id_token.slice(0, -2)}${
    id_token.slice(-2) === 'aa' ? 'bb' : 'aa'
  }`
  await assert.rejects(
    client.implicitAuthentication(
      config,
      fragmentCallback({ state: 'state', id_token: tampered }),
      'nonce',
      { expectedState: 'state' },
    ),
    { code: 'OAUTH_INVALID_RESPONSE' },
  )
})

test('implicit flow rejects an id_token issued by another issuer', async () => {
  const config = configuration()
  client.useIdTokenResponseType(config)
  const id_token = await sign(
    { nonce: 'nonce' },
    'https://attacker.example.com',
  )
  await assert.rejects(
    client.implicitAuthentication(
      config,
      fragmentCallback({ state: 'state', id_token }),
      'nonce',
      { expectedState: 'state' },
    ),
    { code: 'OAUTH_JWT_CLAIM_COMPARISON_FAILED' },
  )
})

test('hybrid flow rejects trailing data delivered via form_post', async () => {
  const config = configuration()
  client.useCodeIdTokenResponseType(config)
  const id_token = await hybridIdToken()
  const body = new URLSearchParams({
    code: 'code',
    state: 'state',
    id_token,
    extra: 'leftover',
  })
  const request = new Request('https://rp.example.com/cb', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  })
  await assert.rejects(
    client.authorizationCodeGrant(config, request, hybridChecks),
    { code: 'OAUTH_INVALID_RESPONSE' },
  )
})

test('plain code flow remains permissive of additional response parameters', async () => {
  const config = new client.Configuration(
    {
      issuer: issuer.href,
      token_endpoint: `${issuer.origin}/token`,
      jwks_uri: `${issuer.origin}/jwks`,
      id_token_signing_alg_values_supported: ['ES256'],
    },
    'client',
    undefined,
    client.None(),
  )
  config[client.customFetch] = async (url) => {
    if (new URL(url).pathname === '/jwks') {
      return Response.json(jwks)
    }
    return Response.json({
      access_token: 'access_token',
      token_type: 'bearer',
      id_token: await sign(),
    })
  }
  const url = new URL('https://rp.example.com/cb')
  url.search = new URLSearchParams({
    code: 'code',
    extra: 'kept',
  }).toString()
  const result = await client.authorizationCodeGrant(config, url)
  assert.equal(result.access_token, 'access_token')
})
