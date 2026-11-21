// Reproduction tests for JWKS cache handling during key rotation.
//
// The JWKS cache (in-memory and the explicit cache exchanged via
// getJwksCache()/setJwksCache()) must be evaluated together with
//   1. the cache generation (a newer generation must never be replaced by an
//      older one, even under concurrent readers),
//   2. the issuer the cache belongs to (a cache exported from issuer A must
//      not be used to validate tokens of issuer B),
//   3. the header of the token currently being validated (an unknown "kid",
//      or a signature that does not verify with the cached key, must trigger
//      a refetch instead of a hard failure).
//
// Groups that assert this invariant currently FAIL and reproduce the bug;
// groups marked "preserved behaviour" pass and must keep passing.

import test from 'node:test'
import assert from 'node:assert/strict'
import * as jose from 'jose'
import * as client from '../src/index.js'

const issuer = new URL('https://as.example.com')

const epoch = () => Math.floor(Date.now() / 1000)

type Jwk = JsonWebKey & { kid?: string; alg?: string; use?: string }

interface RotationKey {
  kid: string
  privateKey: Awaited<ReturnType<typeof jose.generateKeyPair>>['privateKey']
  jwk: Jwk
}

async function makeKey(kid: string): Promise<RotationKey> {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256')
  const jwk = (await jose.exportJWK(publicKey)) as Jwk
  jwk.kid = kid
  jwk.alg = 'ES256'
  jwk.use = 'sig'
  return { kid, privateKey, jwk }
}

function configuration(iss = issuer) {
  const config = new client.Configuration(
    {
      issuer: iss.href,
      userinfo_endpoint: `${iss.origin}/userinfo`,
      jwks_uri: `${iss.origin}/jwks`,
      userinfo_signing_alg_values_supported: ['ES256'],
    },
    'client',
  )
  client.enableNonRepudiationChecks(config)
  return config
}

type FetchHandler = (url: URL) => Response | Promise<Response>

function mockFetch(config: client.Configuration, handler: FetchHandler) {
  config[client.customFetch] = async (url) => handler(new URL(url))
}

function signUserinfo(key: RotationKey, iss = issuer) {
  return new jose.SignJWT({ sub: 'subject' })
    .setProtectedHeader({ alg: 'ES256', kid: key.kid })
    .setIssuer(iss.href)
    .setAudience('client')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key.privateKey)
}

const asJwt = (jwt: string) =>
  new Response(jwt, { headers: { 'content-type': 'application/jwt' } })

async function waitFor(condition: () => boolean) {
  while (!condition()) {
    await new Promise((resolve) => setImmediate(resolve))
  }
}

// 1. Preserved behaviour: an explicitly exported/imported JWKS cache and a
//    token with a unique "kid" must keep working without any network access.
test('explicit jwks cache input with a unique kid is honored', async () => {
  const key1 = await makeKey('1')

  const first = configuration()
  mockFetch(first, (url) => {
    switch (url.pathname) {
      case '/jwks':
        return Response.json({ keys: [key1.jwk] })
      case '/userinfo':
        return signUserinfo(key1).then(asJwt)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })
  await client.fetchUserInfo(first, 'access_token', 'subject')

  const exported = client.getJwksCache(first)
  assert.ok(exported?.jwks)
  assert.deepStrictEqual(
    exported.jwks.keys.map((jwk) => jwk.kid),
    ['1'],
  )

  const second = configuration()
  client.setJwksCache(second, exported)
  mockFetch(second, (url) => {
    switch (url.pathname) {
      case '/jwks':
        throw new Error('jwks_uri must not be fetched, cache input is fresh')
      case '/userinfo':
        return signUserinfo(key1).then(asJwt)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })
  const claims = await client.fetchUserInfo(second, 'access_token', 'subject')
  assert.strictEqual(claims.sub, 'subject')
})

// 2. A cache exported from issuer A must not be used to validate tokens of
//    issuer B. Currently the explicit cache carries no issuer binding, so
//    issuer B's token is checked against issuer A's old keys and rejected.
test('issuer switch must not reuse the previous issuer keys', async () => {
  const issuerA = new URL('https://as-a.example.com')
  const issuerB = new URL('https://as-b.example.com')
  const keyA = await makeKey('1')
  const keyB = await makeKey('1') // same kid, different key and issuer

  const configA = configuration(issuerA)
  mockFetch(configA, (url) => {
    switch (url.pathname) {
      case '/jwks':
        return Response.json({ keys: [keyA.jwk] })
      case '/userinfo':
        return signUserinfo(keyA, issuerA).then(asJwt)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })
  await client.fetchUserInfo(configA, 'access_token', 'subject')
  const exportedFromA = client.getJwksCache(configA)!

  const configB = configuration(issuerB)
  client.setJwksCache(configB, exportedFromA)
  let jwksFetches = 0
  mockFetch(configB, (url) => {
    switch (url.pathname) {
      case '/jwks':
        jwksFetches++
        return Response.json({ keys: [keyB.jwk] })
      case '/userinfo':
        return signUserinfo(keyB, issuerB).then(asJwt)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })

  const claims = await client.fetchUserInfo(configB, 'access_token', 'subject')
  assert.strictEqual(claims.sub, 'subject')
  assert.strictEqual(jwksFetches, 1)
})

// 3. Concurrent readers during a rotation must not let an older JWKS
//    generation overwrite a newer one. Currently the last writer wins, so a
//    slow fetch of the old generation regresses the cache and subsequent
//    tokens signed with the legitimately rotated key are rejected.
test('concurrent rotation must not regress the jwks cache generation', async () => {
  const key1 = await makeKey('1')
  const key2 = await makeKey('2')
  const jwks1 = { keys: [key1.jwk] }
  const jwks2 = { keys: [key2.jwk] }

  const config = configuration()

  const jwksResolvers: Array<(response: Response) => void> = []
  const userinfoTokens: string[] = []
  mockFetch(config, (url) => {
    switch (url.pathname) {
      case '/jwks':
        return new Promise<Response>((resolve) => jwksResolvers.push(resolve))
      case '/userinfo':
        return asJwt(userinfoTokens.shift()!)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })

  // Two readers race; the server rotates between their two JWKS fetches.
  userinfoTokens.push(await signUserinfo(key1))
  const oldReader = client.fetchUserInfo(config, 'access_token', 'subject')
  await waitFor(() => jwksResolvers.length === 1)

  userinfoTokens.push(await signUserinfo(key2))
  const newReader = client.fetchUserInfo(config, 'access_token', 'subject')
  await waitFor(() => jwksResolvers.length === 2)

  // The fetch of the NEW generation resolves first...
  jwksResolvers[1](Response.json(jwks2))
  await newReader
  // ...then the slow fetch of the OLD generation resolves and must not
  // replace the newer cache entry.
  jwksResolvers[0](Response.json(jwks1))
  await oldReader

  // A token signed with the current (rotated) key must still validate.
  userinfoTokens.push(await signUserinfo(key2))
  const claims = await client.fetchUserInfo(config, 'access_token', 'subject')
  assert.strictEqual(claims.sub, 'subject')

  const cached = client.getJwksCache(config)
  assert.deepStrictEqual(
    cached?.jwks?.keys.map((jwk) => jwk.kid),
    ['2'],
  )
})

// 4a. Rotation that reuses a "kid": the cached old key matches the token's
//     "kid" but the signature does not verify. The client must refetch and
//     find the rotated key instead of failing.
test('rotation reusing a kid must refetch on signature failure', async () => {
  const oldKey = await makeKey('1')
  const newKey = await makeKey('1') // kid reused across the rotation

  const config = configuration()
  client.setJwksCache(config, {
    jwks: { keys: [oldKey.jwk] },
    uat: epoch(),
  })

  let jwksFetches = 0
  mockFetch(config, (url) => {
    switch (url.pathname) {
      case '/jwks':
        jwksFetches++
        return Response.json({ keys: [newKey.jwk] })
      case '/userinfo':
        return signUserinfo(newKey).then(asJwt)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })

  const claims = await client.fetchUserInfo(config, 'access_token', 'subject')
  assert.strictEqual(claims.sub, 'subject')
  assert.strictEqual(jwksFetches, 1)
})

// 4b. A single JWKS document containing two keys with the same "kid" (seen in
//     the wild during rotations): every candidate must be tried until one
//     verifies instead of erroring out on ambiguity.
test('duplicate kid entries must each be tried', async () => {
  const keyA = await makeKey('1')
  const keyB = await makeKey('1')

  const config = configuration()
  mockFetch(config, (url) => {
    switch (url.pathname) {
      case '/jwks':
        return Response.json({ keys: [keyA.jwk, keyB.jwk] })
      case '/userinfo':
        return signUserinfo(keyB).then(asJwt)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })

  const claims = await client.fetchUserInfo(config, 'access_token', 'subject')
  assert.strictEqual(claims.sub, 'subject')
})

// 5. An old (but < 60s) cache without the token's "kid", while the server has
//    legitimately rotated to a new key: the token header must trigger a
//    refetch regardless of the cache age throttle.
test('old cache with a legitimate new key must trigger a refetch', async () => {
  const key1 = await makeKey('1')
  const key2 = await makeKey('2')

  const config = configuration()
  client.setJwksCache(config, {
    jwks: { keys: [key1.jwk] },
    uat: epoch() - 30, // fresh enough to be used, too fresh to be refetched
  })

  let jwksFetches = 0
  mockFetch(config, (url) => {
    switch (url.pathname) {
      case '/jwks':
        jwksFetches++
        return Response.json({ keys: [key2.jwk] })
      case '/userinfo':
        return signUserinfo(key2).then(asJwt)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })

  const claims = await client.fetchUserInfo(config, 'access_token', 'subject')
  assert.strictEqual(claims.sub, 'subject')
  assert.strictEqual(jwksFetches, 1)
})

// Contrast case (passes today): once the cache is older than 60s an unknown
// "kid" does trigger a refetch.
test('stale cache (>= 60s) with an unknown kid refetches', async () => {
  const key1 = await makeKey('1')
  const key2 = await makeKey('2')

  const config = configuration()
  client.setJwksCache(config, {
    jwks: { keys: [key1.jwk] },
    uat: epoch() - 120,
  })

  let jwksFetches = 0
  mockFetch(config, (url) => {
    switch (url.pathname) {
      case '/jwks':
        jwksFetches++
        return Response.json({ keys: [key2.jwk] })
      case '/userinfo':
        return signUserinfo(key2).then(asJwt)
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  })

  const claims = await client.fetchUserInfo(config, 'access_token', 'subject')
  assert.strictEqual(claims.sub, 'subject')
  assert.strictEqual(jwksFetches, 1)
})
