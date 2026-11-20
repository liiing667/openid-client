import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'
import * as oauth from 'oauth4webapi'
import * as undici from 'undici'
import * as jose from 'jose'

test('DCR preserves clock settings across DPoP nonce retries', async () => {
  const issuer = new URL('https://op.example.com')
  const keyPair = await client.randomDPoPKeyPair('ES256')
  let registrationRequests = 0
  let authenticated = false

  const config = await client.dynamicClientRegistration(
    issuer,
    {
      [client.clockSkew]: 120,
      [client.clockTolerance]: 0,
    },
    (server, metadata, body, headers) => {
      assert.strictEqual(metadata[client.clockSkew], 120)
      assert.strictEqual(metadata[client.clockTolerance], 0)
      authenticated = true
      return client.None()(server, metadata, body, headers)
    },
    {
      DPoP: oauth.DPoP({}, keyPair),
      [client.customFetch]: async (url, options) => {
        switch (new URL(url).pathname) {
          case '/.well-known/openid-configuration':
            return Response.json({
              issuer: issuer.href,
              registration_endpoint: `${issuer.origin}/reg`,
              token_endpoint: `${issuer.origin}/token`,
            })
          case '/reg':
            assert.deepStrictEqual(JSON.parse(options.body as string), {})
            if (++registrationRequests === 1) {
              return Response.json(
                {},
                {
                  status: 400,
                  headers: {
                    'dpop-nonce': 'server-nonce',
                    'www-authenticate': 'DPoP error="use_dpop_nonce"',
                  },
                },
              )
            }
            assert.strictEqual(
              jose.decodeJwt(options.headers.dpop).nonce,
              'server-nonce',
            )
            return Response.json({ client_id: 'client' }, { status: 201 })
          case '/token':
            return Response.json({
              access_token: 'access_token',
              token_type: 'bearer',
            })
          default:
            throw new Error(`unexpected request to ${url}`)
        }
      },
    },
  )

  await client.clientCredentialsGrant(config)
  assert.strictEqual(registrationRequests, 2)
  assert.strictEqual(authenticated, true)
})

test('dpop may be used with DCR w/ initial access token', async () => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')
  const kp = await client.randomDPoPKeyPair('ES256')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
      headers({ dpop, authorization }) {
        return typeof dpop === 'string' && authorization === 'DPoP token'
      },
    })
    .reply(
      400,
      {},
      {
        headers: {
          'dpop-nonce': 'use this',
          'www-authenticate': 'dpop error="use_dpop_nonce"',
        },
      },
    )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
      headers({ dpop, authorization }) {
        const { nonce } = jose.decodeJwt(dpop)
        return nonce === 'use this' && authorization === 'DPoP token'
      },
    })
    .reply(201, {
      client_id: 'foo',
    })

  await client.dynamicClientRegistration(issuer, {}, undefined, {
    initialAccessToken: 'token',
    DPoP: oauth.DPoP({}, kp),
    // @ts-ignore
    [client.customFetch](url, options) {
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('dpop may be used with DCR w/o initial access token', async () => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')
  const kp = await client.randomDPoPKeyPair('ES256')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
      headers({ dpop, authorization }) {
        return typeof dpop === 'string' && authorization === undefined
      },
    })
    .reply(
      400,
      {},
      {
        headers: {
          'dpop-nonce': 'use this',
          'www-authenticate': 'dpop error="use_dpop_nonce"',
        },
      },
    )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
      headers({ dpop, authorization }) {
        const { nonce } = jose.decodeJwt(dpop)
        return nonce === 'use this' && authorization === undefined
      },
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  await client.dynamicClientRegistration(issuer, {}, undefined, {
    DPoP: oauth.DPoP({}, kp),
    // @ts-ignore
    [client.customFetch](url, options) {
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('DCR uses client_secret_post by default when client_secret was returned', async () => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  const config = await client.dynamicClientRegistration(issuer, {}, undefined, {
    // @ts-ignore
    [client.customFetch](url, options) {
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      body(body) {
        const params = new URLSearchParams(body)
        assert.strictEqual(params.has('client_id'), true)
        assert.strictEqual(params.has('client_secret'), true)
        return true
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('DCR uses none by default when client_secret was not returned', async () => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
    })

  const config = await client.dynamicClientRegistration(issuer, {}, undefined, {
    // @ts-ignore
    [client.customFetch](url, options) {
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      body(body) {
        const params = new URLSearchParams(body)
        assert.strictEqual(params.has('client_id'), true)
        return true
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('DCR can use ClientSecretBasic without having a secret at hand prior to the registration', async () => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  const config = await client.dynamicClientRegistration(
    issuer,
    {},
    client.ClientSecretBasic(),
    {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    },
  )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      headers(headers) {
        return headers.authorization === 'Basic Zm9vOmJhcg=='
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('DCR can use ClientSecretPost without having a secret at hand prior to the registration', async () => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  const config = await client.dynamicClientRegistration(
    issuer,
    {},
    client.ClientSecretPost(),
    {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    },
  )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      body(body) {
        const params = new URLSearchParams(body)
        assert.strictEqual(params.has('client_id'), true)
        assert.strictEqual(params.has('client_secret'), true)
        return true
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('DCR can use ClientSecretJwt without having a secret at hand prior to the registration', async () => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  const config = await client.dynamicClientRegistration(
    issuer,
    {},
    client.ClientSecretJwt(),
    {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    },
  )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      body(body) {
        const params = new URLSearchParams(body)
        assert.strictEqual(params.has('client_id'), true)
        assert.strictEqual(params.has('client_assertion_type'), true)
        assert.strictEqual(params.has('client_assertion'), true)
        return true
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

const issuer = new URL('https://op.example.com')

function dcrFetch(
  registrationResponse: Record<string, unknown> | (() => Response),
  registrationAssert?: (body: Record<string, unknown>) => void,
) {
  return async (url: string, options: any) => {
    switch (new URL(url).pathname) {
      case '/.well-known/openid-configuration':
        return Response.json({
          issuer: issuer.href,
          registration_endpoint: `${issuer.origin}/reg`,
          token_endpoint: `${issuer.origin}/token`,
        })
      case '/reg': {
        const body = JSON.parse(options.body as string)
        registrationAssert?.(body)
        return typeof registrationResponse === 'function'
          ? registrationResponse()
          : Response.json(registrationResponse, { status: 201 })
      }
      default:
        throw new Error(`unexpected request to ${url}`)
    }
  }
}

test('DCR rejects a registration response pointing at a different issuer', async () => {
  await assert.rejects(
    client.dynamicClientRegistration(issuer, {}, undefined, {
      [client.customFetch]: dcrFetch({
        client_id: 'client',
        issuer: 'https://attacker.example.com',
      }),
    }),
    (err: unknown) => {
      assert.ok(err instanceof client.ClientError)
      assert.strictEqual(err.code, oauth.JSON_ATTRIBUTE_COMPARISON)
      assert.match(err.message, /issuer/)
      return true
    },
  )
})

test('DCR accepts a registration response echoing the same issuer', async () => {
  const config = await client.dynamicClientRegistration(issuer, {}, undefined, {
    // @ts-ignore
    [client.customFetch]: dcrFetch({
      client_id: 'client',
      issuer: issuer.href,
    }),
  })

  assert.strictEqual(config.serverMetadata().issuer, issuer.href)
  assert.strictEqual(config.clientMetadata().issuer, undefined)
})

test('DCR rejects a registration response with a malformed issuer', async () => {
  await assert.rejects(
    client.dynamicClientRegistration(issuer, {}, undefined, {
      // @ts-ignore
      [client.customFetch]: dcrFetch({
        client_id: 'client',
        issuer: 'not a url',
      }),
    }),
    (err: unknown) => {
      assert.ok(err instanceof client.ClientError)
      assert.strictEqual(err.code, oauth.INVALID_RESPONSE)
      assert.match(err.message, /issuer/)
      return true
    },
  )
})

test('DCR rejects a registration response overwriting the requested client_id', async () => {
  await assert.rejects(
    client.dynamicClientRegistration(
      issuer,
      { client_id: 'expected-client' },
      undefined,
      {
        [client.customFetch]: dcrFetch({
          client_id: 'different-client',
        }),
      },
    ),
    (err: unknown) => {
      assert.ok(err instanceof client.ClientError)
      assert.strictEqual(err.code, oauth.JSON_ATTRIBUTE_COMPARISON)
      assert.match(err.message, /client_id/)
      assert.deepStrictEqual(
        (err.cause as Record<string, unknown>).expected,
        'expected-client',
      )
      assert.strictEqual(
        (err.cause as Record<string, unknown>).attribute,
        'client_id',
      )
      return true
    },
  )
})

test('DCR rejects a registration response silently rotating the client_secret', async () => {
  await assert.rejects(
    client.dynamicClientRegistration(
      issuer,
      { client_id: 'client', client_secret: 'original-secret' },
      undefined,
      {
        [client.customFetch]: dcrFetch({
          client_id: 'client',
          client_secret: 'rotated-secret',
          client_secret_expires_at: 0,
        }),
      },
    ),
    (err: unknown) => {
      assert.ok(err instanceof client.ClientError)
      assert.strictEqual(err.code, oauth.JSON_ATTRIBUTE_COMPARISON)
      assert.match(err.message, /client_secret/)
      assert.strictEqual(
        (err.cause as Record<string, unknown>).attribute,
        'client_secret',
      )
      assert.deepStrictEqual(
        ((err.cause as Record<string, unknown>).body as Record<string, unknown>)
          .client_secret,
        'rotated-secret',
      )
      return true
    },
  )
})

test('DCR keeps the requested client_secret when the response omits it', async () => {
  const config = await client.dynamicClientRegistration(
    issuer,
    { client_id: 'client', client_secret: 'original-secret' },
    undefined,
    {
      // @ts-ignore
      [client.customFetch]: dcrFetch({
        client_id: 'client',
      }),
    },
  )

  assert.strictEqual(config.clientMetadata().client_secret, 'original-secret')
})

test('DCR stores a client_secret issued by the authorization server', async () => {
  const config = await client.dynamicClientRegistration(issuer, {}, undefined, {
    // @ts-ignore
    [client.customFetch]: dcrFetch({
      client_id: 'client',
      client_secret: 'server-issued-secret',
      client_secret_expires_at: 0,
    }),
  })

  assert.strictEqual(
    config.clientMetadata().client_secret,
    'server-issued-secret',
  )
})

test('DCR preserves requested metadata the response does not echo back', async () => {
  const codeVerifier = client.randomPKCECodeVerifier()
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier)

  const config = await client.dynamicClientRegistration(
    issuer,
    {
      redirect_uris: ['https://rp.example.com/cb'],
      response_types: ['code'],
      grant_types: ['authorization_code'],
      token_endpoint_auth_method: 'none',
      code_challenge_method: 'S256',
      code_challenge: codeChallenge,
      scope: 'openid',
    },
    undefined,
    {
      [client.customFetch]: dcrFetch(
        {
          client_id: 'client',
          client_id_issued_at: 1700000000,
        },
        (body) => {
          assert.strictEqual(body.token_endpoint_auth_method, 'none')
          assert.strictEqual(body.code_challenge_method, 'S256')
          assert.strictEqual(body.code_challenge, codeChallenge)
          assert.deepStrictEqual(body.redirect_uris, [
            'https://rp.example.com/cb',
          ])
        },
      ),
    },
  )

  const metadata = config.clientMetadata()
  assert.strictEqual(metadata.token_endpoint_auth_method, 'none')
  assert.strictEqual(metadata.code_challenge_method, 'S256')
  assert.strictEqual(metadata.code_challenge, codeChallenge)
  assert.deepStrictEqual(metadata.redirect_uris, ['https://rp.example.com/cb'])
  assert.deepStrictEqual(metadata.response_types, ['code'])
  assert.deepStrictEqual(metadata.grant_types, ['authorization_code'])
  assert.strictEqual(metadata.scope, 'openid')
  assert.strictEqual(metadata.client_id_issued_at, 1700000000)
})

test('DCR public client registration remains usable with PKCE grants', async () => {
  const config = await client.dynamicClientRegistration(
    issuer,
    { token_endpoint_auth_method: 'none' },
    client.None(),
    {
      [client.customFetch]: async (url, options) => {
        switch (new URL(url).pathname) {
          case '/.well-known/openid-configuration':
            return Response.json({
              issuer: issuer.href,
              registration_endpoint: `${issuer.origin}/reg`,
              authorization_endpoint: `${issuer.origin}/auth`,
              token_endpoint: `${issuer.origin}/token`,
            })
          case '/reg':
            return Response.json(
              {
                client_id: 'public-client',
                token_endpoint_auth_method: 'none',
              },
              { status: 201 },
            )
          case '/token': {
            const params = new URLSearchParams(options.body as string)
            assert.strictEqual(params.has('client_secret'), false)
            assert.strictEqual(params.has('code_verifier'), true)
            return Response.json({
              access_token: 'token',
              token_type: 'bearer',
            })
          }
          default:
            throw new Error(`unexpected request to ${url}`)
        }
      },
    },
  )

  const codeVerifier = client.randomPKCECodeVerifier()
  await client.authorizationCodeGrant(
    config,
    new URL('https://rp.example.com/cb?code=authorization-code'),
    {
      pkceCodeVerifier: codeVerifier,
      idTokenExpected: false,
    },
  )

  assert.strictEqual(config.clientMetadata().token_endpoint_auth_method, 'none')
})

test('DCR surfaces registration endpoint failures for diagnosis', async () => {
  await assert.rejects(
    client.dynamicClientRegistration(issuer, {}, undefined, {
      [client.customFetch]: async (url) => {
        if (new URL(url).pathname === '/.well-known/openid-configuration') {
          return Response.json({
            issuer: issuer.href,
            registration_endpoint: `${issuer.origin}/reg`,
          })
        }

        return Response.json(
          { error: 'invalid_client_metadata', error_description: 'bad scope' },
          { status: 400 },
        )
      },
    }),
    (err: unknown) => {
      assert.ok(err instanceof oauth.ResponseBodyError)
      assert.strictEqual(err.error, 'invalid_client_metadata')
      assert.strictEqual(err.error_description, 'bad scope')
      return true
    },
  )
})
