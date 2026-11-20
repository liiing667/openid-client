import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'
import * as undici from 'undici'

const issuer = 'https://op.example.com'

function mockDocument(
  agent: undici.MockAgent,
  origin: string,
  body: object,
  path = '/.well-known/openid-configuration',
) {
  agent
    .get(origin)
    .intercept({ method: 'GET', path })
    .reply(200, body, {
      headers: { 'content-type': 'application/json' },
    })
}

function fetchWith(agent: undici.MockAgent, redirect: 'manual' | 'follow') {
  // @ts-ignore
  return (url, options) =>
    undici.fetch(url, { ...options, redirect, dispatcher: agent })
}

// a custom fetch that ends up requesting a similar looking host, e.g. through
// DNS rebinding or a malicious proxy
function fetchSimilarHost(agent: undici.MockAgent) {
  // @ts-ignore
  return (url, options) =>
    undici.fetch(String(url).replace(issuer, `${issuer}.evil.com`), {
      ...options,
      dispatcher: agent,
    })
}

test('discovery binds the document to the expected issuer', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  mockDocument(agent, 'https://op.example.com', { issuer })

  const config = await client.discovery(
    new URL(issuer),
    'client_id',
    undefined,
    undefined,
    {
      // @ts-ignore
      [client.customFetch]: fetchWith(agent, 'manual'),
    },
  )

  assert.equal(config.serverMetadata().issuer, issuer)
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery rejects a document served by a similar looking host', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  mockDocument(agent, 'https://op.example.com.evil.com', { issuer })

  await assert.rejects(
    client.discovery(new URL(issuer), 'client_id', undefined, undefined, {
      // @ts-ignore
      [client.customFetch]: fetchSimilarHost(agent),
    }),
    (err: Error) => {
      assert.equal(err.name, 'ClientError')
      assert.equal(
        err.message,
        'discovered metadata was received from an unexpected source',
      )
      return true
    },
  )
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery rejects a redirect to a similar looking host', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  agent
    .get('https://op.example.com')
    .intercept({ method: 'GET', path: '/.well-known/openid-configuration' })
    .reply(302, '', {
      headers: {
        location:
          'https://op.example.com.evil.com/.well-known/openid-configuration',
      },
    })
  mockDocument(agent, 'https://op.example.com.evil.com', { issuer })

  await assert.rejects(
    client.discovery(new URL(issuer), 'client_id', undefined, undefined, {
      // a custom fetch that follows redirects, e.g. to a similar host
      // @ts-ignore
      [client.customFetch]: fetchWith(agent, 'follow'),
    }),
    (err: Error) => {
      assert.equal(err.name, 'ClientError')
      assert.equal(
        err.message,
        'discovered metadata was received from an unexpected source',
      )
      return true
    },
  )
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery rejects a document claiming a similar looking issuer', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  mockDocument(agent, 'https://op.example.com', {
    issuer: 'https://op.example.com.evil.com',
  })

  await assert.rejects(
    client.discovery(new URL(issuer), 'client_id', undefined, undefined, {
      // @ts-ignore
      [client.customFetch]: fetchWith(agent, 'manual'),
    }),
    (err: Error) => {
      assert.equal(err.name, 'ClientError')
      assert.equal(
        err.message,
        'discovered metadata issuer does not match the expected issuer',
      )
      return true
    },
  )
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery rejects a document with an invalid issuer', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  mockDocument(agent, 'https://op.example.com', { issuer: 'invalid' })

  await assert.rejects(
    client.discovery(new URL(issuer), 'client_id', undefined, undefined, {
      // @ts-ignore
      [client.customFetch]: fetchWith(agent, 'manual'),
    }),
    (err: Error) => {
      assert.equal(err.name, 'ClientError')
      assert.equal(err.message, 'discovered metadata issuer is not a valid URL')
      return true
    },
  )
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery through a direct well-known URL skips issuer validation', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  mockDocument(agent, 'https://op.example.com', {
    issuer: 'https://issuer.example.com',
  })

  const config = await client.discovery(
    new URL('https://op.example.com/.well-known/openid-configuration'),
    'client_id',
    undefined,
    undefined,
    {
      // @ts-ignore
      [client.customFetch]: fetchWith(agent, 'manual'),
    },
  )

  assert.equal(config.serverMetadata().issuer, 'https://issuer.example.com')
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery through a direct well-known URL still checks the source', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  mockDocument(agent, 'https://op.example.com.evil.com', {
    issuer: 'https://issuer.example.com',
  })

  await assert.rejects(
    client.discovery(
      new URL('https://op.example.com/.well-known/openid-configuration'),
      'client_id',
      undefined,
      undefined,
      {
        // @ts-ignore
        [client.customFetch]: fetchSimilarHost(agent),
      },
    ),
    (err: Error) => {
      assert.equal(err.name, 'ClientError')
      assert.equal(
        err.message,
        'discovered metadata was received from an unexpected source',
      )
      return true
    },
  )
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery keeps accepting Entra ID issuer identifiers', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  mockDocument(
    agent,
    'https://login.microsoftonline.com',
    { issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0' },
    '/common/v2.0/.well-known/openid-configuration',
  )

  await assert.doesNotReject(
    client.discovery(
      new URL('https://login.microsoftonline.com/common/v2.0'),
      'client_id',
      undefined,
      undefined,
      {
        // @ts-ignore
        [client.customFetch]: fetchWith(agent, 'manual'),
      },
    ),
  )
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery keeps accepting b2clogin.com issuer identifiers', async () => {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()
  mockDocument(
    agent,
    'https://openidclientdemo.b2clogin.com',
    {
      issuer:
        'https://openidclientdemo.b2clogin.com/0e96f835-6e34-470c-800b-2e2c5908c54c/v2.0/',
    },
    '/openidclientdemo.onmicrosoft.com/B2C_1_signupsignin/v2.0/.well-known/openid-configuration',
  )

  await assert.doesNotReject(
    client.discovery(
      new URL(
        'https://openidclientdemo.b2clogin.com/openidclientdemo.onmicrosoft.com/B2C_1_signupsignin/v2.0',
      ),
      'client_id',
      undefined,
      undefined,
      {
        // @ts-ignore
        [client.customFetch]: fetchWith(agent, 'manual'),
      },
    ),
  )
  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

test('discovery keeps enforcing https', async () => {
  await assert.rejects(
    client.discovery(new URL('http://op.example.com'), 'client_id'),
    (err: Error) => {
      assert.equal(err.name, 'ClientError')
      assert.equal(err.message, 'only requests to HTTPS are allowed')
      return true
    },
  )
})

test('JWKS cache is bound to the configuration issuer', async () => {
  const config = new client.Configuration({ issuer }, 'client_id')

  // caches without an issuer identifier (e.g. externally managed) are still
  // accepted
  assert.doesNotThrow(() =>
    client.setJwksCache(config, {
      jwks: { keys: [] },
      uat: 123,
    }),
  )

  const exported = client.getJwksCache(config)
  assert.ok(exported?.uat)
  // @ts-expect-error non-standard issuer binding
  assert.equal(exported.iss, issuer)

  // same issuer accepts the exported cache
  const same = new client.Configuration({ issuer }, 'client_id')
  assert.doesNotThrow(() => client.setJwksCache(same, exported!))

  // a different (similar looking) issuer rejects it
  const other = new client.Configuration(
    { issuer: 'https://op.example.com.evil.com' },
    'client_id',
  )
  assert.throws(
    () => client.setJwksCache(other, exported!),
    (err: Error) => {
      assert.equal(err.name, 'ClientError')
      assert.equal(
        err.message,
        'JWKS cache does not belong to the configured issuer',
      )
      return true
    },
  )
})
