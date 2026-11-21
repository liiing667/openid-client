import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'

const issuer = 'https://as.example.com'
const token_endpoint = 'https://as.example.com/token'

function configWith(fetch: client.CustomFetch) {
  const config = new client.Configuration(
    { issuer, token_endpoint },
    'client',
    'client-secret',
  )
  config[client.customFetch] = fetch
  return config
}

function json(payload: Record<string, unknown>, init?: ResponseInit) {
  return Response.json(payload, init)
}

/**
 * A token endpoint mock that records the refresh token of every request and
 * delegates the response to `handler`.
 */
function tokenEndpoint(
  log: string[],
  handler: (refreshToken: string) => Response | Promise<Response>,
): client.CustomFetch {
  return async (url, options) => {
    assert.equal(String(url), token_endpoint)
    const body = new URLSearchParams(
      await new Response(options.body as BodyInit).text(),
    )
    const refreshToken = body.get('refresh_token')!
    log.push(refreshToken)
    return handler(refreshToken)
  }
}

function tokens(payload: Record<string, unknown>) {
  return json({ token_type: 'Bearer', expires_in: 3600, ...payload })
}

test('refresh without rotation keeps the refresh token and scope', async () => {
  const log: string[] = []
  const config = configWith(
    tokenEndpoint(log, () => tokens({ access_token: 'at-2' })),
  )
  const session = new client.TokenRefreshSession(config, {
    refresh_token: 'rt-1',
    scope: 'openid email',
  })

  assert.equal(session.generation, 0)

  const result = await session.refresh()

  assert.equal(result.access_token, 'at-2')
  assert.deepEqual(log, ['rt-1'])
  assert.equal(session.generation, 1)
  assert.equal(session.refreshToken, 'rt-1')
  assert.equal(session.scope, 'openid email')
})

test('a successful rotation replaces the refresh token and bumps the generation', async () => {
  const log: string[] = []
  let rotation = 0
  const config = configWith(
    tokenEndpoint(log, () => {
      rotation++
      return tokens({
        access_token: `at-${rotation + 1}`,
        refresh_token: `rt-${rotation + 1}`,
      })
    }),
  )
  const session = new client.TokenRefreshSession(config, {
    refresh_token: 'rt-1',
    scope: 'openid email',
  })

  await session.refresh()
  assert.equal(session.generation, 1)
  assert.equal(session.refreshToken, 'rt-2')

  await session.refresh()
  assert.equal(session.generation, 2)
  assert.equal(session.refreshToken, 'rt-3')
  assert.equal(session.scope, 'openid email')

  // each refresh used the token committed by the previous one
  assert.deepEqual(log, ['rt-1', 'rt-2'])
})

test('a scope in the response replaces the session scope', async () => {
  const config = configWith(
    tokenEndpoint([], () => tokens({ access_token: 'at-2', scope: 'openid' })),
  )
  const session = new client.TokenRefreshSession(config, {
    refresh_token: 'rt-1',
    scope: 'openid email',
  })

  await session.refresh()
  assert.equal(session.scope, 'openid')
  assert.equal(session.generation, 1)
})

test('concurrent refreshes share a single request and commit once', async () => {
  const log: string[] = []
  const config = configWith(
    tokenEndpoint(log, async () => {
      await new Promise((resolve) => setTimeout(resolve, 20))
      return tokens({ access_token: 'at-2', refresh_token: 'rt-2' })
    }),
  )
  const session = new client.TokenRefreshSession(config, {
    refresh_token: 'rt-1',
    scope: 'openid email',
  })

  const [a, b, c] = await Promise.all([
    session.refresh(),
    session.refresh(),
    session.refresh(),
  ])

  // all callers settled with the very same outcome
  assert.equal(a, b)
  assert.equal(b, c)

  // a single token endpoint request went out and committed exactly once
  assert.deepEqual(log, ['rt-1'])
  assert.equal(session.generation, 1)
  assert.equal(session.refreshToken, 'rt-2')
  assert.equal(session.scope, 'openid email')
})

test('a failed refresh keeps the previous state', async () => {
  const log: string[] = []
  const config = configWith(
    tokenEndpoint(log, (refreshToken) => {
      if (refreshToken === 'rt-2') {
        return json({ error: 'invalid_grant' }, { status: 400 })
      }
      return tokens({ access_token: 'at-2', refresh_token: 'rt-2' })
    }),
  )
  const session = new client.TokenRefreshSession(config, {
    refresh_token: 'rt-1',
    scope: 'openid email',
  })

  await session.refresh()
  assert.equal(session.generation, 1)
  assert.equal(session.refreshToken, 'rt-2')

  await assert.rejects(session.refresh(), (err: unknown) => {
    assert.ok(err instanceof client.ResponseBodyError)
    assert.equal(err.error, 'invalid_grant')
    return true
  })

  // the failure did not commit anything, the pre-failure state is intact
  assert.equal(session.generation, 1)
  assert.equal(session.refreshToken, 'rt-2')
  assert.equal(session.scope, 'openid email')
  assert.deepEqual(log, ['rt-1', 'rt-2'])
})

test('a failed refresh can be retried with the preserved state', async () => {
  const log: string[] = []
  let fail = true
  const config = configWith(
    tokenEndpoint(log, () => {
      if (fail) {
        fail = false
        return json({ error: 'temporarily_unavailable' }, { status: 503 })
      }
      return tokens({ access_token: 'at-2' })
    }),
  )
  const session = new client.TokenRefreshSession(config, {
    refresh_token: 'rt-1',
    scope: 'openid email',
  })

  await assert.rejects(session.refresh())
  assert.equal(session.generation, 0)

  await session.refresh()
  assert.equal(session.generation, 1)
  assert.equal(session.refreshToken, 'rt-1')
  assert.deepEqual(log, ['rt-1', 'rt-1'])
})

test('reusing an old refresh token fails without touching the session', async () => {
  const log: string[] = []
  const rotated = new Set<string>()
  const config = configWith(
    tokenEndpoint(log, (refreshToken) => {
      if (rotated.has(refreshToken)) {
        // the authorization server already rotated this token away and
        // rejects its reuse
        return json({ error: 'invalid_grant' }, { status: 400 })
      }
      rotated.add(refreshToken)
      return tokens({
        access_token: `at-for-${refreshToken}`,
        refresh_token: `${refreshToken}-rotated`,
      })
    }),
  )

  // two sessions hydrated from the same persisted state (e.g. two tabs)
  const stored = { refresh_token: 'rt-1', scope: 'openid email' }
  const first = new client.TokenRefreshSession(config, stored)
  const second = new client.TokenRefreshSession(config, stored)

  await first.refresh()
  assert.equal(first.generation, 1)
  assert.equal(first.refreshToken, 'rt-1-rotated')

  // the second session still holds the old, now rotated away, token
  await assert.rejects(second.refresh(), (err: unknown) => {
    assert.ok(err instanceof client.ResponseBodyError)
    assert.equal(err.error, 'invalid_grant')
    return true
  })

  // the rejected reuse did not commit anything to either session
  assert.equal(second.generation, 0)
  assert.equal(second.refreshToken, 'rt-1')
  assert.equal(second.scope, 'openid email')
  assert.equal(first.generation, 1)
  assert.equal(first.refreshToken, 'rt-1-rotated')
  assert.deepEqual(log, ['rt-1', 'rt-1'])
})

test('concurrent refreshes settle all callers when the request fails', async () => {
  const log: string[] = []
  const config = configWith(
    tokenEndpoint(log, async () => {
      await new Promise((resolve) => setTimeout(resolve, 20))
      return json({ error: 'temporarily_unavailable' }, { status: 503 })
    }),
  )
  const session = new client.TokenRefreshSession(config, {
    refresh_token: 'rt-1',
    scope: 'openid email',
  })

  const outcomes = await Promise.allSettled([
    session.refresh(),
    session.refresh(),
  ])

  assert.ok(outcomes.every((outcome) => outcome.status === 'rejected'))
  assert.deepEqual(log, ['rt-1'])
  assert.equal(session.generation, 0)
  assert.equal(session.refreshToken, 'rt-1')
  assert.equal(session.scope, 'openid email')
})
