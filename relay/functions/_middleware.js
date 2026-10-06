// 私有 GitHub 中转：只放行 GitHub 相关域，必须带密钥，不是公开反代
//   路径形如 /r/<密钥>/https://github.com/<owner>/<repo>/releases/download/...
//   默认剥离客户端的 Authorization/Cookie，不把凭据透传给上游。
const ALLOW = new Set([
  'github.com',
  'raw.githubusercontent.com',
  'codeload.github.com',
  'objects.githubusercontent.com',
  'gist.github.com',
  'gist.githubusercontent.com',
  'avatars.githubusercontent.com',
  'github.githubassets.com',
  'media.githubusercontent.com',
  'private-user-images.githubusercontent.com',
  'user-images.githubusercontent.com',
  'camo.githubusercontent.com',
  'desktop.githubusercontent.com',
  'notebook.githubusercontent.com'
])

function bad(status, why) {
  return new Response(why, { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } })
}

function same(a, b) {
  // 定长比较，避免按字符早退的时间侧信道
  const enc = new TextEncoder()
  const x = enc.encode(String(a)), y = enc.encode(String(b))
  if (x.length !== y.length) return false
  let diff = 0
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i]
  return diff === 0
}

export async function onRequest(ctx) {
  const { request, env } = ctx
  const key = env.RELAY_KEY
  if (!key) return bad(500, 'relay misconfigured: RELAY_KEY missing')

  const u = new URL(request.url)
  const m = u.pathname.match(/^\/r\/[^/]+\/(https?:\/\/.+)$/)
  if (!m) return ctx.next()
  if (!same(decodeURIComponent(u.pathname.split('/')[2] || ''), key)) return bad(403, 'bad key')
  if (['GET', 'HEAD', 'POST'].indexOf(request.method) < 0) return bad(405, 'method not allowed')

  let target
  try { target = new URL(m[1] + u.search) } catch (e) { return bad(400, 'bad target') }
  if (target.protocol !== 'https:' || !ALLOW.has(target.hostname.toLowerCase())) return bad(403, 'host not allowed')

  const H = new Headers()
  // 保留客户端 UA：GitHub 靠 git/* 的 User-Agent 决定回 pkt-line 还是 HTML 页，
  // 改写它就会让 git clone 收到一坨网页而不是 refs
  H.set('user-agent', request.headers.get('user-agent') || 'git/2.50.0')
  H.set('accept-encoding', 'identity')
  H.set('accept', request.headers.get('accept') || '*/*')
  if (request.method === 'POST') {
    const ct = request.headers.get('content-type'); if (ct) H.set('content-type', ct)
    const ce = request.headers.get('content-encoding'); if (ce) H.set('content-encoding', ce)
  }
  if (env.RELAY_ALLOW_AUTH === '1') {
    const auth = request.headers.get('authorization')
    if (auth) H.set('authorization', auth)
  }

  let up
  try {
    up = await fetch(target.toString(), {
      method: request.method,
      headers: H,
      redirect: 'follow',
      body: request.method === 'POST' ? request.body : undefined
    })
  } catch (e) {
    return bad(502, 'upstream fetch failed')
  }

  const out = new Headers()
  const ct = up.headers.get('content-type'); if (ct) out.set('content-type', ct)
  const cl = up.headers.get('content-length'); if (cl) out.set('content-length', cl)
  const cc = up.headers.get('cache-control'); out.set('cache-control', cc || 'public, max-age=300')
  const et = up.headers.get('etag'); if (et) out.set('etag', et)
  const last = up.headers.get('last-modified'); if (last) out.set('last-modified', last)
  out.set('x-relay-target', target.hostname)
  return new Response(up.body, { status: up.status, statusText: up.statusText, headers: out })
}
