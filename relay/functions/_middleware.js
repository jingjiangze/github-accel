// 私有 GitHub 中转：只放行 GitHub 相关域，必须带密钥，不是公开反代
//   路径形如 /r/<密钥>/https://github.com/<owner>/<repo>/releases/download/...
//   默认剥离客户端的 Authorization/Cookie，不把凭据透传给上游。
const ALLOW = new Set([
  'github.com',
  'raw.githubusercontent.com',
  'codeload.github.com',
  'objects.githubusercontent.com',
  // release 资产经常 302 到这里，缺了它 /releases/download 会在跳转终点被 403 卡住
  'release-assets.githubusercontent.com',
  'github-cloud.githubusercontent.com',
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
// 跳转链上每一跳都要重新过白名单：redirect:'follow' 只验证了第一跳
const MAX_HOPS = 5
// 请求侧必须透传的条件头：少了 Range，客户端设计好的"停滞换源续传"在 relay 上会退化成从 0 重下
const REQ_PASS = ['range', 'if-range', 'if-none-match', 'if-modified-since', 'cache-control']
// 响应侧对应的分片/缓存头，不透传客户端就无法断点续传、也无法正确缓存
const RES_PASS = ['content-range', 'accept-ranges', 'content-disposition', 'content-encoding']

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

function allowed(u) {
  try {
    const t = new URL(u)
    return t.protocol === 'https:' && ALLOW.has(t.hostname.toLowerCase())
  } catch (e) { return false }
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
  if (!allowed(target.toString())) return bad(403, 'host not allowed')

  const H = new Headers()
  // 保留客户端 UA：GitHub 靠 git/* 的 User-Agent 决定回 pkt-line 还是 HTML 页，
  // 改写它就会让 git clone 收到一坨网页而不是 refs
  H.set('user-agent', request.headers.get('user-agent') || 'git/2.50.0')
  H.set('accept-encoding', 'identity')
  H.set('accept', request.headers.get('accept') || '*/*')
  for (const name of REQ_PASS) {
    const v = request.headers.get(name)
    if (v) H.set(name, v)
  }
  if (request.method === 'POST') {
    const ct = request.headers.get('content-type'); if (ct) H.set('content-type', ct)
    const ce = request.headers.get('content-encoding'); if (ce) H.set('content-encoding', ce)
  }
  if (env.RELAY_ALLOW_AUTH === '1') {
    const auth = request.headers.get('authorization')
    if (auth) H.set('authorization', auth)
  }

  // 手动跟跳：每一跳都重新校验 host，最多 MAX_HOPS 跳，超出即拒。
  // 这样既支持 release 资产的正常跳转，也不会把 relay 变成"允许重定向的开放代理"。
  let hopUrl = target.toString()
  let up
  for (let hop = 0; ; hop++) {
    if (!allowed(hopUrl)) return bad(403, 'host not allowed')
    try {
      up = await fetch(hopUrl, {
        method: request.method,
        headers: H,
        redirect: 'manual',
        body: request.method === 'POST' ? request.body : undefined
      })
    } catch (e) {
      return bad(502, 'upstream fetch failed')
    }
    if (up.status < 300 || up.status >= 400) break
    const loc = up.headers.get('location')
    if (!loc) break
    if (hop >= MAX_HOPS) return bad(508, 'too many redirects')
    let next
    try { next = new URL(loc, hopUrl).toString() } catch (e) { return bad(502, 'bad redirect location') }
    if (!allowed(next)) return bad(403, 'redirect host not allowed: ' + new URL(next).hostname)
    // 3xx 的 body 对客户端无用，先释放
    try { await up.body.cancel() } catch (e) {}
    hopUrl = next
  }

  const out = new Headers()
  const ct = up.headers.get('content-type'); if (ct) out.set('content-type', ct)
  const cl = up.headers.get('content-length'); if (cl) out.set('content-length', cl)
  const cc = up.headers.get('cache-control'); out.set('cache-control', cc || 'public, max-age=300')
  const et = up.headers.get('etag'); if (et) out.set('etag', et)
  const last = up.headers.get('last-modified'); if (last) out.set('last-modified', last)
  for (const name of RES_PASS) {
    const v = up.headers.get(name)
    if (v) out.set(name, v)
  }
  out.set('x-relay-target', new URL(hopUrl).hostname)
  return new Response(up.body, { status: up.status, statusText: up.statusText, headers: out })
}
