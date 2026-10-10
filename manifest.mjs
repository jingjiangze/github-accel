// manifest.mjs —— 反代入口「动态清单」的生成器：在 GitHub Actions 的中立出口上体检候选入口，
// 产出 proxies.json；本机 gh.mjs 把它当作候选池消费（见 config.json 的 manifest 段）。
//
//   node manifest.mjs [--out dist/proxies.json] [--seed manifest-seed.json] [--concurrency 4]
//   node manifest.mjs --selftest
//
// 判定只有一种含义：**这个入口本身还活着吗**——返回约定的 canary 内容、能真拉够一段数据。
// 这跟线路无关，所以放在中立出口上测是有效的。但「谁最快」强依赖线路，runner 的数字对本机
// 没有参考价值——排名必须留给本机实测（README「为什么是竞速而不是选最快的入口」）。
//
// 跨平台：只依赖 Node 内置 fetch（runner 是 Linux，本机是 Windows），不调 curl.exe。
// 单点失败不影响整体：任何一个入口探测抛错都只记进它自己的 err 字段。
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ARGV = process.argv.slice(2)
const SELFTEST = ARGV.includes('--selftest')

function opt(name, dflt) {
  const i = ARGV.indexOf('--' + name)
  return i >= 0 && ARGV[i + 1] && !ARGV[i + 1].startsWith('--') ? ARGV[i + 1] : dflt
}

const CFG = JSON.parse(fs.readFileSync(path.join(HERE, 'config.json'), 'utf8'))
const UA = 'github-accel-manifest/1 (+https://github.com/jingjiangze/github-accel)'
const PROBE_MS = Number(CFG.manifest_probe_ms || 12000)
const BULK_MS = Number(CFG.bulk_ms || 6000)
const BULK_MAX_BYTES = Number(CFG.bulk_max_bytes || 4 * 1024 * 1024)
const CANARY_MAX_BYTES = Number(CFG.canary_max_bytes || 262144)

// 可替换，方便离线自测打桩（生产就是 Node 内置 fetch）
let fetchImpl = globalThis.fetch

async function pool(items, size, worker) {
  const out = []
  let i = 0
  async function slot() {
    while (true) {
      const k = i++
      if (k >= items.length) return
      out[k] = await worker(items[k])
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(size, items.length)) }, slot))
  return out
}

// ---------- 候选来源 ----------
// 种子清单（manifest-seed.json，人工维护的「待测集合」）+ 本机 config 里正在用/在测的入口。
// 官方入口不会因为「这次没人报」而被丢掉：种子清单是并集，只增不减。
function normalize(u) {
  try {
    const p = new URL(u)
    return p.origin + p.pathname.replace(/\/*$/, '/')
  } catch (e) { return null }
}
function candidates(seedFile) {
  const out = []
  const seen = new Set()
  const add = function (u) {
    const n = normalize(u)
    if (!n || seen.has(n)) return
    seen.add(n)
    out.push(n)
  }
  try {
    const seed = JSON.parse(fs.readFileSync(seedFile, 'utf8'))
    for (const u of (seed.candidates || [])) add(u)
  } catch (e) { /* 种子清单缺失不算错误，config 里的入口仍然要测 */ }
  for (const u of (CFG.proxies || [])) add(u)
  for (const u of (CFG.proxies_explore || [])) add(u)
  return out
}

// ---------- 探测 ----------
// 读流到 maxBytes 或 timeoutMs 为止；首字节时间与累计字节都返回，避免把大响应整个拉下来。
// 关键：超时是用 AbortController 打断读流的，所以**状态码必须在拿到响应头时就记下来**——
// 否则慢但可用的入口（实测 ghproxy.net 2.7MB/6s）会在 abort 时把 200 一起丢掉，被判成不可用。
async function fetchCapped(url, maxBytes, timeoutMs, headers) {
  const ac = new AbortController()
  const timer = setTimeout(function () { ac.abort() }, timeoutMs)
  const t0 = Date.now()
  let firstByte = 0, bytes = 0, code = 0, hdrs = null, err = ''
  const chunks = []
  try {
    const res = await fetchImpl(url, {
      redirect: 'follow',
      signal: ac.signal,
      headers: Object.assign({ 'user-agent': UA, accept: '*/*' }, headers || {})
    })
    code = res.status
    hdrs = res.headers
    if (res.body) {
      const reader = res.body.getReader()
      while (true) {
        const step = await reader.read()
        if (step.done) break
        if (!firstByte) firstByte = Date.now()
        bytes += step.value.length
        chunks.push(Buffer.from(step.value))
        if (bytes >= maxBytes || Date.now() - t0 >= timeoutMs) { try { await reader.cancel() } catch (e) {} break }
      }
    }
  } catch (e) {
    const aborted = e && (e.name === 'AbortError' || /abort/i.test(String(e.message || '')))
    err = aborted ? 'timeout after ' + timeoutMs + 'ms' : String((e && e.message) || e)
  } finally {
    clearTimeout(timer)
  }
  return { code: code, headers: hdrs, body: Buffer.concat(chunks), bytes: bytes, ttfb: firstByte ? firstByte - t0 : 0, ms: Date.now() - t0, err: err }
}

async function probeOne(prefix) {
  const rec = { url: prefix, ok: false, soft: false, content: false, range: false, code: 0, ms: 1e9, ttfb: 0, bytes: 0, bulk_code: 0, bulk_bytes: 0, bps: 0, err: '' }
  const canary = await fetchCapped(prefix + CFG.proxy_canary, CANARY_MAX_BYTES, PROBE_MS, null)
  rec.code = canary.code
  rec.ms = canary.ms
  rec.ttfb = canary.ttfb
  rec.bytes = canary.bytes
  rec.err = canary.err
  // 必须取回约定内容：只看状态码会把自建拦截页/错误页当成"通"
  rec.content = canary.code >= 200 && canary.code < 400 && canary.body.toString('utf8').indexOf(CFG.canary_token) >= 0
  if (!rec.content) return rec
  // Range 能力：本机竞速靠 Range 换源续传，入口不吃 Range 就少一条腿
  const rg = await fetchCapped(prefix + CFG.proxy_canary, 2048, PROBE_MS, { range: 'bytes=0-1023' })
  rec.range = rg.code === 206 || !!(rg.headers && rg.headers.get && rg.headers.get('content-range'))
  // 带宽样本：内容标记只证明"连上了"，还得真拉够一段数据（200 + 标记 + 543 字节错误页不算 OK）
  const bulk = await fetchCapped(prefix + CFG.bulk_canary, BULK_MAX_BYTES, BULK_MS, null)
  rec.bulk_code = bulk.code
  rec.bulk_bytes = bulk.bytes
  rec.bps = bulk.bytes > 0 ? Math.round(bulk.bytes / (Math.max(1, bulk.ms) / 1000)) : 0
  rec.soft = true
  rec.ok = bulk.code >= 200 && bulk.code < 400 && bulk.bytes >= (CFG.bulk_min_bytes || 1) && rec.bps >= (CFG.bulk_min_bps || 0)
  return rec
}

// ---------- 产物 ----------
function runnerInfo() {
  const e = process.env
  const repo = e.GITHUB_REPOSITORY || ''
  return {
    os: e.RUNNER_OS || process.platform,
    arch: e.RUNNER_ARCH || process.arch,
    repository: repo,
    run_id: e.GITHUB_RUN_ID || '',
    run_url: repo && e.GITHUB_RUN_ID ? 'https://github.com/' + repo + '/actions/runs/' + e.GITHUB_RUN_ID : ''
  }
}
function buildManifest(entries) {
  const sorted = entries.slice().sort(function (a, b) {
    if (a.ok !== b.ok) return a.ok ? -1 : 1
    if ((b.bps || 0) !== (a.bps || 0)) return (b.bps || 0) - (a.bps || 0)
    return (a.ms || 1e9) - (b.ms || 1e9)
  })
  const count = function (f) { return sorted.filter(f).length }
  return {
    schema: 1,
    generated_at: new Date().toISOString(),
    note: '中立出口（GitHub Actions runner）对入口做的"存在性"体检：ok=返回约定内容且能拉够数据。判定与线路无关，可用于筛选与淘汰；不要用它排名——排名必须由本机实测。',
    runner: runnerInfo(),
    canary: { url: CFG.proxy_canary, token: CFG.canary_token, bulk_url: CFG.bulk_canary },
    thresholds: { bulk_min_bytes: CFG.bulk_min_bytes || 1, bulk_min_bps: CFG.bulk_min_bps || 0, probe_ms: PROBE_MS, bulk_ms: BULK_MS, bulk_max_bytes: BULK_MAX_BYTES },
    counts: { probed: sorted.length, ok: count(function (e) { return e.ok }), soft: count(function (e) { return e.soft && !e.ok }), dead: count(function (e) { return !e.soft && !e.ok }) },
    live: sorted.filter(function (e) { return e.ok }).map(function (e) { return e.url }),
    entries: sorted
  }
}

async function main() {
  const seedFile = path.resolve(opt('seed', path.join(HERE, 'manifest-seed.json')))
  const outFile = path.resolve(opt('out', path.join(HERE, 'dist', 'proxies.json')))
  const conc = Math.max(1, Number(opt('concurrency', CFG.proxy_probe_concurrency || 4)) || 4)
  const list = candidates(seedFile)
  console.log('候选 ' + list.length + ' 个，并发 ' + conc + '，canary ' + CFG.proxy_canary)
  const entries = await pool(list, conc, function (p) {
    return probeOne(p).catch(function (e) { return { url: p, ok: false, soft: false, content: false, range: false, code: 0, ms: 1e9, ttfb: 0, bytes: 0, bulk_code: 0, bulk_bytes: 0, bps: 0, err: String((e && e.message) || e) } })
  })
  const mf = buildManifest(entries)
  fs.mkdirSync(path.dirname(outFile), { recursive: true })
  fs.writeFileSync(outFile, JSON.stringify(mf, null, 1) + '\n')
  console.log('ok ' + mf.counts.ok + ' / soft ' + mf.counts.soft + ' / dead ' + mf.counts.dead + ' → ' + outFile)
  for (const e of mf.live) console.log('  OK   ' + e)
  // 一个都不活：多半是 runner 网络或上游 canary 出问题，别把空清单推上去覆盖上一份可用的
  if (!mf.counts.ok) {
    console.error('没有任何入口通过内容级体检：不发布（保留上一份清单）')
    process.exitCode = 1
  }
}

// ---------- 离线自测（打桩 fetch，不联网、不落盘） ----------
if (SELFTEST) {
  let bad = 0
  const T = function (name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want)
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
  }
  const streamOf = function (buf) {
    let sent = false
    return { getReader: function () { return { read: async function () { if (sent) return { done: true }; sent = true; return { done: false, value: new Uint8Array(buf) } }, cancel: async function () {} } } }
  }
  const headersOf = function (o) { return { get: function (k) { return (o || {})[String(k).toLowerCase()] || null } } }
  const res = function (status, buf, hdr) { return { status: status, headers: headersOf(hdr), body: streamOf(buf) } }

  const healthy = Buffer.from('xx' + CFG.canary_token + 'yy')
  const big = Buffer.alloc(Number(CFG.bulk_min_bytes || 262144) + 1024, 0x41)
  const tiny = Buffer.alloc(543, 0x42)
  const plan = {
    // 健康：内容标记 + 206 + 拉满带宽门槛
    'https://good.test/': function (url) {
      if (url.indexOf(CFG.bulk_canary) >= 0) return Promise.resolve(res(200, big))
      return Promise.resolve(res(200, healthy, { 'content-range': 'bytes 0-1023/2048' }))
    },
    // 拦截页：200 但没有约定内容
    'https://waf.test/': function () { return Promise.resolve(res(200, Buffer.from('<html>blocked</html>'))) },
    // 连不上
    'https://dead.test/': function () { return Promise.reject(new Error('connect ECONNREFUSED')) },
    // 内容对但只有 543 字节错误页 → SOFT（不能算 OK）
    'https://tiny.test/': function (url) {
      if (url.indexOf(CFG.bulk_canary) >= 0) return Promise.resolve(res(200, tiny))
      return Promise.resolve(res(200, healthy))
    },
    // 慢但能拉：读流中途被 abort（超时）时，HTTP 状态码不能跟着丢
    'https://slow.test/': function (url) {
      if (url.indexOf(CFG.bulk_canary) >= 0) {
        const reader = { getReader: function () { let n = 0; return { read: async function () { if (n++ === 0) return { done: false, value: new Uint8Array(Number(CFG.bulk_min_bytes || 262144) + 1024) }; const e = new Error('The operation was aborted'); e.name = 'AbortError'; throw e }, cancel: async function () {} } } }
        return Promise.resolve({ status: 200, headers: headersOf({}), body: reader })
      }
      return Promise.resolve(res(200, healthy))
    }
  }
  fetchImpl = function (url) {
    for (const k of Object.keys(plan)) if (url.indexOf(k) === 0) return plan[k](url)
    return Promise.reject(new Error('no plan for ' + url))
  }

  const normalizeCases = [
    ['https://a.test', 'https://a.test/'],
    ['https://a.test/', 'https://a.test/'],
    ['https://a.test/gh//', 'https://a.test/gh/'],
    ['not a url', null]
  ]
  for (const c of normalizeCases) T('normalize ' + c[0], normalize(c[0]), c[1])

  const main = async function () {
    const good = await probeOne('https://good.test/')
    T('健康入口 ok', [good.ok, good.soft, good.content, good.range, good.code], [true, true, true, true, 200])
    const waf = await probeOne('https://waf.test/')
    T('拦截页不算通', [waf.ok, waf.soft, waf.content, waf.code], [false, false, false, 200])
    const dead = await probeOne('https://dead.test/')
    T('连不上记 code=0 + err', [dead.ok, dead.content, dead.code, dead.err.length > 0], [false, false, 0, true])
    const tiny2 = await probeOne('https://tiny.test/')
    T('小样本只算 SOFT', [tiny2.ok, tiny2.soft, tiny2.content], [false, true, true])
    const slow = await probeOne('https://slow.test/')
    T('读流被 abort 仍保留状态码', [slow.ok, slow.soft, slow.bulk_code, slow.bulk_bytes > 0], [true, true, 200, true])

    const mf = buildManifest([dead, tiny2, good, waf])
    T('清单 schema', mf.schema, 1)
    T('清单计数', mf.counts, { probed: 4, ok: 1, soft: 1, dead: 2 })
    T('live 只有 ok 的', mf.live, ['https://good.test/'])
    T('排序 ok 在前', mf.entries.map(function (e) { return e.ok }), [true, false, false, false])
    T('阈值随 config', mf.thresholds.bulk_min_bytes, CFG.bulk_min_bytes || 1)
    T('runner 信息有 os', typeof mf.runner.os, 'string')

    console.log(bad ? '  ' + bad + ' 项未通过' : '  全部通过')
    process.exitCode = bad ? 1 : 0
  }
  main()
} else {
  main()
}
