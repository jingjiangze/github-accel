// gh.mjs —— GitHub 取件工具：入口实时竞速（不依赖"上次测速第一名"）
//   node gh.mjs <github-url> [输出文件名]              并发竞速下载，先出数据的胜出，停滞自动换源续传
//   node gh.mjs clone [git clone 参数...] <repo-url>    先并发探 info/refs 只留真 pkt-line 的入口，再克隆
//   node gh.mjs doctor [--force]                        入口体检（内容标记 + 带宽样本两级判定）
//   node gh.mjs list                                    打印缓存中的入口状态与评分
//   node gh.mjs --selftest                              离线自测（闸门 / 脱敏 / 评分 / 冷却，不联网）
import fs from 'node:fs'
import path from 'node:path'
import { execFile, spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, 'config.json'), 'utf8'))
const STATE = path.join(HERE, 'proxy-state.json')
const TTL = (CFG.proxy_ttl_s || 60) * 1000
const ARGV = process.argv.slice(2)
const SELFTEST = ARGV.includes('--selftest')

function run(exe, args, timeoutMs) {
  return new Promise(function (resolve) {
    execFile(exe, args, { maxBuffer: 64 * 1024 * 1024, windowsHide: true, timeout: timeoutMs || 60000, encoding: 'utf8' },
      function (err, out, errout) {
        resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: (out || '').trim(), stderr: (errout || '').trim() })
      })
  })
}
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
function tail(s) { const l = String(s || '').split(/\r?\n/).filter(Boolean); return l.length ? l[l.length - 1] : '' }
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms) }) }
function mbps(bps) { return (bps / 1048576).toFixed(2) }
function hostOf(p) { try { return new URL(p).hostname } catch (e) { return String(p) } }

// ---------- 安全闸门：只放行 GitHub 域，且一律不带凭据 ----------
// 下载与 clone 都必须先过这里；只保护 clone 等于把 README 的安全承诺留了个后门。
const GH_HOSTS = new Set([
  'github.com', 'www.github.com', 'api.github.com',
  'raw.githubusercontent.com', 'codeload.github.com',
  'objects.githubusercontent.com', 'release-assets.githubusercontent.com',
  'github-cloud.githubusercontent.com',
  'gist.github.com', 'gist.githubusercontent.com',
  'avatars.githubusercontent.com', 'github.githubassets.com',
  'media.githubusercontent.com', 'private-user-images.githubusercontent.com',
  'user-images.githubusercontent.com', 'camo.githubusercontent.com',
  'desktop.githubusercontent.com', 'notebook.githubusercontent.com'
])
function hostAllowed(h) {
  h = String(h || '').toLowerCase()
  if (GH_HOSTS.has(h)) return true
  // 允许 *.githubusercontent.com / *.github.com 这类官方子域，不放行 example.com 之类
  return /\.githubusercontent\.com$/.test(h) || /\.github\.com$/.test(h)
}
function credsRisk(u) {
  if (/oauth2:|x-access-token|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_|:\/\/[^/@:]+:[^@/]+@/.test(u)) return true
  try {
    const q = new URL(u).searchParams
    for (const k of ['access_token', 'authorization', 'token', 'client_secret', 'private_token', 'auth']) if (q.has(k)) return true
  } catch (e) {}
  return false
}
// 返回拒绝原因；null 表示放行
function gate(u) {
  let p
  try { p = new URL(u) } catch (e) { return '不是合法 URL' }
  if (p.protocol !== 'https:' && p.protocol !== 'http:') return '只接受 http/https'
  if (!hostAllowed(p.hostname)) return p.hostname + ' 不在 GitHub 白名单'
  if (credsRisk(u)) return '地址疑似带凭据'
  return null
}

// ---------- 私有 relay：真实前缀只在内存里，落盘/日志一律用别名 ----------
// 密钥写在 URL 路径里，任何一次 console.log 或 proxy-state.json 落盘都会把它泄漏到本地运行数据。
const RELAY_ALIAS = '__RELAY__'
let RELAY_REAL = null
function relayReal() {
  if (RELAY_REAL) return RELAY_REAL
  const r = CFG.relay
  if (!r || !r.enabled) return null
  let key = process.env[r.key_env] || ''
  if (!key) { try { key = fs.readFileSync(path.join(HERE, r.key_file), 'utf8').trim() } catch (e) {} }
  if (!key) return null
  RELAY_REAL = r.base.replace('KEY', encodeURIComponent(key))
  return RELAY_REAL
}
function isRelay(p) { return p === RELAY_ALIAS || (!!RELAY_REAL && p === RELAY_REAL) }
function maskPrefix(p) { return isRelay(p) ? String(CFG.relay.base).replace('KEY', '<REDACTED>') : p }
function label(p) { return isRelay(p) ? 'relay:' + hostOf(CFG.relay.base) : hostOf(p) }
function tierTag(t) { return t === 'manifest' ? '[清]' : t === 'explore' ? '[候]' : '[主]' }
function entryDefs(includeExplore, manifestU) {
  const list = (CFG.proxies || []).map(function (p) { return { key: p, prefix: p, tier: 'core' } })
  const rp = relayReal()
  if (rp) list.unshift({ key: RELAY_ALIAS, prefix: rp, tier: 'core' })
  // 候选池只做低频测量，不参与竞速：它的样本可能是一小时前的，拿它选路等于用陈旧数据
  if (includeExplore) {
    const seen = new Set(list.map(function (e) { return e.key }))
    for (const p of (CFG.proxies_explore || [])) if (!seen.has(p)) { seen.add(p); list.push({ key: p, prefix: p, tier: 'explore' }) }
    // 动态清单（Actions 在中立出口判过"还活着"的入口）：并进候选池，本机再实测一遍。
    // 同样只做候选、不参与竞速，也不改主清单——改 config 的 proxies 属于用户的决定。
    for (const p of (manifestU || [])) if (!seen.has(p)) { seen.add(p); list.push({ key: p, prefix: p, tier: 'manifest' }) }
  }
  return list
}

// ---------- 动态清单：Actions 体检出的 live 入口，本机当候选池消费 ----------
// 判定只有"存在性"（返回约定内容 + 能拉够数据），跟线路无关；排名仍由本机实测决定。
const MANIFEST_CACHE = path.join(HERE, (CFG.manifest && CFG.manifest.cache) || 'manifest-cache.json')
function readManifestCache() {
  try { return JSON.parse(fs.readFileSync(MANIFEST_CACHE, 'utf8')) } catch (e) { return null }
}
function manifestUrls() {
  const m = CFG.manifest || {}
  return [].concat(m.urls || []).filter(function (u) { return typeof u === 'string' && /^https?:\/\//.test(u) })
}
// 清单里可用的入口 URL（默认只取 ok=true 的；max_entries 防止清单无限膨胀把每轮体检拖长）
function manifestEntries(mf) {
  const m = CFG.manifest || {}
  const max = m.max_entries || 24
  let list = (mf && Array.isArray(mf.entries)) ? mf.entries : (mf && Array.isArray(mf.live)) ? mf.live.map(function (u) { return { url: u, ok: true } }) : []
  if (m.only_ok !== false) list = list.filter(function (e) { return e && e.ok })
  return list.map(function (e) { return e && e.url }).filter(function (u) { return typeof u === 'string' }).slice(0, max)
}
// 纯函数：把多个观测点的清单并成一个候选列表。顺序即优先级——config 里盒子在前，
// 所以并集被 max_entries 截断时留下的是盒子的入口（真实线路比中立出口更相关）。
function mergeManifests(list) {
  const out = [], seen = new Set(), sources = []
  for (const s of (list || [])) {
    const mf = s && s.mf
    if (!mf || !Array.isArray(mf.entries)) { sources.push({ url: s && s.url, ok: false }); continue }
    const picked = manifestEntries(mf)
    for (const u of picked) if (!seen.has(u)) { seen.add(u); out.push(u) }
    sources.push({
      url: s.url, ok: true, count: picked.length,
      vantage: (mf.runner && (mf.runner.vantage || mf.runner.os)) || '',
      generated_at: mf.generated_at || ''
    })
  }
  return { urls: out, sources: sources }
}
function sourceLabel(sources) {
  if (!sources || !sources.length) return ''
  return sources.map(function (s) {
    return s.ok ? ((s.vantage || hostOf(s.url)) + '(' + (s.count || 0) + ')') : (hostOf(s.url) + '(×)')
  }).join(' + ')
}
// 依次取 config 里的来源（盒子 → runner，各带 raw/jsDelivr 镜像），并成一个候选池后写本地缓存。
// 全部失败时退回上一份缓存（哪怕过期）——宁可候选陈旧，也不要在 GitHub 不通时把候选池清空。
async function loadManifest(force) {
  const m = CFG.manifest || {}
  if (!m.enabled) return { urls: [], at: 0, stale: false, source: 'disabled', sources: [] }
  const ttl = (m.ttl_h || 6) * 3600e3
  const cache = readManifestCache()
  if (!force && cache && cache.at && Date.now() - cache.at < ttl) {
    return { urls: manifestEntries(cache), at: cache.at, stale: false, source: sourceLabel(cache.sources), generated_at: cache.generated_at || '', sources: cache.sources || [] }
  }
  const fetched = []
  for (const url of manifestUrls()) {
    const r = await run('curl.exe', ['-sS', '-L', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '12', url], 16000)
    let mf = null
    if (r.code === 0 && r.stdout) { try { mf = JSON.parse(r.stdout) } catch (e) { mf = null } }
    fetched.push({ url: url, mf: mf })
  }
  const merged = mergeManifests(fetched)
  if (merged.urls.length) {
    const rec = { at: Date.now(), generated_at: merged.sources.reduce(function (a, s) { return s.generated_at && s.generated_at > a ? s.generated_at : a }, ''), sources: merged.sources, entries: merged.urls.map(function (u) { return { url: u, ok: true } }) }
    try { fs.writeFileSync(MANIFEST_CACHE, JSON.stringify(rec, null, 1)) } catch (e) {}
    return { urls: merged.urls, at: rec.at, stale: false, source: sourceLabel(merged.sources), generated_at: rec.generated_at, sources: merged.sources }
  }
  if (cache) return { urls: manifestEntries(cache), at: cache.at || 0, stale: true, source: sourceLabel(cache.sources) + '（取新失败，用缓存）', generated_at: cache.generated_at || '', sources: cache.sources || [] }
  return { urls: [], at: 0, stale: true, source: sourceLabel(merged.sources), sources: merged.sources }
}
// 候选池每 N 轮探一次（默认 6 轮 ≈ 1 小时，按 10 分钟一轮算）
function exploreDue(st) {
  const every = CFG.proxy_explore_every || 6
  if (every <= 0) return false
  return (((st && st.round) || 0) % every) === 0
}
// 状态文件里存的是别名；读取时再换回真实前缀，旧格式（直接存了真实 URL）顺手迁移
function resolveEntries(entries) {
  const rp = relayReal()
  const out = []
  for (const e of entries || []) {
    let key = e.prefix, prefix = key
    if (key === RELAY_ALIAS) prefix = rp
    else if (rp && key === rp) { key = RELAY_ALIAS; prefix = rp }
    if (!prefix) continue
    out.push(Object.assign({}, e, { prefix: prefix, key: key }))
  }
  return out
}

// ---------- 历史健康统计：不再"上次第一就永远第一" ----------
function pct(arr, p) {
  if (!arr || !arr.length) return 0
  const a = arr.slice().sort(function (x, y) { return x - y })
  const i = Math.min(a.length - 1, Math.max(0, Math.round((a.length - 1) * p)))
  return a[i]
}
function cooldownFor(streak, now) {
  const C = CFG.proxy_cooldown || {}
  if (streak >= (C.tier3_fails || 8)) return now + (C.tier3_ms || 24 * 3600e3)
  if (streak >= (C.tier2_fails || 5)) return now + (C.tier2_ms || 2 * 3600e3)
  if (streak >= (C.tier1_fails || 3)) return now + (C.tier1_ms || 30 * 60e3)
  return 0
}
function mergeHist(prev, cur, now) {
  const h = (prev && prev.hist) || {}
  const max = CFG.proxy_history_samples || 12
  const speeds = (h.speeds || []).slice(-(max - 1))
  const lats = (h.lats || []).slice(-(max - 1))
  if (cur.ok && cur.bps > 0) speeds.push(Math.round(cur.bps))
  if (cur.ok && cur.ms < 1e9) lats.push(cur.ms)
  const failStreak = cur.ok ? 0 : (h.fail_streak || 0) + 1
  return {
    samples: (h.samples || 0) + 1,
    ok_count: (h.ok_count || 0) + (cur.ok ? 1 : 0),
    speeds: speeds,
    lats: lats,
    fail_streak: failStreak,
    last_ok: cur.ok ? now : (h.last_ok || 0),
    cooldown_until: cur.ok ? 0 : cooldownFor(failStreak, now)
  }
}
function inCooldown(e, now) { return ((e.hist && e.hist.cooldown_until) || 0) > (now || Date.now()) }
// 稳定性 30 + 速度P50 25 + 速度P10 15 + 首字节延迟 15 + 失败率 10 + 新鲜度 5
const W = CFG.proxy_score_weights || { stability: 30, speed_p50: 25, speed_p10: 15, latency: 15, fail_rate: 10, freshness: 5 }
function scoreAll(entries, now) {
  const H = function (e) { return (e && e.hist) || {} }
  const sp50 = function (e) { return pct(H(e).speeds, 0.5) }
  const sp10 = function (e) { return pct(H(e).speeds, 0.1) }
  const lat50 = function (e) { return pct(H(e).lats, 0.5) }
  const maxSp50 = Math.max.apply(null, [1].concat(entries.map(sp50)))
  const maxSp10 = Math.max.apply(null, [1].concat(entries.map(sp10)))
  const latVals = entries.map(lat50).filter(function (v) { return v > 0 })
  const minLat = latVals.length ? Math.min.apply(null, latVals) : 1
  for (const e of entries) {
    const h = H(e)
    const stability = (h.ok_count || 0) / Math.max(1, h.samples || 1)
    const failScore = 1 - Math.min(1, (h.fail_streak || 0) / 5)
    const freshness = h.last_ok ? Math.exp(-(now - h.last_ok) / (CFG.proxy_freshness_ms || 3600e3)) : 0
    const norm = function (v, max) { return max > 0 ? Math.min(1, v / max) : 0 }
    const latScore = lat50(e) > 0 ? Math.min(1, minLat / lat50(e)) : 0
    e.score = Math.round((
      W.stability * stability +
      W.speed_p50 * norm(sp50(e), maxSp50) +
      W.speed_p10 * norm(sp10(e), maxSp10) +
      W.latency * latScore +
      W.fail_rate * failScore +
      W.freshness * freshness
    ) * 10) / 10
  }
  return entries
}

// ---------- 体检：内容标记 + 大文件带宽，两级判定 ----------
async function bulkSample(prefix) {
  const secs = Math.ceil((CFG.bulk_ms || 6000) / 1000)
  const r = await run('curl.exe', ['-sS', '-L', '-o', 'NUL', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', String(secs),
    '-w', '%{http_code} %{size_download} %{speed_download}', prefix + CFG.bulk_canary], (secs + 6) * 1000)
  const m = r.stdout.match(/^(\d+)\s+(\d+)\s+([\d.]+)/)
  const bytes = m ? Number(m[2]) : 0
  return { code: m ? Number(m[1]) : 0, bytes, bps: bytes > 0 ? Number(m[3]) : 0 }
}
// 正文与 curl 的 -w 尾巴拼在同一个 stdout 里，用不会出现在正文里的标记切开。
// 为什么不留临时文件：某些入口返回的是 HTML 拦截/跳转页，落盘后会被 Defender 判成
// Trojan:HTML/Redirector 并隔离（实测每小时一条事件 + 一条隔离记录），
// 而我们只需要在内存里找一下那几个字节的内容标记。
const TRAILER = '\n__GHW__'
function splitBody(stdout) {
  const s = String(stdout || '')
  const i = s.lastIndexOf(TRAILER)
  if (i < 0) return { body: '', meta: '' }
  return { body: s.slice(0, i), meta: s.slice(i + TRAILER.length) }
}
async function checkOne(def) {
  const prefix = def.prefix
  const r = await run('curl.exe', ['-sS', '-L', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '12',
    '--max-filesize', String(CFG.canary_max_bytes || 262144),
    '-w', TRAILER + '%{http_code} %{time_total} %{size_download}', prefix + CFG.proxy_canary], 18000)
  const sp = splitBody(r.stdout)
  const body = sp.body
  const m = sp.meta.match(/^(\d+)\s+([\d.]+)\s+(\d+)/)
  if (!m) return { prefix: def.key, ok: false, soft: false, ms: 1e9, code: 0, bytes: 0, bulk_code: 0, bulk_bytes: 0, bps: 0 }
  const code = Number(m[1]), ms = Math.round(Number(m[2]) * 1000)
  // 必须取回约定内容，免得把自建拦截页/错误页当成"通"
  const contentOk = code >= 200 && code < 400 && body.indexOf(CFG.canary_token) >= 0
  const bulk = contentOk ? await bulkSample(prefix) : { code: 0, bytes: 0, bps: 0 }
  // 内容标记只能证明"连上了"，还得真拉够一段数据：200 + 标记 + 543 字节错误页不能算 OK
  const bulkOk = bulk.code >= 200 && bulk.code < 400 && bulk.bytes >= (CFG.bulk_min_bytes || 1) && (bulk.bps || 0) >= (CFG.bulk_min_bps || 0)
  return { prefix: def.key, ok: contentOk && bulkOk, soft: contentOk, ms: ms, code: code, bytes: Number(m[3]), bulk_code: bulk.code, bulk_bytes: bulk.bytes, bps: bulk.bps }
}
function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')) } catch (e) { return null }
}
async function checkAll(force, withExplore) {
  const st = loadState()
  const fresh = st && Date.now() - st.at < TTL && (st.entries || []).some(function (e) { return e.ok || e.soft })
  if (fresh && !force) return st
  const prevByKey = new Map()
  for (const e of (st && st.entries) || []) prevByKey.set(e.prefix, e)
  const now = Date.now()
  const round = ((st && st.round) || 0) + 1
  const wantExplore = !!withExplore || exploreDue(st)
  // 清单只在探候选池那轮去取（默认约一小时一次），避免每 10 分钟都去拉一次远端
  const mf = wantExplore
    ? await loadManifest(false)
    : { urls: [], at: (st && st.manifest && st.manifest.at) || 0, stale: false, source: (st && st.manifest && st.manifest.source) || '', generated_at: (st && st.manifest && st.manifest.generated_at) || '' }
  const entries = await pool(entryDefs(wantExplore, mf.urls), CFG.proxy_probe_concurrency || 4, async function (d) {
    const r = await checkOne(d)
    r.tier = d.tier
    r.hist = mergeHist(prevByKey.get(d.key), r, now)
    return r
  })
  // 评分是整组相对量（按当前候选集归一化），所以在这里算完一起落盘，
  // 免得下游（accel 的 report.json、list）只能看到 undefined
  const out = {
    v: 2, at: now, round: round, explore: wantExplore, target: CFG.proxy_canary,
    manifest: { at: mf.at || 0, stale: !!mf.stale, source: mf.source || '', count: (mf.urls || []).length, generated_at: mf.generated_at || '' },
    entries: scoreAll(entries, now)
  }
  fs.writeFileSync(STATE, JSON.stringify(out, null, 1))
  return out
}
function order(st) {
  const now = Date.now()
  const entries = scoreAll(resolveEntries(st && st.entries), now)
  return entries.slice().sort(function (a, b) {
    const ca = inCooldown(a, now) ? 1 : 0, cb = inCooldown(b, now) ? 1 : 0
    if (ca !== cb) return ca - cb
    if (a.ok !== b.ok) return a.ok ? -1 : 1
    if ((b.score || 0) !== (a.score || 0)) return (b.score || 0) - (a.score || 0)
    if ((b.bps || 0) !== (a.bps || 0)) return (b.bps || 0) - (a.bps || 0)
    return a.ms - b.ms
  })
}
// 竞速取三路：最稳 / 本轮最快 / 样本最少的探索位，尽量落在不同 host 上——避免三个入口同属一个故障域
// strict=true 只认过了带宽门槛的；带宽门槛全灭时退化为"仅内容标记可用"，别让竞速直接无入口
function pickRacers(st, n, strict) {
  const now = Date.now()
  // 只有主清单（core）能进竞速：候选池（explore）与动态清单（manifest）都只做低频测量
  const ok = order(st).filter(function (e) { return (strict === false ? (e.ok || e.soft) : e.ok) && (e.tier || 'core') === 'core' })
  const usable = ok.filter(function (e) { return !inCooldown(e, now) })
  const base = usable.length ? usable : ok
  if (!CFG.proxy_race_diversity) return base.slice(0, n)
  const chosen = []
  const has = function (e) { return chosen.indexOf(e) >= 0 }
  const diffHost = function (e) { return !chosen.some(function (c) { return hostOf(c.prefix) === hostOf(e.prefix) }) }
  const add = function (e) { if (e && !has(e) && chosen.length < n) chosen.push(e) }
  add(base.slice().sort(function (a, b) { return (b.score || 0) - (a.score || 0) })[0])
  const fast = base.slice().sort(function (a, b) { return (b.bps || 0) - (a.bps || 0) })
  add(fast.filter(function (e) { return !has(e) && diffHost(e) })[0] || fast[0])
  const explore = base.filter(function (e) { return !has(e) && diffHost(e) })
    .sort(function (a, b) { return ((a.hist && a.hist.samples) || 0) - ((b.hist && b.hist.samples) || 0) })
  add(explore[0])
  for (const e of base) add(e)
  return chosen
}

// ---------- 竞速下载 ----------
function startCurl(url, file, resume) {
  const args = ['-fsS', '-L', '--ssl-no-revoke', '--connect-timeout', '5', '--max-time', String(CFG.race.max_time_s || 900)]
  if (resume) args.push('-C', '-')
  args.push('-o', file, '-w', '%{http_code} %{size_download} %{speed_download}', url)
  const child = spawn('curl.exe', args, { windowsHide: true })
  const rec = { child: child, out: '', done: false, code: null, killed: false }
  child.stdout.on('data', function (b) { rec.out += b.toString() })
  child.stderr.on('data', function (b) { rec.err = (rec.err || '') + b.toString() })
  child.on('exit', function (c) { rec.done = true; rec.code = c })
  child.on('error', function (e) { rec.done = true; rec.code = 1; rec.err = String(e) })
  return rec
}
function statSize(f) { try { return fs.statSync(f).size } catch (e) { return 0 } }

async function race(url, name) {
  const why = gate(url)
  if (why) { console.error('拒绝：' + why + '。只经反代取 GitHub 内容，且不携带凭据。'); process.exit(2) }
  const st = await checkAll(false)
  const N = Math.max(CFG.race.max || 3, 2)
  let cands = pickRacers(st, N, true)
  if (!cands.length) {
    cands = pickRacers(st, N, false)
    if (cands.length) console.warn('  没有入口过带宽门槛，退化为仅内容标记可用')
  }
  if (!cands.length) { console.error('体检里没有可用入口，跑 node gh.mjs doctor --force'); process.exit(3) }
  const R = CFG.race
  const parts = cands.slice(0, Math.max(R.max, 2)).map(function (e, i) {
    return { entry: e, file: name + '.part' + i, proc: null, last: 0, stale: 0, tries: 0, firstSeen: 0 }
  })
  const launch = function (p, resume) {
    p.proc = startCurl(p.entry.prefix + url, p.file, !!resume)
    p.firstSeen = Date.now()
  }
  parts.slice(0, R.max).forEach(function (p) { launch(p, false) })
  console.log('  并发竞速：' + parts.map(function (p) { return label(p.entry.prefix) }).join(' | '))

  let winner = null, report = null
  const deadline = Date.now() + (R.wall_ms || 300000)
  while (!winner && Date.now() < deadline) {
    await sleep(1000)
    for (const p of parts) {
      const sz = statSize(p.file)
      if (p.proc && p.proc.done) {
        const ok = p.proc.code === 0
        if (ok) { winner = p; report = p.proc.out; break }
        if (sz > 0 && p.tries < (R.retries_per_entry || 2)) { p.tries++; launch(p, true); continue }
        p.proc = null
        continue
      }
      if (!p.proc) continue
      // 从没拿到字节的入口早点踢掉
      if (sz === 0 && Date.now() - p.firstSeen > R.first_byte_ms) { p.proc.child.kill(); p.proc = null; continue }
      // 增速低于阈值的判停滞，换源续传
      if (sz > 0 && sz - p.last < R.speed_limit_bps && Date.now() - p.stale > R.speed_time_ms) {
        p.proc.child.kill(); p.last = sz; p.stale = Date.now()
        if (p.tries < (R.retries_per_entry || 2)) { p.tries++; launch(p, true) } else p.proc = null
        continue
      }
      if (sz > p.last) { p.last = sz; p.stale = Date.now() }
    }
    if (winner) break
    const live = parts.filter(function (p) { return p.proc && !p.proc.done })
    // 领先者甩开足够多时收回备用带宽，但只保留前二
    if (live.length > 2) {
      const bySize = live.slice().sort(function (a, b) { return statSize(b.file) - statSize(a.file) })
      const lead = statSize(bySize[0].file)
      bySize.slice(2).forEach(function (p) { if (statSize(p.file) < lead / 3) { p.proc.child.kill(); p.proc = null } })
    }
    const alive = parts.filter(function (p) { return p.proc && !p.proc.done }).length
    if (alive === 0) {
      const next = parts.filter(function (p) { return !p.proc })
      if (next.length) launch(next[0], statSize(next[0].file) > 0)
      else break
    }
    const tot = parts.reduce(function (s, p) { return s + statSize(p.file) }, 0)
    if (Date.now() % 4000 < 1100) process.stdout.write('  进度 ' + tot + ' 字节\r')
  }
  parts.forEach(function (p) { if (p.proc && !p.proc.done) { try { p.proc.child.kill() } catch (e) {} } })

  if (!winner) {
    parts.forEach(function (p) { try { fs.unlinkSync(p.file) } catch (e) {} })
    console.error('竞速失败：没有入口拿到完整文件')
    process.exit(4)
  }
  const m = String(report || '').match(/^(\d+)\s+(\d+)\s+([\d.]+)/)
  try { if (fs.existsSync(name)) fs.unlinkSync(name) } catch (e) {}
  fs.renameSync(winner.file, name)
  parts.forEach(function (p) { if (p !== winner) { try { fs.unlinkSync(p.file) } catch (e) {} } })
  console.log('完成  ' + name + '  ' + (m ? m[2] : statSize(name)) + ' 字节  ' + mbps(m ? Number(m[3]) : 0) + ' MB/s  经 ' + label(winner.entry.prefix) +
    (winner.tries ? '（续传 ' + winner.tries + ' 次）' : ''))
}

// ---------- 竞速克隆 ----------
async function probeRefs(repo) {
  const st = await checkAll(false)
  const N = Math.max(CFG.race.max || 3, 2)
  const cands = pickRacers(st, N, true)
  const out = []
  await pool(cands, CFG.proxy_probe_concurrency || 4, async function (e) {
    const u = e.prefix + repo + '/info/refs?service=git-upload-pack'
    // 同样不落盘：入口返回 HTML 页时，写出的文件会被 Defender 判成跳转木马
    const r = await run('curl.exe', ['-sS', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '10',
      '--max-filesize', '65536', '-H', 'User-Agent: git/2.50.0', '-w', TRAILER + '%{http_code}', u], 14000)
    const sp = splitBody(r.stdout)
    const body = sp.body.slice(0, 200)
    // 必须是 pkt-line（十六进制长度开头），不是 HTML 页
    const ok = sp.meta === '200' && /^[0-9a-f]{4}# service=git-upload-pack/.test(body)
    out.push({ entry: e, ok: ok, head: body.slice(0, 24) })
  })
  return out.filter(function (x) { return x.ok }).map(function (x) { return x.entry })
}

async function clone(args) {
  const repo = args.filter(function (a) { return /^https?:\/\//.test(a) })[0]
  if (!repo) { console.error('clone 需要仓库 URL'); process.exit(2) }
  const why = gate(repo)
  if (why) { console.error('拒绝：' + why + '。只经反代克隆 GitHub 仓库，且不携带凭据。'); process.exit(2) }
  const rest = args.filter(function (a) { return a !== repo })
  let candidates = await probeRefs(repo)
  if (!candidates.length) {
    const st = await checkAll(true)
    candidates = pickRacers(st, Math.max(CFG.race.max || 3, 2), false)
    console.log('  info/refs 探测没选出可用入口，退化为按体检评分顺序重试')
  }
  if (!candidates.length) { console.error('没有可用入口'); process.exit(3) }
  const C = CFG.clone || {}
  for (const e of candidates) {
    for (let attempt = 1; attempt <= (C.same_retry || 2); attempt++) {
      process.stdout.write('  经 ' + label(e.prefix) + ' 第' + attempt + ' 次 ... ')
      const gitArgs = ['-c', 'http.version=HTTP/1.1',
        '-c', 'http.lowSpeedLimit=' + (C.low_speed_limit || 1024),
        '-c', 'http.lowSpeedTime=' + (C.low_speed_time || 20),
        '-c', 'url.' + e.prefix + 'https://github.com/.insteadOf=https://github.com/']
        .concat(['clone'], rest, [repo])
      const r = await run('git.exe', gitArgs, 1800000)
      if (r.code === 0) { console.log('完成'); return }
      console.log('失败 ' + tail(r.stderr))
      const dirs = rest.filter(function (x) { return x.charAt(0) !== '-' })
      const dirname = dirs.length > 1 ? dirs[1] : repo.replace(/\.git$/, '').split('/').pop()
      try { if (dirname && fs.existsSync(dirname)) fs.rmSync(dirname, { recursive: true, force: true }) } catch (x) {}
      // schannel 随机握手失败（实测约 1/3 概率）值得原地重试一次
      if (!/handshake|RPC failed|empty reply|Failed to connect/i.test(r.stderr)) break
    }
  }
  console.error('全部入口失败'); process.exit(4)
}

async function doctor(show, explore) {
  const st = await checkAll(show, explore)
  const now = Date.now()
  console.log('入口体检 @ ' + new Date(st.at).toLocaleString() + '  第 ' + st.round + ' 轮' + (st.explore ? '（含候选池）' : '') +
    '  目标 ' + st.target + (show ? '' : '  (缓存 ' + (CFG.proxy_ttl_s || 60) + 's)'))
  if (st.manifest && (st.manifest.count || st.manifest.at)) {
    console.log('  动态清单：' + st.manifest.count + ' 个候选' + (st.manifest.generated_at ? '，生成于 ' + st.manifest.generated_at : '') +
      (st.manifest.stale ? '（取新失败，用的是缓存）' : '') + (st.manifest.source ? '  ← ' + st.manifest.source : ''))
  }
  for (const e of order(st)) console.log('  ' + (e.ok ? 'OK  ' : (e.soft ? 'SOFT' : 'DEAD')) + ' ' + tierTag(e.tier) + ' ' +
    maskPrefix(e.prefix).padEnd(46) +
    (e.ms === 1e9 ? '     -' : (String(e.ms) + 'ms').padStart(7)) +
    '  实测 ' + mbps(e.bps || 0).padStart(6) + ' MB/s  评分 ' + String(e.score || 0).padStart(5) +
    ' code=' + e.code + '/' + e.bulk_code + ' 样本=' + (e.bulk_bytes || 0) +
    (inCooldown(e, now) ? '  [冷却中]' : ''))
  // 候选池（含动态清单）里翻身的入口不会自动进主清单（改 config 属于用户的决定），这里点名提示
  if (st.explore) {
    const promoted = order(st).filter(function (e) { return (e.tier === 'explore' || e.tier === 'manifest') && e.ok })
    console.log(promoted.length
      ? '  候选池本轮可用：' + promoted.map(function (e) { return maskPrefix(e.prefix) + '（' + mbps(e.bps || 0) + ' MB/s）' }).join('、') +
        '  —— 想启用请加进 config.json 的 proxies'
      : '  候选池本轮无可用入口')
  }
}
function list() {
  try {
    const now = Date.now()
    for (const e of order(loadState())) console.log((e.ok ? 'OK   ' : (e.soft ? 'SOFT ' : 'DEAD ')) + tierTag(e.tier) + ' ' +
      maskPrefix(e.prefix).padEnd(46) + '  ' + mbps(e.bps || 0) + ' MB/s  评分 ' + (e.score || 0) + (inCooldown(e, now) ? '  [冷却中]' : ''))
  } catch (e) { console.log('无体检记录，先跑 node gh.mjs doctor') }
}

// ---------- 离线自测（不联网、不落盘） ----------
if (SELFTEST) {
  let bad = 0
  const T = function (name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want)
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
  }
  // 闸门：下载与 clone 同一套规则，GitHub 域放行、别的一律拒
  T('github release 放行', gate('https://github.com/a/b/releases/download/v1/x.zip'), null)
  T('raw 放行', gate('https://raw.githubusercontent.com/a/b/main/c'), null)
  T('release-assets 放行', gate('https://release-assets.githubusercontent.com/x'), null)
  T('gist 子域放行', gate('https://gist.github.com/abc'), null)
  T('非 GitHub 域被拒', typeof gate('https://example.com/x'), 'string')
  T('内嵌账密被拒', typeof gate('https://user:pw@github.com/a/b'), 'string')
  T('access_token 被拒', typeof gate('https://github.com/a/b?access_token=xyz'), 'string')
  T('ghp_ 令牌被拒', typeof gate('https://github.com/a/b/ghp_abcdefghijklmnop'), 'string')
  T('伪 github 域被拒', typeof gate('https://github.com.evil.tld/a'), 'string')
  // 脱敏：别名永远解析成 <REDACTED>，真实密钥不进任何产物
  T('别名脱敏', maskPrefix(RELAY_ALIAS), String(CFG.relay.base).replace('KEY', '<REDACTED>'))
  T('脱敏不含密钥字样', maskPrefix(RELAY_ALIAS).indexOf('<REDACTED>') >= 0, true)
  T('别名标签不泄漏路径', label(RELAY_ALIAS).indexOf('/r/') < 0, true)
  T('普通入口不改写', maskPrefix('https://ghfast.top/'), 'https://ghfast.top/')
  // 正文与 -w 尾巴的切分（不落盘方案的核心）：标记取最后一个，因为尾巴总在末尾
  T('切分正文与尾巴', splitBody('hello\n__GHW__200 1.5 5'), { body: 'hello', meta: '200 1.5 5' })
  T('没有尾巴时返回空', splitBody('just body'), { body: '', meta: '' })
  T('正文里出现同样标记时取最后一个', splitBody('a__GHW__b\n__GHW__404'), { body: 'a__GHW__b', meta: '404' })
  T('空输入不炸', splitBody(''), { body: '', meta: '' })
  // 冷却阶梯
  T('两次失败不冷却', cooldownFor(2, 1000), 0)
  T('三次失败进入 30 分钟冷却', cooldownFor(3, 1000) - 1000, 30 * 60e3)
  T('五次失败进入 2 小时冷却', cooldownFor(5, 1000) - 1000, 2 * 3600e3)
  T('八次失败进入 24 小时冷却', cooldownFor(8, 1000) - 1000, 24 * 3600e3)
  // 历史合并：连续失败要累计，成功后清零并解除冷却
  const h1 = mergeHist({ hist: { samples: 1, ok_count: 1, speeds: [100], lats: [10], fail_streak: 0, last_ok: 1 } }, { ok: false, bps: 0, ms: 1e9 }, 2000)
  T('失败累计样本', h1.samples, 2)
  T('失败不涨 ok_count', h1.ok_count, 1)
  T('连续失败累计', h1.fail_streak, 1)
  T('成功清零失败串', mergeHist({ hist: { fail_streak: 4, samples: 4, ok_count: 0 } }, { ok: true, bps: 50, ms: 20 }, 3000).fail_streak, 0)
  T('成功解除冷却', mergeHist({ hist: { fail_streak: 4, samples: 4, ok_count: 0, cooldown_until: 99999 } }, { ok: true, bps: 50, ms: 20 }, 3000).cooldown_until, 0)
  // 评分：稳定型要压过"单次很快但不稳"的入口（审计里的核心诉求）
  const now0 = Date.now()
  const stable = { prefix: 'https://a/', ok: true, bps: 1000, ms: 100, hist: { samples: 10, ok_count: 10, speeds: [1000, 1000, 1000], lats: [100, 100, 100], fail_streak: 0, last_ok: now0 } }
  const flaky = { prefix: 'https://b/', ok: true, bps: 3000, ms: 50, hist: { samples: 10, ok_count: 5, speeds: [1000, 2000, 3000], lats: [50, 60, 70], fail_streak: 2, last_ok: now0 } }
  scoreAll([stable, flaky], now0)
  T('稳定型评分高于波动型', stable.score > flaky.score, true)
  // 排序：冷却中的入口排到最后
  const stx = { entries: [
    { prefix: 'https://cool/', ok: true, bps: 9000, ms: 10, hist: { samples: 5, ok_count: 1, fail_streak: 5, cooldown_until: Date.now() + 60000 } },
    { prefix: 'https://warm/', ok: true, bps: 100, ms: 200, hist: { samples: 5, ok_count: 5, fail_streak: 0, cooldown_until: 0 } }
  ] }
  T('冷却入口排最后', order(stx)[1].prefix, 'https://cool/')
  // 多样性：三路竞速要尽量落在不同 host
  const sty = { entries: [
    { prefix: 'https://x1/', ok: true, bps: 100, ms: 10, hist: { samples: 3, ok_count: 3, fail_streak: 0, speeds: [100], lats: [10] } },
    { prefix: 'https://x2/', ok: true, bps: 9000, ms: 20, hist: { samples: 3, ok_count: 3, fail_streak: 0, speeds: [9000], lats: [20] } },
    { prefix: 'https://y1/', ok: true, bps: 500, ms: 30, hist: { samples: 1, ok_count: 1, fail_streak: 0, speeds: [500], lats: [30] } }
  ] }
  const picked = pickRacers(sty, 3)
  T('三路竞速取满', picked.length, 3)
  T('三路竞速不同 host', new Set(picked.map(function (e) { return hostOf(e.prefix) })).size, 3)
  // 状态迁移：旧格式里直接存了真实 relay URL，读取时要换成别名，不能原样留在内存里当 key
  const rp0 = relayReal()
  if (rp0) {
    const migrated = resolveEntries([{ prefix: rp0, ok: true }])[0]
    T('旧格式迁移成别名', migrated.key, RELAY_ALIAS)
    T('迁移后前缀仍是真实地址', migrated.prefix, rp0)
  } else {
    console.log('  SKIP  未配置 relay-key，跳过旧格式迁移用例')
  }
  // 候选池（explore）只做低频测量，不参与竞速——它的样本可能是一小时前的
  const stz = { entries: [
    { prefix: 'https://core/', ok: true, bps: 100, ms: 10, tier: 'core', hist: { samples: 3, ok_count: 3, fail_streak: 0, speeds: [100], lats: [10] } },
    { prefix: 'https://exp/', ok: true, bps: 9999, ms: 5, tier: 'explore', hist: { samples: 3, ok_count: 3, fail_streak: 0, speeds: [9999], lats: [5] } }
  ] }
  const pz = pickRacers(stz, 3)
  T('候选池即使更快也不参与竞速', pz.length === 1 && pz[0].prefix === 'https://core/', true)
  // 候选池探测节奏：无状态时先探一次（做初始发现），之后每 N 轮一次
  T('首轮探候选池', exploreDue(null), true)
  T('第 1 轮不探候选池', exploreDue({ round: 1 }), false)
  T('第 6 轮探候选池', exploreDue({ round: 6 }), true)
  // 动态清单：并进候选池（tier=manifest）、与主清单去重、同样不参与竞速
  T('清单入口标成 manifest 层', entryDefs(true, ['https://mf.test/']).filter(function (e) { return e.prefix === 'https://mf.test/' })[0].tier, 'manifest')
  T('清单与主清单去重', entryDefs(true, ['https://gh-proxy.com/']).filter(function (e) { return e.prefix === 'https://gh-proxy.com/' }).length, 1)
  T('不探候选池时不带清单入口', entryDefs(false, ['https://mf.test/']).some(function (e) { return e.tier === 'manifest' }), false)
  T('清单默认只取 ok 的', manifestEntries({ entries: [{ url: 'https://a/', ok: true }, { url: 'https://b/', ok: false }] }), ['https://a/'])
  T('清单兼容只有 live 数组', manifestEntries({ live: ['https://c/'] }), ['https://c/'])
  T('清单数量有上限', manifestEntries({ entries: Array.from({ length: 100 }, function (_, i) { return { url: 'https://x' + i + '/', ok: true } }) }).length, (CFG.manifest && CFG.manifest.max_entries) || 24)
  T('清单标签', tierTag('manifest'), '[清]')
  const stm = { entries: [
    { prefix: 'https://core2/', ok: true, bps: 100, ms: 10, tier: 'core', hist: { samples: 3, ok_count: 3, fail_streak: 0, speeds: [100], lats: [10] } },
    { prefix: 'https://mf2/', ok: true, bps: 9999, ms: 5, tier: 'manifest', hist: { samples: 3, ok_count: 3, fail_streak: 0, speeds: [9999], lats: [5] } }
  ] }
  const pm = pickRacers(stm, 3)
  T('清单入口不参与竞速', pm.length === 1 && pm[0].prefix === 'https://core2/', true)
  // 多观测点合并：盒子（真实线路）在前，与 runner 的并集去重
  const mm = mergeManifests([
    { url: 'https://raw/manifest-box/proxies.json', mf: { generated_at: '2026-10-10T12:00:00Z', runner: { vantage: 'box-shandong' }, entries: [{ url: 'https://a/', ok: true }] } },
    { url: 'https://raw/manifest/proxies.json', mf: { generated_at: '2026-10-10T11:00:00Z', runner: { vantage: 'runner' }, entries: [{ url: 'https://a/', ok: true }, { url: 'https://b/', ok: true }, { url: 'https://dead/', ok: false }] } }
  ])
  T('合并去重且盒子在前', mm.urls, ['https://a/', 'https://b/'])
  T('合并保留各观测点计数', mm.sources.map(function (s) { return s.vantage + ':' + s.count }), ['box-shandong:1', 'runner:2'])
  T('合并标签', sourceLabel(mm.sources), 'box-shandong(1) + runner(2)')
  const mm2 = mergeManifests([{ url: 'https://x/', mf: null }, { url: 'https://y/', mf: { entries: [{ url: 'https://c/', ok: true }], runner: { vantage: 'box' } } }])
  T('坏来源不致命', [mm2.urls, mm2.sources[0].ok], [['https://c/'], false])
  T('全坏来源给空列表', mergeManifests([{ url: 'https://x/', mf: null }]).urls, [])
  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测全部通过')
  process.exit(bad ? 1 : 0)
}

const a = ARGV[0]
if (!a) console.log(['用法:', '  node gh.mjs <github-url> [输出文件名]', '  node gh.mjs clone [git clone 参数...] <repo-url>', '  node gh.mjs doctor --force [--explore]', '  node gh.mjs list', '  node gh.mjs --selftest', '说明: 竞速选路，不依赖上次测速结果；只取 GitHub 域，带凭据的地址一律拒绝外送'].join('\n'))
else if (a === 'doctor') await doctor(ARGV.includes('--force'), ARGV.includes('--explore'))
else if (a === 'list') list()
else if (a === 'clone') await clone(ARGV.slice(1))
else if (/^https?:\/\//.test(a)) await race(a, ARGV[1] || decodeURIComponent(a.split('/').pop().split('?')[0]) || 'download.bin')
else console.log('未识别的参数：' + a)
