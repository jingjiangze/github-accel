// pool.mjs —— 候选健康池：把"每轮从头随机探一堆"换成"按历史挑少数几个探"
//
// 模型：Candidate -> Probe -> Health -> Score -> Diversity -> Active/Reserve/Explorer/Quarantine
//   - candidates.json（discover.mjs 产出）是"有哪些候选"；
//   - pool-state.json 是"每个候选在本机实测的历史表现"；
//   - accel.mjs 每轮只向 probes() 要一小撮 IP 去探，探完用 record() 写回。
//
// 时间分层（配置在 config.json 的 pool 段）：
//   每轮（10 分钟）只探 probe_per_round 个；其中 explore_ratio 比例留给"没试过的"，
//   其余给历史表现好的；慢速下载测速（speed）由 accel 按 speed_every_rounds 低频触发。
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const STATE = path.join(HERE, 'pool-state.json')
const CANDS = path.join(HERE, 'candidates.json')

function isV4(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s || '').trim()) }
function isV6(s) { const t = String(s || '').trim(); return t.indexOf(':') >= 0 && /^[0-9a-fA-F:]+$/.test(t) }
function fam(ip) { return isV4(ip) ? 4 : (isV6(ip) ? 6 : 0) }
function key(dom, ip) { return dom + '|' + ip }
// 同一 /24（v4）或 /64（v6）当作一个故障域，避免一撮候选全落在同一个前缀里
function prefixOf(ip) {
  if (isV4(ip)) return ip.split('.').slice(0, 3).join('.')
  const seg = String(ip).split(':').filter(Boolean)
  return seg.slice(0, 4).join(':')
}
function pct(arr, p) {
  if (!arr || !arr.length) return 0
  const a = arr.slice().sort(function (x, y) { return x - y })
  const i = Math.min(a.length - 1, Math.max(0, Math.round((a.length - 1) * p)))
  return a[i]
}

// 连续失败冷却：坏候选不该每 10 分钟被重新撞一次
function cooldownFor(streak, now, C) {
  C = C || {}
  if (streak >= (C.tier3_fails || 8)) return now + (C.tier3_ms || 24 * 3600e3)
  if (streak >= (C.tier2_fails || 5)) return now + (C.tier2_ms || 2 * 3600e3)
  if (streak >= (C.tier1_fails || 3)) return now + (C.tier1_ms || 30 * 60e3)
  return 0
}

export function mergeObs(prev, obs, now, cfg) {
  const P = (cfg && cfg.pool) || {}
  const max = P.history_samples || 16
  const e = prev ? Object.assign({}, prev) : { samples: 0, ok_count: 0, fail_streak: 0, lats: [], speeds: [], last_ok: 0, cooldown_until: 0, speed_at: 0 }
  e.samples = (e.samples || 0) + 1
  if (obs.ok) {
    e.ok_count = (e.ok_count || 0) + 1
    e.fail_streak = 0
    e.cooldown_until = 0
    e.last_ok = now
    e.lats = (e.lats || []).concat([obs.ms]).slice(-max)
    if (obs.speed > 0) { e.speeds = (e.speeds || []).concat([obs.speed]).slice(-max); e.speed_at = now }
  } else {
    e.fail_streak = (e.fail_streak || 0) + 1
    e.cooldown_until = cooldownFor(e.fail_streak, now, P.cooldown)
  }
  if (obs.code) e.last_code = obs.code
  e.last_at = now
  if (obs.src) e.src = obs.src
  return e
}

// 评分权重按审计建议：可用率 35 / 延迟P50 20 / 延迟P95 10 / 速度P50 20 / 速度P10 5 / 抖动 5 / 新鲜度 5
export function scoreDomain(entries, now, cfg) {
  const W = ((cfg && cfg.pool) || {}).score_weights ||
    { available: 35, lat_p50: 20, lat_p95: 10, speed_p50: 20, speed_p10: 5, jitter: 5, freshness: 5 }
  const arr = Object.keys(entries).map(function (k) { return entries[k] })
  const maxSpeed = Math.max.apply(null, [1].concat(arr.map(function (e) { return pct(e.speeds, 0.5) })))
  const maxSpeed10 = Math.max.apply(null, [1].concat(arr.map(function (e) { return pct(e.speeds, 0.1) })))
  const latVals = arr.map(function (e) { return pct(e.lats, 0.5) }).filter(function (v) { return v > 0 })
  const minLat = latVals.length ? Math.min.apply(null, latVals) : 1
  const freshMs = ((cfg && cfg.pool) || {}).freshness_ms || 3600e3
  for (const e of arr) {
    const available = (e.ok_count || 0) / Math.max(1, e.samples || 1)
    const l50 = pct(e.lats, 0.5), l95 = pct(e.lats, 0.95)
    const sp50 = pct(e.speeds, 0.5), sp10 = pct(e.speeds, 0.1)
    const jitter = (l95 && l50) ? Math.min(1, Math.abs(l95 - l50) / Math.max(1, l50)) : 0
    const fresh = e.last_ok ? Math.exp(-(now - e.last_ok) / freshMs) : 0
    const norm = function (v, max) { return max > 0 ? Math.min(1, v / max) : 0 }
    e.score = Math.round((
      W.available * available +
      W.lat_p50 * (l50 > 0 ? Math.min(1, minLat / l50) : 0) +
      W.lat_p95 * (l95 > 0 ? Math.min(1, minLat / l95) : 0) +
      W.speed_p50 * norm(sp50, maxSpeed) +
      W.speed_p10 * norm(sp10, maxSpeed10) +
      W.jitter * (1 - jitter) +
      W.freshness * fresh
    ) * 10) / 10
  }
  return arr
}

export function inCooldown(e, now) { return ((e && e.cooldown_until) || 0) > (now || Date.now()) }

// 每轮该探哪些：exploit（历史好的）+ explore（没试过的），并做前缀多样性约束
export function pickProbes(entries, candList, n, rand, cfg) {
  const P = (cfg && cfg.pool) || {}
  const now = Date.now()
  const minSamples = P.min_samples || 2
  const ratio = P.explore_ratio === undefined ? 0.15 : P.explore_ratio
  const capPerPrefix = P.max_per_prefix || 2
  const all = Object.keys(entries).map(function (k) { return Object.assign({ ip: entries[k].ip }, entries[k]) })
  const usable = all.filter(function (e) { return !inCooldown(e, now) })
  const known = usable.filter(function (e) { return (e.samples || 0) >= minSamples }).sort(function (a, b) { return (b.score || 0) - (a.score || 0) })
  const tried = new Set(all.map(function (e) { return e.ip }))
  const fresh = (candList || []).filter(function (c) { return !tried.has(c.ip) })
  const out = []
  const prefixCount = {}
  const push = function (ip, src, why) {
    if (!fam(ip) || out.some(function (x) { return x.ip === ip })) return false
    const p = prefixOf(ip)
    if ((prefixCount[p] || 0) >= capPerPrefix) return false
    prefixCount[p] = (prefixCount[p] || 0) + 1
    out.push({ ip: ip, src: src || '', why: why })
    return true
  }
  const wantExplore = Math.max(1, Math.round(n * ratio))
  // explore 先挑"完全没试过的"，不够再挑样本最少的
  let ex = 0
  for (const c of fresh) { if (ex >= wantExplore) break; if (push(c.ip, c.src, 'explore:new')) ex++ }
  if (ex < wantExplore) {
    const low = usable.filter(function (e) { return (e.samples || 0) < minSamples }).sort(function (a, b) { return (a.samples || 0) - (b.samples || 0) })
    for (const e of low) { if (ex >= wantExplore) break; if (push(e.ip, e.src, 'explore:low-sample')) ex++ }
  }
  for (const e of known) { if (out.length >= n) break; push(e.ip, e.src, 'exploit:score') }
  for (const c of fresh) { if (out.length >= n) break; push(c.ip, c.src, 'explore:fill') }
  return out.slice(0, n)
}

export function rank(entries, cfg) {
  const now = Date.now()
  return scoreDomain(entries, now, cfg).sort(function (a, b) {
    const ca = inCooldown(a, now) ? 1 : 0, cb = inCooldown(b, now) ? 1 : 0
    if (ca !== cb) return ca - cb
    return (b.score || 0) - (a.score || 0)
  })
}

export function buckets(entries, cfg) {
  const P = (cfg && cfg.pool) || {}
  const now = Date.now()
  const minSamples = P.min_samples || 2
  const ranked = rank(entries, cfg)
  const active = [], reserve = [], explorer = [], quarantine = []
  for (const e of ranked) {
    const avail = (e.ok_count || 0) / Math.max(1, e.samples || 1)
    if (inCooldown(e, now)) quarantine.push(e)
    else if ((e.samples || 0) < minSamples) explorer.push(e)
    else if (avail >= (P.active_ok_rate || 0.6)) active.push(e)
    else reserve.push(e)
  }
  return { active: active, reserve: reserve, explorer: explorer, quarantine: quarantine }
}

// ---------- 文件 I/O ----------
export function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')) } catch (e) { return { v: 1, entries: {} } }
}
export function saveState(st) { fs.writeFileSync(STATE, JSON.stringify(st, null, 1)) }
export function loadCandidates() {
  try { return JSON.parse(fs.readFileSync(CANDS, 'utf8')) } catch (e) { return null }
}

// 给 accel 用的便捷封装：读盘 -> 选探针 -> 记录 -> 落盘
export function open(cfg) {
  const st = loadState()
  const cands = loadCandidates()
  if (!st.entries) st.entries = {}
  const on = !!(cfg.pool && cfg.pool.enabled) && !!cands
  return {
    on: on,
    candidatesAt: cands ? cands.at : 0,
    probes: function (dom, n, rand) {
      const list = (cands && cands.domains && cands.domains[dom]) || []
      const mine = {}
      for (const k of Object.keys(st.entries)) if (st.entries[k].dom === dom) mine[k] = st.entries[k]
      const picked = pickProbes(mine, list, n, rand || Math.random, cfg)
      return picked.map(function (p) {
        // 只有已知候选才带来源标签，避免污染
        const c = list.find(function (x) { return x.ip === p.ip })
        return { ip: p.ip, src: c ? c.src : (p.src || ''), why: p.why }
      })
    },
    record: function (dom, ip, obs) {
      const k = key(dom, ip)
      st.entries[k] = mergeObs(st.entries[k], obs, Date.now(), cfg)
      st.entries[k].dom = dom
      st.entries[k].ip = ip
      return st.entries[k]
    },
    ranked: function (dom) {
      const mine = {}
      for (const k of Object.keys(st.entries)) if (st.entries[k].dom === dom) mine[k] = st.entries[k]
      return rank(mine, cfg)
    },
    buckets: function (dom) {
      const mine = {}
      for (const k of Object.keys(st.entries)) if (st.entries[k].dom === dom) mine[k] = st.entries[k]
      return buckets(mine, cfg)
    },
    save: function () { st.at = Date.now(); saveState(st) },
    raw: st
  }
}

// ---------- CLI ----------
const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
if (isMain) {
  const CFG = JSON.parse(fs.readFileSync(path.join(HERE, 'config.json'), 'utf8'))
  const ARGV = process.argv.slice(2)
  if (ARGV.includes('--selftest')) {
    let bad = 0
    const T = function (name, got, want) {
      const ok = JSON.stringify(got) === JSON.stringify(want)
      if (!ok) bad++
      console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
    }
    const now = Date.now()
    // 观测合并：成功清零失败串并解除冷却，失败累计
    const a1 = mergeObs(null, { ok: true, ms: 100, speed: 0 }, now, CFG)
    T('首次成功', [a1.samples, a1.ok_count, a1.fail_streak], [1, 1, 0])
    const a2 = mergeObs(mergeObs(mergeObs(null, { ok: false, ms: 0 }, now, CFG), { ok: false, ms: 0 }, now, CFG), { ok: false, ms: 0 }, now, CFG)
    T('三次失败进冷却', a2.cooldown_until - now, 30 * 60e3)
    const a3 = mergeObs(a2, { ok: true, ms: 50 }, now, CFG)
    T('成功解除冷却', [a3.fail_streak, a3.cooldown_until], [0, 0])
    // 历史窗口有上限
    let e = null
    for (let i = 0; i < 40; i++) e = mergeObs(e, { ok: true, ms: 10 + i }, now, CFG)
    T('延迟样本被截断到上限', e.lats.length, (CFG.pool && CFG.pool.history_samples) || 16)
    // 评分是排序信号：延迟/速度相同的情况下，可用率高的必须更高。
    // 注意"快但不稳"得分可能更高——可用率由 active_ok_rate 在分桶时单独把关，不靠评分。
    const entries = {
      'x|1.1.1.1': { dom: 'x', ip: '1.1.1.1', samples: 10, ok_count: 10, fail_streak: 0, lats: [100, 100, 100], speeds: [1e6], last_ok: now },
      'x|2.2.2.2': { dom: 'x', ip: '2.2.2.2', samples: 10, ok_count: 4, fail_streak: 2, lats: [100, 100, 100], speeds: [1e6], last_ok: now }
    }
    const sc = scoreDomain(entries, now, CFG)
    const s1 = sc.find(function (x) { return x.ip === '1.1.1.1' }), s2 = sc.find(function (x) { return x.ip === '2.2.2.2' })
    T('同延迟同速度时可用率高的评分更高', s1.score > s2.score, true)
    T('可用率不足的进不了 active', buckets(entries, CFG).active.some(function (x) { return x.ip === '2.2.2.2' }), false)
    // 探针挑选：explore 比例、去重、前缀多样性
    const cands = []
    for (let i = 0; i < 30; i++) cands.push({ ip: '104.16.' + (i % 10) + '.' + (Math.floor(i / 10) + 1), src: 'test' })
    const picked = pickProbes({}, cands, 10, function () { return 0.5 }, CFG)
    T('探针数量受上限约束', picked.length, 10)
    T('探针不重复', new Set(picked.map(function (p) { return p.ip })).size, 10)
    const prefixCount = {}
    for (const p of picked) { const k = prefixOf(p.ip); prefixCount[k] = (prefixCount[k] || 0) + 1 }
    T('同前缀不超过上限', Math.max.apply(null, Object.keys(prefixCount).map(function (k) { return prefixCount[k] })) <= (CFG.pool.max_per_prefix || 2), true)
    T('全部标记为 explore', picked.every(function (p) { return p.why.indexOf('explore') === 0 }), true)
    // 冷却中的候选不会被选中
    const cold = { 'y|9.9.9.9': { dom: 'y', ip: '9.9.9.9', samples: 9, ok_count: 9, fail_streak: 5, lats: [10], speeds: [], last_ok: now, cooldown_until: now + 60e3 } }
    T('冷却中的候选不入选', pickProbes(cold, [], 5, function () { return 0.5 }, CFG).length, 0)
    // 分桶
    const bk = buckets(Object.assign({}, entries, cold), CFG)
    T('冷却进 quarantine', bk.quarantine.length, 1)
    T('高可用进 active', bk.active.some(function (x) { return x.ip === '1.1.1.1' }), true)
    console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测全部通过')
    process.exit(bad ? 1 : 0)
  }
  const P = open(CFG)
  const only = ARGV[0] && ARGV[0] !== 'show' ? ARGV[0] : null
  const doms = only ? [only] : Object.keys(CFG.domains || {})
  console.log('候选池 @ ' + new Date(P.candidatesAt).toLocaleString() + '  ' + (P.on ? '(启用)' : '(未启用：缺 candidates.json)'))
  for (const d of doms) {
    const b = P.buckets(d)
    const n = b.active.length + b.reserve.length + b.explorer.length + b.quarantine.length
    if (!n) continue
    console.log('  ' + d + '  active=' + b.active.length + ' reserve=' + b.reserve.length + ' explorer=' + b.explorer.length + ' quarantine=' + b.quarantine.length)
    for (const e of b.active.slice(0, 5)) console.log('      [act] ' + e.ip.padEnd(28) + ' score=' + String(e.score).padStart(5) + ' lat50=' + pct(e.lats, 0.5) + 'ms ok=' + e.ok_count + '/' + e.samples)
    for (const e of b.quarantine.slice(0, 3)) console.log('      [qua] ' + e.ip.padEnd(28) + ' fail=' + e.fail_streak)
  }
}
