// discover.mjs —— 候选发现：官方来源为主，第三方列表只当 hint
//   node discover.mjs [--force] [-v]
// 产物 candidates.json：{ at, sources:{...}, domains:{ <域>: [ {ip, src, fam} ] } }
//
// 为什么要分来源：本机实测 api.github.com 直连 200 而经代理 403（CF 出口被 GitHub 拉黑），
// 所以每个源都带自己的 via（direct/proxy），不能一刀切。
import fs from 'node:fs'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, 'config.json'), 'utf8'))
const OUT = path.join(HERE, 'candidates.json')
const ARGV = process.argv.slice(2)
const FORCE = ARGV.includes('--force')
const VERBOSE = ARGV.includes('-v')
const D = CFG.discovery || {}

function log() { console.log(Array.from(arguments).join(' ')) }
function run(exe, args, timeoutMs) {
  return new Promise(function (resolve) {
    execFile(exe, args, { maxBuffer: 64 * 1024 * 1024, windowsHide: true, timeout: timeoutMs, encoding: 'utf8' },
      function (err, out) { resolve({ code: err ? 1 : 0, stdout: out || '' }) })
  })
}
function rnd() { return Math.random() }

// ---------- 纯函数（可离线自测） ----------
function num4(ip) {
  const p = String(ip).trim().split('.')
  return (((+p[0]) << 24) | ((+p[1]) << 16) | ((+p[2]) << 8) | (+p[3])) >>> 0
}
function str4(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.') }
function isV4(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s).trim()) }
function isV6(s) { const t = String(s).trim(); return t.indexOf(':') >= 0 && /^[0-9a-fA-F:]+$/.test(t) }

// 每个 /24 抽 per24 个，而不是把整个网段扫完（CloudflareSpeedTest 就是这么控成本的）
function sampleCidr4(cidr, per24, rand) {
  const parts = String(cidr).trim().split('/')
  if (!isV4(parts[0])) return []
  const bits = parts[1] === undefined ? 32 : Number(parts[1])
  const n = num4(parts[0])
  const out = []
  if (bits >= 24) {
    const size = Math.pow(2, 32 - bits)
    out.push(str4(n))
    const step = Math.max(1, Math.floor(size / ((per24 || 1) + 1)))
    for (let i = 1; i <= (per24 || 1) && i * step < size; i++) out.push(str4((n + i * step) >>> 0))
    return out
  }
  const blocks = Math.pow(2, 24 - bits)
  for (let b = 0; b < blocks; b++) {
    const start = (n + b * 256) >>> 0
    for (let i = 0; i < (per24 || 1); i++) out.push(str4((start + 1 + Math.floor(rand() * 254)) >>> 0))
  }
  return out
}
// v6 网段太大，只按 /64 取网络地址（够用来当候选探针，不做全扫）
function sampleCidr6(cidr, per64) {
  const parts = String(cidr).trim().split('/')
  if (!isV6(parts[0])) return []
  const bits = parts[1] === undefined ? 128 : Number(parts[1])
  const head = parts[0].toLowerCase().split(':')
  const out = []
  const groups = Math.max(1, Math.min(4, Math.pow(2, Math.max(0, 64 - bits))))
  for (let g = 0; g < groups; g++) {
    const seg = head.slice(0, 4)
    out.push(seg.join(':') + '::' + (g + 1).toString(16))
  }
  return out.slice(0, per64 || 1)
}
function parseCidrList(text) {
  return String(text).split(/\s+/).map(function (s) { return s.trim() }).filter(function (s) { return s && s.indexOf('/') > 0 })
}
// GitHub /meta：按服务名分组 CIDR（hooks 之类给的是单 IP、domains 给的是域名，都不是 CIDR，丢掉）
function parseMeta(obj) {
  const out = {}
  for (const k of Object.keys(obj || {})) {
    const v = obj[k]
    if (Array.isArray(v) && v.length && typeof v[0] === 'string' && v[0].indexOf('/') > 0) out[k] = v
  }
  return out
}
function parseDoh(json) {
  const ips = []
  try {
    const o = JSON.parse(json)
    for (const a of (o.Answer || [])) if (a && (isV4(a.data) || isV6(a.data))) ips.push(String(a.data).trim())
  } catch (e) {}
  return ips
}
function parseThirdParty(text) {
  const map = {}
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+([a-z0-9._-]+)\s*$/i)
    if (!m) continue
    const ip = m[1], dom = m[2].toLowerCase()
    if (!isV4(ip) && !isV6(ip)) continue
    if (!map[dom]) map[dom] = []
    if (map[dom].indexOf(ip) < 0) map[dom].push(ip)
  }
  return map
}
function fam(ip) { return isV4(ip) ? 4 : (isV6(ip) ? 6 : 0) }
function dedupe(list) {
  const seen = new Set(), out = []
  for (const x of list) if (x && !seen.has(x)) { seen.add(x); out.push(x) }
  return out
}

// ---------- 取数 ----------
function curlArgs(src) {
  const a = ['-sS', '-g', '--ssl-no-revoke', '--connect-timeout', '6', '--max-time', '25']
  if (src.via === 'proxy' && D.proxy) a.push('-x', D.proxy)
  else a.push('--noproxy', '*')
  if (src.header) a.push('-H', src.header)
  return a
}
async function fetchSrc(src, ms) {
  const r = await run('curl.exe', curlArgs(src).concat([src.url]), ms || 30000)
  return r.stdout.length > 2 ? r.stdout : ''
}

async function main() {
  if (D.enabled === false) { log('discovery.enabled=false，跳过'); return }
  const prev = (function () { try { return JSON.parse(fs.readFileSync(OUT, 'utf8')) } catch (e) { return null } })()
  const freshH = D.refresh_h || 6
  if (!FORCE && prev && Date.now() - prev.at < freshH * 3600e3) {
    log('候选还在有效期内（' + freshH + 'h），用 --force 强制刷新'); return
  }
  const per24 = D.sample_per_24 || 1
  const cap = D.max_per_domain || 64
  const domains = {}
  const sources = {}
  const add = function (dom, ip, src) {
    if (!domains[dom]) domains[dom] = []
    if (!fam(ip)) return
    if (domains[dom].some(function (x) { return x.ip === ip })) return
    if (domains[dom].length >= cap) return
    domains[dom].push({ ip: ip, src: src, fam: fam(ip) })
  }

  // 1) 多 DoH 合并（不信单一 DNS 视角）。放在最前面：它是"当前真实答案"，
  //    而 meta/CF 只是官方网段里的抽样，配额不够时该先保 DoH。
  for (const dom of Object.keys(CFG.domains || {})) {
    for (const src of (D.doh || [])) {
      for (const type of ['A', 'AAAA']) {
        const u = { url: String(src.url).replace('DOMAIN', dom).replace('TYPE', type), via: src.via, header: src.header }
        const text = await fetchSrc(u, 15000)
        for (const ip of parseDoh(text)) add(dom, ip, 'doh:' + new URL(src.url).hostname)
      }
    }
  }
  sources.doh_domains = Object.keys(CFG.domains || {}).length

  // 2) GitHub /meta（按服务映射到本项目的域）
  if (D.github_meta && D.github_meta.url) {
    const text = await fetchSrc(D.github_meta, 30000)
    let meta = null
    try { meta = text ? parseMeta(JSON.parse(text)) : null } catch (e) { meta = null }
    if (meta) {
      sources.github_meta = Object.keys(meta)
      for (const dom of Object.keys(D.gh_domains || {})) {
        for (const svc of D.gh_domains[dom]) {
          for (const cidr of (meta[svc] || [])) {
            for (const ip of (fam(cidr.split('/')[0]) === 6 ? sampleCidr6(cidr, 1) : sampleCidr4(cidr, per24, rnd))) add(dom, ip, 'gh-meta:' + svc)
          }
        }
      }
      log('GitHub /meta 已解析：' + Object.keys(meta).length + ' 个服务')
    } else log('GitHub /meta 取不到，跳过（不影响其它来源）')
  }

  // 3) Cloudflare 官方网段（给 CF 前置的域）
  for (const [key, v6] of [['cf_ips4', false], ['cf_ips6', true]]) {
    const src = D[key]
    if (!src || !src.url) continue
    const text = await fetchSrc(src, 30000)
    const cidrs = parseCidrList(text)
    if (!cidrs.length) { log(key + ' 取不到，跳过'); continue }
    sources[key] = cidrs.length
    for (const dom of (D.cf_domains || [])) {
      for (const cidr of cidrs) {
        for (const ip of (v6 ? sampleCidr6(cidr, 1) : sampleCidr4(cidr, per24, rnd))) add(dom, ip, key)
      }
    }
    log(key + '：' + cidrs.length + ' 段 -> ' + (D.cf_domains || []).join('/'))
  }

  // 4) 第三方列表：只当 hint，不直接写 hosts；也只留本项目关心的域（列表里几百个域与本工具无关）
  const wanted = new Set(Object.keys(CFG.domains || {}))
  for (const url of (CFG.sources || [])) {
    const text = await fetchSrc({ url: url, via: 'direct' }, 20000)
    const map = parseThirdParty(text)
    let n = 0
    for (const dom of Object.keys(map)) {
      if (!wanted.has(dom)) continue
      for (const ip of map[dom]) { add(dom, ip, 'hint:' + new URL(url).hostname); n++ }
    }
    if (n) log('第三方 hint ' + new URL(url).hostname + '：' + n + ' 条')
  }

  // 5) 本机历史（warm pool）：上一份候选里被探过的照样保留，外部列表变了也不丢
  if (prev && prev.domains) {
    for (const dom of Object.keys(prev.domains)) {
      for (const e of prev.domains[dom]) if (e.src && e.src.indexOf('history') === 0) add(dom, e.ip, e.src)
    }
  }

  const out = { at: Date.now(), sources: sources, domains: domains }
  fs.writeFileSync(OUT, JSON.stringify(out, null, 1))
  const tot = Object.keys(domains).reduce(function (s, d) { return s + domains[d].length }, 0)
  log('候选已写入 candidates.json：' + Object.keys(domains).length + ' 域 / ' + tot + ' 个候选')
  if (VERBOSE) for (const d of Object.keys(domains)) log('  ', d.padEnd(30), domains[d].length + ' 个', '[' + dedupe(domains[d].map(function (x) { return x.src.split(':')[0] })).join(',') + ']')
}

if (ARGV.includes('--selftest')) {
  let bad = 0
  const T = function (name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want)
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
  }
  // 抽样：/24 至少给出网络地址本身，数量受 per24 约束
  const a = sampleCidr4('104.16.0.0/24', 1, function () { return 0.5 })
  T('/24 抽样含网络地址', a[0], '104.16.0.0')
  T('/24 抽样数量', a.length, 2)
  // 大段按 /24 抽：/22 = 4 个 /24，每 /24 一个
  const b = sampleCidr4('104.16.0.0/22', 1, function () { return 0.5 })
  T('/22 每 /24 抽一个', b.length, 4)
  T('/22 落在不同 /24', dedupe(b.map(function (x) { return x.split('.').slice(0, 3).join('.') })).length, 4)
  T('非 v4 段返回空', sampleCidr4('2606:50c0::/32', 1, rnd).length, 0)
  // /meta 解析：只收 CIDR 数组（单 IP 与域名列表丢掉）
  T('parseMeta 只收 CIDR 数组', parseMeta({ web: ['140.82.112.0/20'], hooks: ['1.2.3.4'], domains: ['github.com'] }), { web: ['140.82.112.0/20'] })
  // DoH 解析
  T('parseDoh 提取 A/AAAA', parseDoh(JSON.stringify({ Answer: [{ data: '20.205.243.166' }, { data: '2606:50c0::154' }, { data: 'x' }] })), ['20.205.243.166', '2606:50c0::154'])
  T('parseDoh 容错', parseDoh('not json'), [])
  // 第三方列表解析
  const tp = parseThirdParty('# comment\n20.205.243.166 github.com\n2606:50c0::154 raw.githubusercontent.com\nbad line\n')
  T('parseThirdParty 忽略注释与坏行', Object.keys(tp).sort(), ['github.com', 'raw.githubusercontent.com'])
  T('parseThirdParty 计数', tp['github.com'], ['20.205.243.166'])
  // 采样确定性：固定 rnd 时结果可复现
  T('抽样可复现', sampleCidr4('104.16.0.0/22', 2, function () { return 0.5 }), sampleCidr4('104.16.0.0/22', 2, function () { return 0.5 }))
  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测全部通过')
  process.exit(bad ? 1 : 0)
}

main().catch(function (e) { console.error('discover 失败：' + ((e && e.stack) || e)); process.exit(1) })
