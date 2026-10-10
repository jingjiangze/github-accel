// 本机自适应 hosts：候选 IP（含 IPv6）全部来自实测，只有真的比现状快才写入
import fs from 'node:fs'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { promises as dnsp } from 'node:dns'
import { open as openPool } from './pool.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
// 候选健康池（pool.mjs）：每轮只探一小撮，探完写回历史。未启用时为 null，走旧的候选来源。
let POOL = null
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, 'config.json'), 'utf8'))
const MARK_S = '# >>> accel-start >>> 本机实测自动生成，请勿手工编辑'
const MARK_E = '# <<< accel-end <<<'
const LOGDIR = path.join(HERE, 'logs')
const LOG = path.join(LOGDIR, 'accel-' + new Date().toISOString().slice(0, 10) + '.log')
const ARGV = process.argv.slice(2)
const DRY = ARGV.includes('--dry')
const REVERT = ARGV.includes('--revert')
const VERBOSE = ARGV.includes('-v')
const SELFTEST = ARGV.includes('--selftest')
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/
const IPV6 = /^[0-9a-f:]+$/i
const DOMRE = /^[a-z0-9._-]+$/i

function now() { return new Date().toISOString().slice(11, 19) }
function log() {
  const line = now() + ' ' + Array.from(arguments).join(' ')
  console.log(line)
  try { fs.appendFileSync(LOG, line + '\r\n') } catch (e) {}
}
// 同一时刻只允许一轮：hosts 是读-改-写，两轮重叠会互相覆盖。
// 用 O_EXCL 原子创建，别用"先 stat 再 write"——两个实例会同时判"不存在"然后一起拿到锁。
const LOCK = path.join(HERE, 'run.lock')
const LOCK_STALE = 8 * 60 * 1000
function acquireLock() {
  for (let i = 0; i < 3; i++) {
    try {
      const fd = fs.openSync(LOCK, 'wx')
      fs.writeSync(fd, process.pid + ' ' + new Date().toISOString())
      fs.closeSync(fd)
      return
    } catch (e) {
      if (e.code !== 'EEXIST') { log('锁创建异常：' + (e.code || e.message) + '，本轮继续'); return }
    }
    let st = null
    try { st = fs.statSync(LOCK) } catch (x) { continue }
    if (Date.now() - st.mtimeMs < LOCK_STALE) { log('已有实例在跑（锁未过期），本轮退出'); process.exit(0) }
    log('发现过期锁，接管')
    try { fs.unlinkSync(LOCK) } catch (x) {}
  }
  log('锁竞争未落定，本轮退出')
  process.exit(0)
}
function releaseLock() { try { fs.unlinkSync(LOCK) } catch (e) {} }

// 系统代理（Clash 混合端口）是否可用：可用时 github.com 这类主域交给它，
// 因为实测该域直连候选在 000 与 0.5s 之间反复翻，而代理 4/4 稳定；代理挂了才由 hosts 顶上。
async function proxyGate() {
  const g = CFG.proxy_gate
  if (!g || !g.enabled) return { alive: false, ms: 0, skipped: false }
  const r = await run('curl.exe', ['-sS', '-o', 'NUL', '--ssl-no-revoke', '-x', g.proxy, '--connect-timeout', '4',
    '--max-time', String(Math.ceil((g.timeout_ms || 8000) / 1000)), '-w', '%{http_code} %{time_total}', g.test_url], (g.timeout_ms || 8000) + 4000)
  const m = r.stdout.match(/^(\d+)\s+([\d.]+)/)
  const code = m ? Number(m[1]) : 0
  return { alive: code >= 200 && code < 400, ms: m ? Math.round(Number(m[2]) * 1000) : 1e9, domains: g.handoff_domains || [] }
}

function run(exe, args, timeoutMs) {
  return new Promise(function (resolve) {
    execFile(exe, args, { maxBuffer: 32 * 1024 * 1024, windowsHide: true, timeout: timeoutMs || 25000, encoding: 'utf8' },
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
function fam(ip) { return IPV4.test(ip) ? 4 : (IPV6.test(ip) && ip.indexOf(':') >= 0 ? 6 : 0) }

// 代理内核（mihomo/Clash）的 fake-ip 段。系统解析落在这里 = DNS 被 TUN 的 dns-hijack 接管：
// 此时 hosts 层被架空，写进去的固定也必然复核失败，工具会把自己上一轮的固定全部撤销。
// 关掉 TUN 之后解析还会在缓存里残留一段 fake-ip，那段时间直连是「全都连不上」的。
const FAKE4 = CFG.fake_ip_ranges4 || ['198.18.0.0/16']
const FAKE6 = CFG.fake_ip_ranges6 || ['fdfe:dcba:9876::/64']
function num4(ip) {
  const p = ip.split('.')
  return (((+p[0]) << 24) | ((+p[1]) << 16) | ((+p[2]) << 8) | (+p[3])) >>> 0
}
function norm6(ip) {
  const parts = String(ip).split('%')[0].toLowerCase().split('::')
  const head = parts[0] ? parts[0].split(':') : []
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : []
  const pad = new Array(Math.max(0, 8 - head.length - tail.length)).fill('0')
  return head.concat(pad, tail)
}
function inRange6(ip, cidr) {
  const c = String(cidr).split('/')
  const a = norm6(ip), b = norm6(c[0])
  let bits = Number(c[1] || 128)
  for (let i = 0; i < 8 && bits > 0; i++) {
    const take = Math.min(16, bits)
    const mask = take >= 16 ? 0xffff : ((0xffff << (16 - take)) & 0xffff)
    if ((parseInt(a[i] || '0', 16) & mask) !== (parseInt(b[i] || '0', 16) & mask)) return false
    bits -= take
  }
  return true
}
function isFakeIp(ip) {
  if (!ip) return false
  const f = fam(ip)
  if (f === 4) return FAKE4.some(function (c) {
    const p = String(c).split('/')
    const mask = p[1] ? ((~0 << (32 - Number(p[1]))) >>> 0) : 0xffffffff
    return (num4(ip) & mask) === (num4(p[0]) & mask)
  })
  if (f === 6) return FAKE6.some(function (c) { return inRange6(ip, c) })
  return false
}
// 公网域名解析到回环/内网地址 = 环境被本地代理或内核接管，这种"解析"不能当泄漏证据
function isLocalIp(ip) {
  if (!ip) return false
  const f = fam(ip)
  if (f === 4) {
    const n = num4(ip)
    const inR = function (c) {
      const p = String(c).split('/')
      const mask = ((~0 << (32 - Number(p[1]))) >>> 0)
      return (n & mask) === (num4(p[0]) & mask)
    }
    return inR('127.0.0.0/8') || inR('10.0.0.0/8') || inR('172.16.0.0/12') || inR('192.168.0.0/16') || inR('169.254.0.0/16')
  }
  if (f === 6) return inRange6(ip, '::1/128') || inRange6(ip, 'fe80::/10') || inRange6(ip, 'fc00::/7')
  return false
}
// 用不作为候选的域看系统解析是否落在 fake-ip 段（命中就说明代理内核正接管 DNS）
async function fakeEnv() {
  const dom = CFG.fake_ip_probe_domain || 'www.example.com'
  const a4 = await sysA(dom), a6 = await sysAAAA(dom)
  const hit = [a4, a6].filter(Boolean).find(function (ip) { return isFakeIp(ip) }) || null
  return { active: !!hit, ip: hit, domain: dom, a4, a6 }
}
// 上一轮自己写进 hosts 的固定：baseline 命中它们时，是"我的钉在起作用"，
// 不能当「现状已是最优」把钉丢掉——系统 DNS 本身未必给得出这个 IP
function readPrevPins() {
  const m = new Map()
  try {
    const t = fs.readFileSync(CFG.hosts_path, 'utf8')
    const i = t.indexOf(MARK_S), j = t.indexOf(MARK_E, i)
    if (i < 0 || j < 0) return m
    for (const line of t.slice(i, j).split(/\r?\n/)) {
      const s = line.trim()
      if (!s || s.charAt(0) === '#') continue
      const p = s.split(/\s+/)
      if (p.length >= 2 && fam(p[0]) && DOMRE.test(p[1])) {
        if (!m.has(p[1])) m.set(p[1], new Set())
        m.get(p[1]).add(p[0])
      }
    }
  } catch (e) {}
  return m
}
const PREV = readPrevPins()
function prevHas(dom, ip) { const s = PREV.get(dom); return !!(s && ip && s.has(ip)) }

async function fetchText(url, ms) {
  const r = await run('curl.exe', ['-sS', '-g', '--compressed', '--ssl-no-revoke', '--connect-timeout', '5', '--max-time', String(Math.ceil(ms / 1000)), url], ms + 5000)
  return r.stdout.length > 40 ? r.stdout : ''
}
async function loadRemoteCandidates() {
  const map = {}
  for (const url of CFG.sources) {
    const text = await fetchText(url, 15000)
    if (!text) { if (VERBOSE) log('源失败', url); continue }
    let n = 0
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\s+([a-z0-9._-]+)$/i)
      if (!m || !fam(m[1])) continue
      const dom = m[2].toLowerCase()
      if (!map[dom]) map[dom] = new Set()
      map[dom].add(m[1]); n++
    }
    log('源已解析', new URL(url).hostname, n + ' 条')
  }
  return map
}
async function dohResolve(dom, type) {
  const c = CFG.dns_over_proxy
  if (!c || !c.enabled) return []
  const r = await run('curl.exe', ['-sS', '-g', '--ssl-no-revoke', '-x', c.proxy, '--connect-timeout', '3', '--max-time', '8',
    '-H', 'accept: application/dns-json', c.doh.replace('DOMAIN', dom) + '&type=' + type], 12000)
  if (r.code !== 0) return []
  const ips = []
  try {
    for (const a of (JSON.parse(r.stdout).Answer || [])) if (fam(a.data)) ips.push(a.data)
  } catch (e) {}
  return ips
}
async function sysA(dom) { try { return (await dnsp.lookup(dom)).address } catch (e) { return null } }
async function sysAAAA(dom) { try { return (await dnsp.resolve6(dom))[0] || null } catch (e) { return null } }

// 单 IP 实测：TLS 建连 + 取回完整响应；只回头不返体（github.com 的典型症状）判为不可用
async function probeOnce(dom, ip, canary) {
  const url = 'https://' + dom + (canary || '/')
  // --noproxy：环境里若有 http_proxy/https_proxy（如交互式 shell 注入），curl 会改走本地代理，
  // --resolve 随之失效、测出来的不是直连——这一层测的就是直连，必须钉死不走代理
  const r = await run('curl.exe', ['-sS', '-o', 'NUL', '--noproxy', '*', '--ssl-no-revoke', '--connect-timeout', '4',
    '--max-time', String(Math.ceil(CFG.probe.budget_ms / 1000)), '-w', '%{http_code} %{time_total} %{size_download} %{remote_ip}',
    '--resolve', dom + ':443:' + ip, url], CFG.probe.budget_ms + 6000)
  const m = r.stdout.match(/^(\d+)\s+([\d.]+)\s+(\d+)\s+(\S+)/)
  if (!m) return { ok: false, ms: 1e9, code: 0, bytes: 0, rip: '' }
  const code = Number(m[1]), ms = Math.round(Number(m[2]) * 1000), bytes = Number(m[3])
  // 语义正确才算数：错误后端返回的 400 页比卡死更危险，会静默把域名指到别的服务上。
  // min_bytes 是给 github.com 这类"200 + 头几 KB 后就卡死"的假健康节点准备的：拿到几个字节不算通。
  const allow = (CFG.domains[dom] || {}).expect || CFG.probe.ok_codes || [200, 301, 302, 404]
  const minBytes = (CFG.domains[dom] || {}).min_bytes || CFG.probe.min_bytes || 1
  // max_ms：慢到离谱的候选（实测 github.com 有 8026ms 仍返回 200 的）不值得写进去——
  // 写进去复核也会被撤，白折腾一轮 hosts 和 DNS 缓存
  const maxMs = (CFG.domains[dom] || {}).max_ms || 0
  return { ok: allow.indexOf(code) >= 0 && bytes >= minBytes && (!maxMs || ms <= maxMs), ms, code, bytes, rip: m[4] }
}
async function probe(dom, ip, canary) {
  // 默认严格：每一轮都必须通过才认定可用，取最慢一轮计时——单轮侥幸通过会把抖动 IP 固定进去
  const strict = (CFG.domains[dom] || {}).strict !== false
  const rs = []
  for (let i = 0; i < CFG.probe.retries; i++) {
    const r = await probeOnce(dom, ip, canary)
    rs.push(r)
    if (!strict && r.ok) break
  }
  const good = rs.filter(function (r) { return r.ok })
  if (!good.length) return { ok: false, ms: 1e9, code: rs[rs.length - 1].code, bytes: 0, tries: rs.length }
  const times = good.map(function (r) { return r.ms })
  const ms = strict ? Math.max.apply(null, times) : Math.min.apply(null, times)
  return { ok: strict ? good.length === rs.length : true, ms, code: good[0].code, bytes: good[0].bytes, tries: rs.length }
}
function stripBlock(text) {
  const i = text.indexOf(MARK_S)
  if (i < 0) return text
  const j = text.indexOf(MARK_E, i)
  return j < 0 ? text : text.slice(0, i) + text.slice(j + MARK_E.length)
}
function writeHosts(block) {
  const cur = fs.readFileSync(CFG.hosts_path, 'utf8')
  const rest = stripBlock(cur).replace(/[\r\n]+$/, '')
  const out = rest + '\r\n' + block + '\r\n'
  // dry-run 只算出目标内容，不落盘、也不建 backups/
  if (DRY) return out
  const bdir = path.join(HERE, 'backups')
  fs.mkdirSync(bdir, { recursive: true })
  fs.writeFileSync(path.join(bdir, 'hosts-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)), cur)
  const all = fs.readdirSync(bdir).filter(function (f) { return f.indexOf('hosts-') === 0 }).sort()
  while (all.length > 5) fs.unlinkSync(path.join(bdir, all.shift()))
  fs.writeFileSync(CFG.hosts_path, out)
  return out
}

// 哪些候选真的写进 hosts。抽成纯函数是为了能离线回归——这里踩过
// "v4 1012ms 被 v6 1948ms 顶掉"的坑（见 --selftest 用例）。
function betterThan(cand, base, ratio) {
  if (!cand) return false
  if (!base || !base.ok) return true
  if (cand.ip === base.ip) return false
  return cand.ms < base.ms * ratio
}
function pickPins(pin4, pin6, base4, base6, sysHasV6, ratio) {
  const take4 = betterThan(pin4, base4, ratio) ? pin4 : null
  // 无系统 AAAA 时，v6 要和"将要写进去的 v4"比（没有 v4 候选时才是当前 v4）：
  // 双栈下系统优先试 IPv6，若写入的 v6 比写入的 v4 还慢，等于把 v4 的收益抵消掉
  // （线上真实踩过两次：v4 1012 被 v6 1948 顶掉；v4 候选 1052 与 v6 2405 同时写入）。
  // 有 AAAA 基线时仍按族内比（系统本来就优先 v6，改进 v6 才有意义）。
  // ref4 必须带 ok:true——pin 对象没有 ok 字段，直接当基准会被 betterThan 判成"基准不可用"
  const ref4 = take4 ? { ip: take4.ip, ok: true, ms: take4.ms } : base4
  const v6Worth = sysHasV6 ? betterThan(pin6, base6, ratio) : betterThan(pin6, ref4, ratio)
  const take6 = v6Worth ? pin6 : null
  return { take4, take6 }
}

async function evalDomain(dom, conf, remote) {
  const canary = conf.canary || '/'
  const cand = new Set()
  const srcOf = {}
  // 候选从哪来：有健康池就走池子（每轮只探 probe_per_round 个，exploit + explore），
  // 没有就退回旧来源。旧的 static_ips / 第三方列表正是审计要摆脱的"过期候选集"。
  if (POOL && POOL.on) {
    for (const p of POOL.probes(dom, (CFG.pool && CFG.pool.probe_per_round) || 8)) { cand.add(p.ip); srcOf[p.ip] = p.src }
  } else {
    if (remote[dom]) for (const ip of remote[dom]) if (fam(ip) && (!conf.family || fam(ip) === conf.family)) cand.add(ip)
    for (const ip of ((CFG.static_ips || {})[dom] || []).concat((CFG.static_ips6 || {})[dom] || [])) if (fam(ip) && (!conf.family || fam(ip) === conf.family)) cand.add(ip)
  }
  // 实时解析仍然每轮取一次：线路变化时它是最快的信号，也是池子里 explore 的主要来源
  for (const ip of await dohResolve(dom, 'A')) cand.add(ip)
  const v6 = await dohResolve(dom, 'AAAA')
  if (v6.length) for (const ip of v6) cand.add(ip)
  const a4 = await sysA(dom), a6 = await sysAAAA(dom)
  const sysHasV6 = !!a6
  const jobs = []
  if (a4) jobs.push({ ip: a4, kind: 'base4' })
  if (a6) jobs.push({ ip: a6, kind: 'base6' })
  for (const ip of cand) if (ip !== a4 && ip !== a6) jobs.push({ ip, kind: 'cand' })
  const res = await pool(jobs, CFG.probe.concurrency, async function (j) {
    const r = await probe(dom, j.ip, canary)
    return { ip: j.ip, kind: j.kind, fam: fam(j.ip), ok: r.ok, ms: r.ms, code: r.code, bytes: r.bytes }
  })
  // 观测写回池子（含 baseline：系统解析答案本身好不好用也是有用信息）
  if (POOL && POOL.on) {
    const minSpeedBytes = (CFG.pool && CFG.pool.speed_min_bytes) || 65536
    for (const x of res) {
      // 速度直接从已有探测的 bytes/ms 推导，不额外下载；只有响应体够大才计入，
      // 否则小响应测出来的"速度"其实是延迟倒数
      const speed = (x.ok && x.bytes >= minSpeedBytes && x.ms > 0) ? Math.round(x.bytes / (x.ms / 1000)) : 0
      POOL.record(dom, x.ip, { ok: x.ok, ms: x.ms, code: x.code, speed: speed, src: srcOf[x.ip] || (x.kind === 'base4' || x.kind === 'base6' ? 'system-dns' : '') })
    }
  }
  const byFam = function (f) { return res.filter(function (x) { return x.fam === f }).slice().sort(function (a, b) { return a.ms - b.ms }) }
  const g4 = byFam(4).filter(function (x) { return x.ok })
  const g6 = byFam(6).filter(function (x) { return x.ok })
  const base4 = res.find(function (x) { return x.kind === 'base4' })
  const base6 = res.find(function (x) { return x.kind === 'base6' })
  const pin4 = g4[0] || null, pin6 = g6[0] || null
  // v4 与 v6 各自择优：两族的可用性会随时间互换（同一时刻 Pages 的 v4 全灭而 v6 4.5s 可用），
  // 写完后由 verify 按真实解析复核，不成立就当场撤销，不做 ::1 沉洞那类取巧。
  const ratio = CFG.probe.win_ratio
  const pins = pickPins(pin4, pin6, base4, base6, sysHasV6, ratio)
  const take4 = pins.take4, take6 = pins.take6
  // 现状就是自己上一轮钉的 IP 且还可用 → 继续钉着；判「现状已是最优」等于这一轮把钉撤了
  const keep4 = base4 && base4.ok && prevHas(dom, base4.ip) ? base4.ip : null
  const keep6 = base6 && base6.ok && prevHas(dom, base6.ip) ? base6.ip : null
  let use = null, reason = ''
  if (!pin4 && !pin6 && !keep4 && !keep6) reason = '无可用候选，保持系统 DNS'
  else if (take4 || take6 || keep4 || keep6) {
    const ip4 = take4 ? take4.ip : (keep4 || null)
    const ip6 = take6 ? take6.ip : (keep6 || null)
    const ms = (take4 && take4.ms) || (take6 && take6.ms) || (base4 && base4.ms) || 0
    use = { ip4, ip6, ms }
    reason = (take4 || take6)
      ? 'v4 ' + (base4 ? base4.ms : '不可用') + '→' + (take4 ? take4.ms : (keep4 ? '保持' : '不写')) +
        '，v6 ' + (base6 ? base6.ms : (sysHasV6 ? '不可用' : '无记录')) + '→' + (take6 ? take6.ms : (keep6 ? '保持' : '不写')) + 'ms'
      : '上一轮固定仍可用（' + ms + 'ms），保持'
  } else reason = '现状已是最优' + (sysHasV6 ? '（系统 AAAA 可直接用）' : '')
  return { dom, pin4: use ? use.ip4 : null, pin6: use ? use.ip6 : null, pin4ms: use ? use.ms : 0,
    alt4: pin4 ? pin4.ip : null, alt6: pin6 ? pin6.ip : null,
    base4: base4 || null, base6: base6 || null, sysHasV6, reason, tried: res.length, all: res }
}

async function verify(dom, canary, expect) {
  const url = 'https://' + dom + canary
  // 不跟随重定向：跨主机跳转后 %{remote_ip} 是最终跳的 IP，会把自己钉的域判成「泄漏」
  // （avatars.githubusercontent.com/u/1 就是这种：一跳就到别的域）
  const r = await run('curl.exe', ['-sS', '-o', 'NUL', '--noproxy', '*', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '15',
    '-w', '%{remote_ip} %{http_code} %{time_total}', url], 20000)
  const m = r.stdout.match(/^(\S+)\s+(\d+)\s+([\d.]+)/)
  const rip = m ? m[1] : ''
  // fake-ip / 回环 / 内网地址说明解析被代理内核或本地代理接管了：这次复核说明不了固定对不对，不能据此撤销
  if (isFakeIp(rip) || isLocalIp(rip)) return { ok: true, inactive: true, remote: rip, detail: '连到 ' + rip + '（fake-ip/本地代理接管），本轮不复核，保留现有固定' }
  if (!rip) return { ok: false, remote: '', detail: '连接失败 ' + (m ? m[2] : '000') }
  if (expect.indexOf(rip) < 0) return { ok: false, remote: rip, detail: '泄漏到未钉的 ' + rip + '（写入的是 ' + expect.join('/') + '）' }
  return { ok: true, remote: rip, code: Number(m[2]), ms: Math.round(Number(m[3]) * 1000), detail: rip + ' ' + m[2] + ' ' + Math.round(Number(m[3]) * 1000) + 'ms' }
}

// 复核泄漏后该怎么办：泄漏那一族根本没写过 → 补钉它；已经写过还不贴 → 整域撤销
function planAfterLeak(c, remote) {
  const v6 = String(remote).indexOf(':') >= 0
  const key = v6 ? 'ip6' : 'ip'
  const alt = v6 ? c.alt6 : c.alt4
  if (!c[key] && alt) return { action: 'plug', key, ip: alt }
  return { action: 'revoke' }
}

async function main() {
  fs.mkdirSync(LOGDIR, { recursive: true })
  // dry-run 是纯只读：不建锁文件、不备份、不写 hosts、不刷 DNS、不做落地复核
  if (!DRY) acquireLock()
  if (REVERT) {
    if (DRY) { log('--dry 下不执行回滚（回滚是写操作），去掉 --dry 再跑'); return }
    if (fs.readFileSync(CFG.hosts_path, 'utf8').indexOf(MARK_S) < 0) { log('hosts 里没有本工具写入的块'); return }
    writeHosts('')
    await run('ipconfig.exe', ['/flushdns'], 10000)
    log('已回滚：accel 块移除，DNS 缓存刷新')
    return
  }
  log('==== 一轮选路开始 ' + (DRY ? '(dry-run)' : '') + ' ====')
  // 交互式 shell 常带 http_proxy/https_proxy：本轮 curl 已用 --noproxy 强制直连，这里只做提示
  const proxied = ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'].filter(function (k) { return process.env[k] })
  if (proxied.length) log('提示：环境里有 ' + proxied.join('/') + '，本轮实测已 --noproxy 强制直连（换空环境跑更接近计划任务的结论）')
  // 代理内核接管 DNS（fake-ip）时本轮整体跳过：写了也复核不了，还会把上一轮写好的固定全撤销
  const env = await fakeEnv()
  if (env.active) {
    log('环境：系统解析 ' + env.domain + ' -> ' + env.ip + ' = fake-ip（代理内核接管 DNS）')
    log('==== 本轮跳过：hosts 层被架空，保留现有固定，不写也不撤（report.json 留上一轮） ====')
    return
  }
  // 候选过期就顺手刷新一次（discover 自己也会判有效期；这里保证它不会永远不跑）。
  // dry-run 跳过：discover 会写 candidates.json，只读轮次不能有副作用。
  if (!DRY && CFG.discovery && CFG.discovery.enabled) {
    const cj = path.join(HERE, 'candidates.json')
    let at = 0
    try { at = JSON.parse(fs.readFileSync(cj, 'utf8')).at } catch (e) {}
    if (Date.now() - at > (CFG.discovery.refresh_h || 6) * 3600e3) {
      log('候选发现：开始刷新（candidates.json 已过期）')
      const r = await run(process.execPath, [path.join(HERE, 'discover.mjs')], 300000)
      log('候选发现：' + (r.code === 0 ? '已刷新' : '未完成 code=' + r.code))
    }
  }
  POOL = openPool(CFG)
  // 池子启用时不再每轮抓第三方列表：候选已经在 candidates.json 里，且它只当 hint
  const remote = POOL.on ? {} : await loadRemoteCandidates()
  log(POOL.on
    ? '候选池已启用：每域每轮探 ' + ((CFG.pool && CFG.pool.probe_per_round) || 8) + ' 个（exploit + explore）'
    : '候选池未启用（缺 candidates.json 或 pool.enabled=false），本轮沿用旧候选来源')
  const report = { at: new Date().toISOString(), env, pool: { enabled: POOL.on }, domains: {} }
  const chosen = []
  for (const dom of Object.keys(CFG.domains)) {
    if (CFG.deny.indexOf(dom) >= 0 || !DOMRE.test(dom)) continue
    const conf = CFG.domains[dom] || {}
    const r = await evalDomain(dom, conf, remote)
    if (r.pin4 || r.pin6) chosen.push({ dom, ip: r.pin4, ip6: r.pin6, alt4: r.alt4, alt6: r.alt6, canary: conf.canary || '/' })
    report.domains[dom] = { baseline: r.base4, baseline6: r.base6, sys_has_aaaa: r.sysHasV6, pinned: r.pin4, pinned6: r.pin6, reason: r.reason, tried: r.tried, probed: r.all }
    log((r.pin4 || r.pin6 ? '固定 ' : '跳过 '), dom.padEnd(28), (r.pin4 || r.pin6 || (r.base4 && r.base4.ok ? r.base4.ip : '-')).padEnd(22),
      String(r.base4 ? r.base4.ms + 'ms' : '无').padEnd(9), String(r.pin4 || r.pin6 ? r.pin4ms + 'ms' : '-').padEnd(9), r.reason)
    if (VERBOSE) for (const p of r.all) log('    ', p.kind.padEnd(6), p.ip.padEnd(22), p.ok ? 'ok ' : 'bad', (String(p.ms) + 'ms').padStart(9), 'code=' + p.code, 'B=' + p.bytes)
  }
  const render = function (list) {
    const lines = []
    for (const c of list.slice(0, CFG.probe.max_entries)) {
      if (c.ip) lines.push(c.ip + '  ' + c.dom)
      if (c.ip6) lines.push(c.ip6 + '  ' + c.dom)
    }
    return [MARK_S, '# 生成时间 ' + new Date().toISOString(), '# 候选来源 GitHub520 + GitHub-IP-hosts + DoH(A/AAAA) + 内置，全部经本机 TLS 实测', lines.join('\r\n'), MARK_E].join('\r\n')
  }
  const doWrite = async function (list) {
    if (DRY) return
    writeHosts(render(list))
    await run('ipconfig.exe', ['/flushdns'], 8000)
  }
  const recheck = async function (list) {
    const bad = []
    for (const c of list) {
      const v = await verify(c.dom, c.canary, [c.ip, c.ip6].filter(Boolean))
      log((v.ok ? (v.inactive ? '未复核' : '生效  ') : '! 泄漏 ') + c.dom.padEnd(28) + v.detail)
      if (!v.ok) bad.push({ c, v })
    }
    return bad
  }
  // 写入后按真实解析复核：探针可能单轮侥幸通过，落地不成立就不该留在 hosts 里
  let bad = []
  if (DRY) {
    log('dry-run：跳过写入与落地复核（复核以真实写入为前提）')
  } else {
    await doWrite(chosen)
    bad = await recheck(chosen)
    // 泄漏的常见原因是只钉了一族，另一族仍由 DNS/隧道给出并被优先选中。
    // 先按族补钉（用实测可用的另一族候选），补不上的才撤销整域。
    const plugged = []
    for (const b of bad) {
      const pl = planAfterLeak(b.c, b.v.remote)
      if (pl.action === 'plug') { b.c[pl.key] = pl.ip; plugged.push(b.c.dom + (pl.key === 'ip6' ? ':v6' : ':v4')) }
      else log('  ' + b.c.dom + ' 泄漏族已写过或无候选 -> 撤销')
    }
    if (plugged.length) {
      log('补钉未覆盖族：' + plugged.join(' ') + ' -> 第二轮复核')
      await doWrite(chosen)
      bad = await recheck(chosen)
    }
  }
  const failed = bad.map(function (x) { return x.c.dom })
  if (failed.length && !DRY) {
    await doWrite(chosen.filter(function (c) { return failed.indexOf(c.dom) < 0 }))
    log('已撤销 ' + failed.length + ' 条：' + failed.join(', '))
  }
  for (const d of failed) if (report.domains[d]) { report.domains[d].revoked = true }
  // T：入口体检并入同一节奏，report.json 因此同时是"这一轮所有通道的快照"
  if (DRY) log('dry-run：跳过入口体检（doctor 会写 proxy-state.json）')
  else try {
    const d = await run(process.execPath, [path.join(HERE, 'gh.mjs'), 'doctor', '--force'], 240000)
    const ps = JSON.parse(fs.readFileSync(path.join(HERE, 'proxy-state.json'), 'utf8'))
    report.proxies = {
      at: ps.at,
      entries: ps.entries.map(function (e) {
        // 私有 relay 的密钥在 URL 路径里，report.json 里只留脱敏形式
        const p = e.prefix === '__RELAY__' ? String((CFG.relay || {}).base || '__RELAY__').replace('KEY', '<REDACTED>') : e.prefix
        return { prefix: p, ok: e.ok, soft: e.soft, ms: e.ms, score: e.score, mbps: Math.round((e.bps || 0) / 10485.76) / 100 }
      })
    }
    log('入口体检：' + report.proxies.entries.filter(function (x) { return x.ok }).length + ' 可用 / ' + report.proxies.entries.length + ' 已测')
    if (VERBOSE) for (const line of String(d.stdout).split(/\r?\n/).slice(1)) log('    ', line)
  } catch (e) { log('入口体检未完成：' + ((e && e.message) || e)) }
  // 观测落盘。dry-run 是只读：内存里记录过但不写盘
  if (POOL && POOL.on && !DRY) {
    POOL.save()
    const tot = { active: 0, reserve: 0, explorer: 0, quarantine: 0 }
    for (const d of Object.keys(CFG.domains)) {
      const b = POOL.buckets(d)
      tot.active += b.active.length; tot.reserve += b.reserve.length
      tot.explorer += b.explorer.length; tot.quarantine += b.quarantine.length
    }
    report.pool = Object.assign({ enabled: true }, tot)
    log('候选池：active ' + tot.active + ' / reserve ' + tot.reserve + ' / explorer ' + tot.explorer + ' / quarantine ' + tot.quarantine)
  }
  fs.writeFileSync(path.join(HERE, 'report.json'), JSON.stringify(report, null, 1))
  log('==== 完成' + (DRY ? '（dry-run，未动文件）' : '') + '：评估 ' + Object.keys(report.domains).length + ' 域，' +
    (DRY ? '拟固定 ' + chosen.length : '保留 ' + (chosen.length - failed.length)) + ' 条固定，撤销 ' + failed.length + ' 条，报告 report.json ====')
}
// 不依赖网络的判定自测：泄漏族没写过 -> 补钉；已写过或没候选 -> 撤销
if (SELFTEST) {
  const cases = [
    [{ ip: '1.1.1.1', ip6: null, alt4: '2.2.2.2', alt6: '2606::1' }, '2001:2::24', { action: 'plug', key: 'ip6', ip: '2606::1' }],
    [{ ip: null, ip6: '2606::9', alt4: '2.2.2.2', alt6: '2606::9' }, '2001:2::24', { action: 'revoke' }],
    [{ ip: null, ip6: '2606::9', alt4: '2.2.2.2', alt6: null }, '8.8.8.8', { action: 'plug', key: 'ip', ip: '2.2.2.2' }],
    [{ ip: '1.1.1.1', ip6: null, alt4: null, alt6: null }, '2001:2::24', { action: 'revoke' }],
    [{ ip: null, ip6: null, alt4: '2.2.2.2', alt6: null }, '', { action: 'plug', key: 'ip', ip: '2.2.2.2' }]
  ]
  let bad = 0
  for (const [c, remote, want] of cases) {
    const got = planAfterLeak(c, remote)
    const ok = got.action === want.action && (want.action !== 'plug' || (got.key === want.key && got.ip === want.ip))
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  泄漏=' + (remote || '(无响应)') + ' -> ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
  }
  // fake-ip 判定：命中代理内核的假地址段时复核必须让路，否则写好的固定会被误撤销
  const fakeCases = [
    ['198.18.0.30', true], ['198.18.255.255', true], ['198.19.0.1', false], ['20.205.243.166', false],
    ['fdfe:dcba:9876::1', true], ['fdfe:dcba:9877::1', false], ['2606:4700::6811:6fb8', false], ['', false]
  ]
  for (const [ip, want] of fakeCases) {
    const ok = isFakeIp(ip) === want
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  isFakeIp(' + (ip || '(空)') + ') = ' + isFakeIp(ip) + (ok ? '' : '，期望 ' + want))
  }
  // 公网域名解到回环/内网同样不能当泄漏证据（交互式 shell 的 http_proxy 会让 curl 连到 127.0.0.1）
  const localCases = [
    ['127.0.0.1', true], ['192.168.0.1', true], ['10.1.2.3', true], ['172.16.0.1', true], ['172.32.0.1', false],
    ['20.205.243.166', false], ['fe80::1', true], ['fc00::1', true], ['2606:4700::6811:6fb8', false]
  ]
  for (const [ip, want] of localCases) {
    const ok = isLocalIp(ip) === want
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  isLocalIp(' + ip + ') = ' + isLocalIp(ip) + (ok ? '' : '，期望 ' + want))
  }
  // 跨族选择：无 AAAA 时不能因为"v4 慢"就把比 v4 还慢的 v6 写进去
  // （线上真实踩过：cdn.jsdelivr.net 的 v4 1012ms 被 v6 1948ms 顶掉）
  const R = CFG.probe.win_ratio
  const pinCases = [
    ['无 AAAA，v6 比 v4 现状慢 -> 不写 v6', { ip: '1.1.1.1', ms: 1000 }, { ip: '2606::1', ms: 1948 }, { ip: '9.9.9.9', ok: true, ms: 1012 }, null, false, false, false],
    ['无 AAAA，v4 候选可用、v6 只快 10% -> 不写 v6', { ip: '1.1.1.1', ms: 1000 }, { ip: '2606::1', ms: 900 }, { ip: '9.9.9.9', ok: false, ms: 1e9 }, null, false, true, false],
    ['无 AAAA，v4 完全不可用 -> 写 v6', null, { ip: '2606::1', ms: 900 }, { ip: '9.9.9.9', ok: false, ms: 1e9 }, null, false, false, true],
    ['无 AAAA，v6 明显快于 v4 -> 写 v6', { ip: '1.1.1.1', ms: 1000 }, { ip: '2606::1', ms: 700 }, { ip: '9.9.9.9', ok: true, ms: 1000 }, null, false, false, true],
    ['无 AAAA，v6 比将写入的 v4 候选还慢 -> 不写 v6', { ip: '1.1.1.1', ms: 1052 }, { ip: '2606::1', ms: 2405 }, { ip: '9.9.9.9', ok: true, ms: 2972 }, null, false, true, false],
    ['无 AAAA，v6 快于将写入的 v4 候选 -> 写 v6', { ip: '1.1.1.1', ms: 1052 }, { ip: '2606::1', ms: 700 }, { ip: '9.9.9.9', ok: true, ms: 2972 }, null, false, true, true],
    ['有 AAAA，v6 只快 5% -> 不写', null, { ip: '2606::1', ms: 950 }, null, { ip: '2606::9', ok: true, ms: 1000 }, true, false, false],
    ['有 AAAA，v6 快 30% -> 写', null, { ip: '2606::1', ms: 700 }, null, { ip: '2606::9', ok: true, ms: 1000 }, true, false, true],
    ['v4 候选只快 10% -> 不写', { ip: '1.1.1.1', ms: 900 }, null, { ip: '9.9.9.9', ok: true, ms: 1000 }, null, false, false, false]
  ]
  for (const [name, p4, p6, b4, b6, has6, want4, want6] of pinCases) {
    const got = pickPins(p4, p6, b4, b6, has6, R)
    const ok = !!got.take4 === want4 && !!got.take6 === want6
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' -> take4=' + !!got.take4 + ' take6=' + !!got.take6 +
      (ok ? '' : '，期望 take4=' + want4 + ' take6=' + want6))
  }
  const total = cases.length + fakeCases.length + localCases.length + pinCases.length
  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测 ' + total + '/' + total + ' 通过')
  process.exit(bad ? 1 : 0)
}

main().then(releaseLock, function (e) { log('致命', (e && e.stack) || String(e)); releaseLock(); process.exit(1) })
