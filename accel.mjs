// accel.mjs —— 本机自适应 hosts（v2，2026-10-13 全面重写）
// 候选 IP（含 IPv6）全部来自实测，只有真的比现状快才写入；写后用"整链 + 分族"两层复核兜底。
//
// v2 相对旧版的关键变化（依据 2026-10-13 审计 + 当日事故教训）：
//   1. 判定/解析/文件 IO 收口到模块：ip.mjs（net.isIP 严格校验）、probe.mjs（判定纯函数）、hostsio.mjs（安全提交）。
//   2. 落地复核 = 系统解析整链检查 + 每族 --resolve 直检；任一失败先重试 1 次再判决；
//      分族失败只撤该族（旧版只能整域撤）。
//   3. hosts 写入 = 写前备份 + 直写 + 写后逐字节读回（失败重写一次 → 仍失败从备份恢复并中止本轮）。
//      （rename / File.Replace 在本机实测均不可用，File.Replace 还会在失败时移走目标——永久禁用，见 hostsio.mjs 头注）
//   4. hosts 缺失（重建需提权）→ 本轮拒绝进入，指向 repair-hosts.ps1。
import fs from 'node:fs'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { promises as dnsp } from 'node:dns'
import { open as openPool } from './pool.mjs'
import { fam, isFakeIp, isLocalIp } from './ip.mjs'
import { parseProbeOut, parseVerifyOut, judgeProbe, summarizeProbes, judgeVerify } from './probe.mjs'
import { readHosts, parsePins, commitHosts } from './hostsio.mjs'
import { readState as readClashState, describe as describeClash } from './clash.mjs'

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
const DOMRE = /^[a-z0-9._-]+$/i
// Critical GitHub web/resource endpoints must use current DNS. This code-level invariant prevents
// a briefly healthy IP pin turning into a machine-wide outage between scheduled maintenance runs.
const NEVER_PIN_DOMAINS = new Set([
  'github.com', 'gist.github.com', 'api.github.com', 'codeload.github.com',
  'raw.githubusercontent.com', 'objects.githubusercontent.com',
  'avatars.githubusercontent.com', 'github.githubassets.com'
])

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

function run(exe, args, timeoutMs) {
  return new Promise(function (resolve) {
    // maxBuffer 1MB（2026-10-13 收紧）：所有调用都 -o NUL 只留 -w 尾巴，实际输出永远 <1KB；
  // 实测 32MB→1MB 峰值仅差 0.3MB（Node 不预分配），所以这不是省内存，而是消除
  // "某条 curl 输出失控就吃掉 32MB" 的失控面。
  execFile(exe, args, { maxBuffer: 1024 * 1024, windowsHide: true, timeout: timeoutMs || 25000, encoding: 'utf8' },
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

// 代理内核（mihomo/Clash）fake-ip 段检测绑定（段定义与判定在 ip.mjs）
const FAKE4 = CFG.fake_ip_ranges4 || ['198.18.0.0/16']
const FAKE6 = CFG.fake_ip_ranges6 || ['fdfe:dcba:9876::/64']
function isFake(ip) { return isFakeIp(ip, FAKE4, FAKE6) }
// 用不作为候选的域看系统解析是否落在 fake-ip 段（命中就说明代理内核正接管 DNS）
async function fakeEnv() {
  const dom = CFG.fake_ip_probe_domain || 'www.example.com'
  const a4 = await sysA(dom), a6 = await sysAAAA(dom)
  const hit = [a4, a6].filter(Boolean).find(function (ip) { return isFake(ip) }) || null
  return { active: !!hit, ip: hit, domain: dom, a4, a6 }
}
// 上一轮自己写进 hosts 的固定：baseline 命中它们时，是"我的钉在起作用"，
// 不能当「现状已是最优」把钉丢掉——系统 DNS 本身未必给得出这个 IP
function readPrevPins() {
  const cur = readHosts(CFG.hosts_path)
  if (cur === null) return new Map()
  return parsePins(cur, MARK_S, MARK_E, function (ip) { return fam(ip) > 0 }, function (d) { return DOMRE.test(d) })
}
const PREV = readPrevPins()
function prevHas(dom, ip) { const s = PREV.get(dom); return !!(s && ip && s.has(ip)) }

// 第三方 hosts 列表（只当 hint）：支持 "url 字符串" 或 { url, via } 两种写法
function fetchArgs(url, via) {
  const a = ['-sS', '-g', '--compressed', '--ssl-no-revoke', '--connect-timeout', '5', '--max-time', '15']
  if (via === 'proxy' && CFG.discovery && CFG.discovery.proxy) a.push('-x', CFG.discovery.proxy)
  else a.push('--noproxy', '*')
  a.push(url)
  return a
}
async function fetchText(url, ms, via) {
  const r = await run('curl.exe', fetchArgs(url, via), (ms || 15000) + 5000)
  return r.stdout.length > 40 ? r.stdout : ''
}
async function loadRemoteCandidates() {
  const map = {}
  for (const item of CFG.sources) {
    const url = typeof item === 'string' ? item : item.url
    const via = typeof item === 'string' ? 'direct' : (item.via || 'direct')
    const text = await fetchText(url, 15000, via)
    if (!text) { if (VERBOSE) log('源失败', url); continue }
    let n = 0
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+([a-z0-9._-]+)$/i)
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

// 一个域「什么响应码算通」：域级 expect 优先，其次是全局 ok_codes。
// probeOnce 与落地复核 verify 共用同一套，避免两处口径漂移（objects.githubusercontent.com 根路径正常就回 404）
function allowedCodes(dom) { return (CFG.domains[dom] || {}).expect || CFG.probe.ok_codes || [200, 301, 302, 404] }

// 单 IP 实测：TLS 建连 + 取回完整响应；只回头不返体（github.com 的典型症状）判为不可用
async function probeOnce(dom, ip, canary) {
  const url = 'https://' + dom + (canary || '/')
  // --noproxy：环境里若有 http_proxy/https_proxy（如交互式 shell 注入），curl 会改走本地代理，
  // --resolve 随之失效、测出来的不是直连——这一层测的就是直连，必须钉死不走代理
  const r = await run('curl.exe', ['-sS', '-o', 'NUL', '--noproxy', '*', '--ssl-no-revoke', '--connect-timeout', '4',
    '--max-time', String(Math.ceil(CFG.probe.budget_ms / 1000)), '-w', '%{http_code} %{time_total} %{size_download} %{remote_ip}',
    '--resolve', dom + ':443:' + ip, url], CFG.probe.budget_ms + 6000)
  const conf = CFG.domains[dom] || {}
  return judgeProbe(parseProbeOut(r.stdout), {
    allow: allowedCodes(dom),
    minBytes: conf.min_bytes || CFG.probe.min_bytes || 1,
    maxMs: conf.max_ms || 0
  })
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
  return summarizeProbes(rs, strict)
}

// ---------- 落地复核（v2：整链 + 分族，各失败重试 1 次） ----------
async function verifySystemOnce(dom, canary) {
  const url = 'https://' + dom + (canary || '/')
  const r = await run('curl.exe', ['-sS', '-o', 'NUL', '--noproxy', '*', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '15',
    '-w', '%{http_code} %{time_total} %{remote_ip}', url], 20000)
  return parseVerifyOut(r.stdout)
}
async function verifyFamilyOnce(dom, canary, ip) {
  const url = 'https://' + dom + (canary || '/')
  // 不跟随重定向：跨主机跳转后 %{remote_ip} 是最终跳的 IP，会把自己钉的域判成「泄漏」
  const r = await run('curl.exe', ['-sS', '-o', 'NUL', '--noproxy', '*', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '15',
    '-w', '%{http_code} %{time_total} %{remote_ip}', '--resolve', dom + ':443:' + ip, url], 20000)
  return parseVerifyOut(r.stdout)
}
async function verifyDomain(dom, canary, pins) {
  const ctx = { expect: pins.map(function (p) { return p.ip }), allow: allowedCodes(dom), isFake: isFake, isLocal: isLocalIp }
  const sys = await withRetries(async function () { return judgeVerify(await verifySystemOnce(dom, canary), ctx) })
  const famChecks = []
  // 分族直检只在整链 ok 时做（泄漏/无响应交给 planAfterLeak 处理；fake/本地让路时不做）
  if (sys.kind === 'ok') {
    for (const p of pins) {
      const fctx = { expect: [p.ip], allow: ctx.allow, isFake: isFake, isLocal: isLocalIp }
      const d = await withRetries(async function () { return judgeVerify(await verifyFamilyOnce(dom, canary, p.ip), fctx) })
      famChecks.push({ fam: p.fam, ip: p.ip, kind: d.kind, detail: d.detail, retried: !!d.retried })
    }
  }
  return { sys: sys, fam: famChecks }
}
// 失败重试（默认 1 次，probe.verify_retries 可调）：瞬时抖动不该触发撤销/换钉（2026-10-13）
const VERIFY_RETRIES = (CFG.probe && CFG.probe.verify_retries !== undefined) ? CFG.probe.verify_retries : 1
async function withRetries(fn) {
  let v = await fn()
  let used = 0
  while (used < VERIFY_RETRIES && v.kind !== 'ok' && v.kind !== 'inactive') {
    v = await fn()
    used++
    v.retried = true
  }
  return v
}

// 复核失败（泄漏到别处，或连上钉了但响应码不成立）后该怎么办：
// 失败那一族根本没写过 → 补钉它；已经写过还不成立 → 整域撤销
function planAfterLeak(c, remote) {
  const v6 = String(remote).indexOf(':') >= 0
  const key = v6 ? 'ip6' : 'ip'
  const alt = v6 ? c.alt6 : c.alt4
  if (!c[key] && alt) return { action: 'plug', key: key, ip: alt }
  return { action: 'revoke' }
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
  for (const ip of cand) if (ip !== a4 && ip !== a6) jobs.push({ ip: ip, kind: 'cand' })
  const res = await pool(jobs, CFG.probe.concurrency, async function (j) {
    const r = await probe(dom, j.ip, canary)
    return { ip: j.ip, kind: j.kind, fam: fam(j.ip), ok: r.ok, ms: r.ms, code: r.code, bytes: r.bytes }
  })
  // 观测写回池子（含 baseline：系统解析答案本身好不好用也是有用信息）。
  // 2026-10-14 修：**整域 0 命中时不写回**——那是线路级故障（基线与全部候选一起失败），
  // 不是"这些 IP 变坏了"。旧行为把失败记到每个候选头上 → 好 IP 攒够 3 次连续失败进 30 分钟冷却 →
  // 恰在线路恢复时被排除，表现为"hosts 失效"（实测：github.com 的 20.27.177.113 有 52/76 成功率、
  // 469ms，却因 fail_streak=3 被冷却，整轮不参与探测）。
  const anyOk = res.some(function (x) { return x.ok })
  if (POOL && POOL.on && anyOk) {
    const minSpeedBytes = (CFG.pool && CFG.pool.speed_min_bytes) || 65536
    for (const x of res) {
      // 速度直接从已有探测的 bytes/ms 推导，不额外下载；只有响应体够大才计入，
      // 否则小响应测出来的"速度"其实是延迟倒数
      const speed = (x.ok && x.bytes >= minSpeedBytes && x.ms > 0) ? Math.round(x.bytes / (x.ms / 1000)) : 0
      POOL.record(dom, x.ip, { ok: x.ok, ms: x.ms, code: x.code, speed: speed, src: srcOf[x.ip] || (x.kind === 'base4' || x.kind === 'base6' ? 'system-dns' : '') })
    }
  } else if (POOL && POOL.on) {
    log('  ' + dom + '：本轮 0 命中（线路级故障），观测不写回池子（避免误伤候选失败计数）')
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
    use = { ip4: ip4, ip6: ip6, ms: ms }
    reason = (take4 || take6)
      ? 'v4 ' + (base4 ? base4.ms : '不可用') + '→' + (take4 ? take4.ms : (keep4 ? '保持' : '不写')) +
        '，v6 ' + (base6 ? base6.ms : (sysHasV6 ? '不可用' : '无记录')) + '→' + (take6 ? take6.ms : (keep6 ? '保持' : '不写')) + 'ms'
      : '上一轮固定仍可用（' + ms + 'ms），保持'
  } else reason = '现状已是最优' + (sysHasV6 ? '（系统 AAAA 可直接用）' : '')
  return { dom: dom, pin4: use ? use.ip4 : null, pin6: use ? use.ip6 : null, pin4ms: use ? use.ms : 0,
    alt4: pin4 ? pin4.ip : null, alt6: pin6 ? pin6.ip : null,
    base4: base4 || null, base6: base6 || null, sysHasV6: sysHasV6, reason: reason, tried: res.length, all: res }
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
  return { take4: take4, take6: take6 }
}

async function main() {
  fs.mkdirSync(LOGDIR, { recursive: true })
  // dry-run 是纯只读：不建锁文件、不备份、不写 hosts、不刷 DNS、不做落地复核
  if (!DRY) acquireLock()
  if (REVERT) {
    if (DRY) { log('--dry 下不执行回滚（回滚是写操作），去掉 --dry 再跑'); return }
    const cur = readHosts(CFG.hosts_path)
    if (cur === null) { log('hosts 文件不存在，无需回滚（重建需提权，见 repair-hosts.ps1）'); return }
    if (cur.indexOf(MARK_S) < 0) { log('hosts 里没有本工具写入的块'); return }
    const r = await commitHosts({ hostsPath: CFG.hosts_path, bdir: path.join(HERE, 'backups'), block: '', markS: MARK_S, markE: MARK_E, keep: 5 })
    if (!r.ok) { log('回滚写入未成立：' + r.reason + (r.error ? '（' + r.error + '）' : '')) ; process.exitCode = 1; return }
    await run('ipconfig.exe', ['/flushdns'], 10000)
    log('已回滚：accel 块移除，DNS 缓存刷新')
    return
  }
  log('==== 一轮选路开始 ' + (DRY ? '(dry-run)' : '') + ' ====')
  // hosts 缺失（重建需提权）：拒绝进入，绝不在半坏状态下继续——2026-10-13 事故守卫
  if (!DRY && readHosts(CFG.hosts_path) === null) {
    log('hosts 文件缺失：本轮拒绝进入（重建需提权，运行 repair-hosts.ps1；本轮不动任何东西）')
    process.exitCode = 1
    return
  }
  // 交互式 shell 常带 http_proxy/https_proxy：本轮 curl 已用 --noproxy 强制直连，这里只做提示
  const proxied = ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'].filter(function (k) { return process.env[k] })
  if (proxied.length) log('提示：环境里有 ' + proxied.join('/') + '，本轮实测已 --noproxy 强制直连（换空环境跑更接近计划任务的结论）')
  // Clash 侦测（2026-10-13）：读本机 mihomo 状态（只读命名管道），写进报告并提示"钉会不会被代理绕过"
  const clash = await readClashState()
  log('Clash：' + describeClash(clash))
  if (clash.up) {
    if (clash.githubDirect) {
      log('  github 家族由「GH直连优先」组接管：当前 ' + clash.githubDirect.now + '（直连优先，不通自动回落节点）')
    } else if (clash.viaNode) {
      log('  提示：github 家族当前由出口节点接管（' + ((clash.end && clash.end.name) || '?') +
        '）；走系统代理的应用不读 hosts，hosts 钉只服务直连流量。')
    }
  }
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
  if (POOL.pruned) log('候选池状态裁剪：移除 ' + POOL.pruned + ' 条过期观测')
  // 池子启用时不再每轮抓第三方列表：候选已经在 candidates.json 里，且它只当 hint
  const remote = POOL.on ? {} : await loadRemoteCandidates()
  log(POOL.on
    ? '候选池已启用：每域每轮探 ' + ((CFG.pool && CFG.pool.probe_per_round) || 8) + ' 个（exploit + explore）'
    : '候选池未启用（缺 candidates.json 或 pool.enabled=false），本轮沿用旧候选来源')
  const report = { at: new Date().toISOString(), env: env, clash: clash.up
    ? { up: true, version: clash.version, mode: clash.mode, tun: clash.tun, mixedPort: clash.mixedPort, end: clash.end, viaNode: clash.viaNode, githubDirect: clash.githubDirect }
    : { up: false }, pool: { enabled: POOL.on }, domains: {} }
  const chosen = []
  for (const dom of Object.keys(CFG.domains)) {
    if (!DOMRE.test(dom)) continue
    if (NEVER_PIN_DOMAINS.has(dom)) {
      report.domains[dom] = { baseline: null, baseline6: null, pinned: null, pinned6: null,
        reason: 'safety-no-pin：GitHub 核心域保留动态 DNS，避免间歇性 IP 固定影响主站/资源' }
      log('保护性跳过 ', dom.padEnd(28), '不写入 hosts 固定（使用动态 DNS）')
      continue
    }
    if (CFG.deny.indexOf(dom) >= 0) continue
    const conf = CFG.domains[dom] || {}
    const r = await evalDomain(dom, conf, remote)
    if (r.pin4 || r.pin6) chosen.push({ dom: dom, ip: r.pin4, ip6: r.pin6, alt4: r.alt4, alt6: r.alt6, canary: conf.canary || '/' })
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
    return [MARK_S, '# 生成时间 ' + new Date().toISOString(), '# 候选来源 GitHub520 + GitHub-IP-hosts + ineo6 + DoH(A/AAAA) + 内置，全部经本机 TLS 实测', lines.join('\r\n'), MARK_E].join('\r\n')
  }
  const doWrite = async function (list) {
    if (DRY) return { ok: true, mode: 'dry' }
    const r = await commitHosts({ hostsPath: CFG.hosts_path, bdir: path.join(HERE, 'backups'), block: render(list), markS: MARK_S, markE: MARK_E, keep: 5 })
    if (!r.ok) {
      log('!! hosts 写入未成立：reason=' + r.reason + (r.error ? ' error=' + r.error : '') +
        (r.reason === 'missing' ? '（hosts 缺失，重建需提权：repair-hosts.ps1）' : ''))
      return r
    }
    if (r.mode === 'write-retry') log('写入读回首次不一致，重写后成立')
    await run('ipconfig.exe', ['/flushdns'], 8000)
    return r
  }
  // 落地复核：整链 + 分族；分族失败只撤该族
  const recheck = async function (list) {
    const bad = []
    const drops = []
    for (const c of list) {
      const pins = []
      if (c.ip) pins.push({ fam: 4, ip: c.ip })
      if (c.ip6) pins.push({ fam: 6, ip: c.ip6 })
      const v = await verifyDomain(c.dom, c.canary, pins)
      log((v.sys.kind === 'ok' ? (v.sys.retried ? '生效·重试后 ' : '生效  ') : v.sys.kind === 'inactive' ? '未复核' : '! 未生效') + c.dom.padEnd(28) + v.sys.detail)
      if (v.sys.kind === 'ok') {
        for (const f of v.fam) {
          if (f.kind === 'ok' || f.kind === 'inactive') continue
          log('  ' + c.dom + ' 分族复核失败 v' + f.fam + ' ' + f.ip + '（重试后仍失败）：' + f.detail)
          drops.push({ c: c, fam: f.fam, ip: f.ip })
        }
      } else if (v.sys.kind !== 'inactive') {
        bad.push({ c: c, v: v.sys })
      }
    }
    return { bad: bad, drops: drops }
  }
  const applyDrops = async function (drops) {
    if (!drops.length) return true
    for (const d of drops) {
      if (d.fam === 4 && d.c.ip === d.ip) d.c.ip = null
      if (d.fam === 6 && d.c.ip6 === d.ip) d.c.ip6 = null
    }
    const names = drops.map(function (d) { return d.c.dom + ':v' + d.fam })
    const w = await doWrite(chosen)
    if (!w.ok) { log('分族撤销写入未成立（' + w.reason + '），本轮中止复核侧写回'); return false }
    log('分族撤销 ' + drops.length + ' 条：' + names.join(', '))
    for (const d of drops) {
      const rd = report.domains[d.c.dom]
      if (rd) { rd.fam_revoked = (rd.fam_revoked || []).concat(['v' + d.fam]); if (!d.c.ip && !d.c.ip6) rd.revoked = true }
    }
    return true
  }
  // 写入后按真实解析复核：探针可能单轮侥幸通过，落地不成立就不该留在 hosts 里
  let bad = []
  let aborted = false
  if (DRY) {
    log('dry-run：跳过写入与落地复核（复核以真实写入为前提）')
  } else {
    const w = await doWrite(chosen)
    if (!w.ok) {
      aborted = true
      log('==== 本轮中止：hosts 未写入（' + w.reason + '），不改动任何固定 ====')
    } else {
      const rc1 = await recheck(chosen)
      bad = rc1.bad
      if (!(await applyDrops(rc1.drops))) aborted = true
      if (!aborted) {
        // 泄漏的常见原因是只钉了一族，另一族仍由 DNS/隧道给出并被优先选中。
        // 先按族补钉（用实测可用的另一族候选），补不上的才撤销整域。
        const plugged = []
        for (const b of bad) {
          const pl = planAfterLeak(b.c, b.v.remote)
          if (pl.action === 'plug') { b.c[pl.key] = pl.ip; plugged.push(b.c.dom + (pl.key === 'ip6' ? ':v6' : ':v4')) }
          else log('  ' + b.c.dom + ' 失败族已写过或无候选 -> 撤销')
        }
        if (plugged.length) {
          log('补钉未覆盖族：' + plugged.join(' ') + ' -> 第二轮复核')
          const w2 = await doWrite(chosen)
          if (!w2.ok) { aborted = true } else {
            const rc2 = await recheck(chosen)
            bad = rc2.bad
            if (!(await applyDrops(rc2.drops))) aborted = true
          }
        }
      }
    }
  }
  const failed = bad.map(function (x) { return x.c.dom })
  if (!aborted && failed.length && !DRY) {
    const w3 = await doWrite(chosen.filter(function (c) { return failed.indexOf(c.dom) < 0 }))
    if (w3.ok) log('已撤销 ' + failed.length + ' 条：' + failed.join(', '))
    else log('撤销写入未成立（' + w3.reason + '）：' + failed.join(', '))
  }
  if (aborted) report.aborted = true
  for (const d of failed) if (report.domains[d]) report.domains[d].revoked = true
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
  // 落地复核的响应码口径：code=000（TCP 连上但请求挂死/超时）不算落地；objects 根路径正常就回 404
  const codeCases = [
    ['github.com', 0, false], ['github.com', 200, true], ['github.com', 404, false],
    ['objects.githubusercontent.com', 404, true], ['objects.githubusercontent.com', 0, false],
    ['raw.githubusercontent.com', 200, true], ['raw.githubusercontent.com', 503, false]
  ]
  for (const [dom, code, want] of codeCases) {
    const got = allowedCodes(dom).indexOf(code) >= 0
    const ok = got === want
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  落地码 ' + dom + ' code=' + code + ' -> ' + got + (ok ? '' : '，期望 ' + want))
  }
  // Stability invariant: critical GitHub endpoints never enter the hosts pin set.
  const protectedDomains = ['github.com', 'gist.github.com', 'api.github.com', 'codeload.github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com', 'avatars.githubusercontent.com', 'github.githubassets.com']
  const protectedOk = protectedDomains.every(function (d) { return NEVER_PIN_DOMAINS.has(d) })
  if (!protectedOk) bad++
  console.log('  ' + (protectedOk ? 'PASS' : 'FAIL') + '  GitHub 核心域禁止静态 hosts 固定' + (protectedOk ? '' : '（缺失保护域名）'))
  // 模块接线自检：ip.mjs 的严格校验确实被本进程用上（垃圾形式一律为 0）
  const wireCases = [
    ['2606:50c0:8000::153', 6], ['104.17.208.5', 4], ['2606:50c0:8000:::1', 0], ['', 0]
  ]
  for (const [ip, want] of wireCases) {
    const got = fam(ip)
    const ok = got === want
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  接线 fam(' + (ip || '(空)') + ') = ' + got + (ok ? '' : '，期望 ' + want))
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
  const total = cases.length + codeCases.length + wireCases.length + pinCases.length
  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测 ' + total + '/' + total + ' 通过')
  process.exit(bad ? 1 : 0)
}

main().then(releaseLock, function (e) { log('致命', (e && e.stack) || String(e)); releaseLock(); process.exit(1) })
