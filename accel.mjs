// 本机自适应 hosts：候选 IP（含 IPv6）全部来自实测，只有真的比现状快才写入
import fs from 'node:fs'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { promises as dnsp } from 'node:dns'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, 'config.json'), 'utf8'))
const MARK_S = '# >>> accel-start >>> 本机实测自动生成，请勿手工编辑'
const MARK_E = '# <<< accel-end <<<'
const LOGDIR = path.join(HERE, 'logs')
const LOG = path.join(LOGDIR, 'accel-' + new Date().toISOString().slice(0, 10) + '.log')
const ARGV = process.argv.slice(2)
const DRY = ARGV.includes('--dry')
const REVERT = ARGV.includes('--revert')
const VERBOSE = ARGV.includes('-v')
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/
const IPV6 = /^[0-9a-f:]+$/i
const DOMRE = /^[a-z0-9._-]+$/i

function now() { return new Date().toISOString().slice(11, 19) }
function log() {
  const line = now() + ' ' + Array.from(arguments).join(' ')
  console.log(line)
  try { fs.appendFileSync(LOG, line + '\r\n') } catch (e) {}
}
// 同一时刻只允许一轮：hosts 是读-改-写，两轮重叠会互相覆盖
const LOCK = path.join(HERE, 'run.lock')
const LOCK_STALE = 8 * 60 * 1000
function acquireLock() {
  try {
    const st = fs.statSync(LOCK)
    if (Date.now() - st.mtimeMs < LOCK_STALE) { log('已有实例在跑（锁未过期），本轮退出'); process.exit(0) }
    log('发现过期锁，接管')
  } catch (e) {}
  try { fs.writeFileSync(LOCK, process.pid + ' ' + new Date().toISOString()) } catch (e) {}
}
function releaseLock() { try { fs.unlinkSync(LOCK) } catch (e) {} }

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
  const r = await run('curl.exe', ['-sS', '-o', 'NUL', '--ssl-no-revoke', '--connect-timeout', '4',
    '--max-time', String(Math.ceil(CFG.probe.budget_ms / 1000)), '-w', '%{http_code} %{time_total} %{size_download} %{remote_ip}',
    '--resolve', dom + ':443:' + ip, url], CFG.probe.budget_ms + 6000)
  const m = r.stdout.match(/^(\d+)\s+([\d.]+)\s+(\d+)\s+(\S+)/)
  if (!m) return { ok: false, ms: 1e9, code: 0, bytes: 0, rip: '' }
  const code = Number(m[1]), ms = Math.round(Number(m[2]) * 1000), bytes = Number(m[3])
  // 语义正确才算数：错误后端返回的 400 页比卡死更危险，会静默把域名指到别的服务上
  const allow = (CFG.domains[dom] || {}).expect || CFG.probe.ok_codes || [200, 301, 302, 404]
  return { ok: allow.indexOf(code) >= 0 && bytes > 0, ms, code, bytes, rip: m[4] }
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
  const bdir = path.join(HERE, 'backups')
  fs.mkdirSync(bdir, { recursive: true })
  fs.writeFileSync(path.join(bdir, 'hosts-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)), cur)
  const all = fs.readdirSync(bdir).filter(function (f) { return f.indexOf('hosts-') === 0 }).sort()
  while (all.length > 5) fs.unlinkSync(path.join(bdir, all.shift()))
  if (!DRY) fs.writeFileSync(CFG.hosts_path, out)
  return out
}

async function evalDomain(dom, conf, remote) {
  const canary = conf.canary || '/'
  const cand = new Set()
  if (remote[dom]) for (const ip of remote[dom]) if (fam(ip) && (!conf.family || fam(ip) === conf.family)) cand.add(ip)
  for (const ip of ((CFG.static_ips || {})[dom] || []).concat((CFG.static_ips6 || {})[dom] || [])) if (fam(ip) && (!conf.family || fam(ip) === conf.family)) cand.add(ip)
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
  const byFam = function (f) { return res.filter(function (x) { return x.fam === f }).slice().sort(function (a, b) { return a.ms - b.ms }) }
  const g4 = byFam(4).filter(function (x) { return x.ok })
  const g6 = byFam(6).filter(function (x) { return x.ok })
  const base4 = res.find(function (x) { return x.kind === 'base4' })
  const base6 = res.find(function (x) { return x.kind === 'base6' })
  const pin4 = g4[0] || null, pin6 = g6[0] || null
  let use = null, reason = ''
  if (!sysHasV6) {
    // 系统本来只有 IPv4：直接按"更快才固定"
    if (!pin4) reason = '无可用候选，保持系统 DNS'
    else if (base4 && base4.ok && pin4.ip === base4.ip) reason = '现状已是最优'
    else if (!base4 || !base4.ok) { use = pin4; reason = '现状不可用，改用实测最快' }
    else if (pin4.ms < base4.ms * CFG.probe.win_ratio) { use = pin4; reason = '比现状快 ' + (100 - Math.round(pin4.ms / base4.ms * 100)) + '%' }
    else reason = '候选未显著优于现状(' + pin4.ms + ' vs ' + base4.ms + 'ms)'
  } else {
    // 系统有 AAAA：只写 IPv4 会被 v6 抢先，必须两族都实测可用且确实更快
    const better4 = !base4 || !base4.ok || (pin4 && pin4.ip !== base4.ip && pin4.ms < base4.ms * CFG.probe.win_ratio)
    const better6 = !base6 || !base6.ok || (pin6 && pin6.ip !== base6.ip && pin6.ms < base6.ms * CFG.probe.win_ratio)
    if (!pin6) reason = '系统有 AAAA，无可用 IPv6 候选，只写 v4 会被抢先 -> 跳过'
    else if (!pin4) reason = '无可用 IPv4 候选，保持系统 DNS'
    else if (!(better4 || better6)) reason = '两族现状已是最优'
    else {
      use = Object.assign({}, pin4, { also6: pin6.ip })
      reason = 'v4+v6 同时固定（现状 v4 ' + (base4 ? base4.ms + 'ms' : '不可用') + ' / v6 ' + (base6 ? base6.ms + 'ms' : '不可用') + '）'
    }
  }
  return { dom, pin4: use ? use.ip : null, pin4ms: use ? use.ms : 0, pin6: use && use.also6 ? use.also6 : null, base4: base4 || null, base6: base6 || null, sysHasV6, reason, tried: res.length, all: res }
}

async function verify(dom, canary, expect) {
  const url = 'https://' + dom + canary
  const r = await run('curl.exe', ['-sS', '-L', '-o', 'NUL', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '15',
    '-w', '%{remote_ip} %{http_code} %{time_total}', url], 20000)
  const m = r.stdout.match(/^(\S+)\s+(\d+)\s+([\d.]+)/)
  const rip = m ? m[1] : ''
  if (!rip) return { ok: false, detail: '连接失败 ' + (m ? m[2] : '000') }
  if (expect.indexOf(rip) < 0) return { ok: false, detail: '实际连到 ' + rip + '，不是写入的 ' + expect.join('/') }
  return { ok: true, detail: rip + ' ' + m[2] + ' ' + Math.round(Number(m[3]) * 1000) + 'ms' }
}

async function main() {
  fs.mkdirSync(LOGDIR, { recursive: true })
  acquireLock()
  if (REVERT) {
    if (fs.readFileSync(CFG.hosts_path, 'utf8').indexOf(MARK_S) < 0) { log('hosts 里没有本工具写入的块'); return }
    writeHosts('')
    await run('ipconfig.exe', ['/flushdns'], 10000)
    log('已回滚：accel 块移除，DNS 缓存刷新')
    return
  }
  log('==== 一轮选路开始 ' + (DRY ? '(dry-run)' : '') + ' ====')
  const remote = await loadRemoteCandidates()
  const report = { at: new Date().toISOString(), domains: {} }
  const chosen = []
  for (const dom of Object.keys(CFG.domains)) {
    if (CFG.deny.indexOf(dom) >= 0 || !DOMRE.test(dom)) continue
    const conf = CFG.domains[dom] || {}
    const r = await evalDomain(dom, conf, remote)
    if (r.pin4) chosen.push({ dom, ip: r.pin4, ip6: r.pin6, canary: conf.canary || '/' })
    report.domains[dom] = { baseline: r.base4, sys_has_aaaa: r.sysHasV6, pinned: r.pin4, pinned6: r.pin6, reason: r.reason, tried: r.tried, probed: r.all }
    log((r.pin4 ? '固定 ' : '跳过 '), dom.padEnd(28), (r.pin4 || (r.base4 && r.base4.ok ? r.base4.ip : '-')).padEnd(16),
      String(r.base4 ? r.base4.ms + 'ms' : '无').padEnd(9), String(r.pin4 ? r.pin4ms + 'ms' : '-').padEnd(9), r.reason)
    if (VERBOSE) for (const p of r.all) log('    ', p.kind.padEnd(6), p.ip.padEnd(22), p.ok ? 'ok ' : 'bad', (String(p.ms) + 'ms').padStart(9), 'code=' + p.code, 'B=' + p.bytes)
  }
  const render = function (list) {
    const lines = []
    for (const c of list.slice(0, CFG.probe.max_entries)) {
      lines.push(c.ip + '  ' + c.dom)
      if (c.ip6) lines.push(c.ip6 + '  ' + c.dom)
    }
    return [MARK_S, '# 生成时间 ' + new Date().toISOString(), '# 候选来源 GitHub520 + GitHub-IP-hosts + DoH(A/AAAA) + 内置，全部经本机 TLS 实测', lines.join('\r\n'), MARK_E].join('\r\n')
  }
  writeHosts(render(chosen))
  await run('ipconfig.exe', ['/flushdns'], 10000)
  // 写入后按真实解析复核：探针可能单轮侥幸通过，落地不成立就当场撤销，不给它活到下一轮的机会
  const failed = []
  for (const c of chosen) {
    const v = await verify(c.dom, c.canary, c.ip6 ? [c.ip, c.ip6] : [c.ip])
    log((v.ok ? '生效  ' : '! 撤销 ') + c.dom.padEnd(28) + v.detail)
    if (!v.ok) failed.push(c.dom)
  }
  if (failed.length && !DRY) {
    const keep = chosen.filter(function (c) { return failed.indexOf(c.dom) < 0 })
    writeHosts(render(keep))
    await run('ipconfig.exe', ['/flushdns'], 10000)
    log('已撤销 ' + failed.length + ' 条：' + failed.join(', '))
    for (const d of failed) if (report.domains[d]) { report.domains[d].revoked = true; report.domains[d].pin4 = null; report.domains[d].pinned = null }
  }
  fs.writeFileSync(path.join(HERE, 'report.json'), JSON.stringify(report, null, 1))
  log('==== 完成：评估 ' + Object.keys(report.domains).length + ' 域，保留 ' + (DRY ? 0 : chosen.length - failed.length) + ' 条固定，撤销 ' + failed.length + ' 条，报告 report.json ====')
}
main().then(releaseLock, function (e) { log('致命', (e && e.stack) || String(e)); releaseLock(); process.exit(1) })
