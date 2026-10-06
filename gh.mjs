// gh.mjs —— GitHub 取件工具：入口实时竞速（不依赖"上次测速第一名"）
//   node gh.mjs <github-url> [输出文件名]              并发竞速下载，先出数据的胜出，停滞自动换源续传
//   node gh.mjs clone [git clone 参数...] <repo-url>    先并发探 info/refs 只留真 pkt-line 的入口，再克隆
//   node gh.mjs doctor [--force]                        入口体检（内容标记 + 带宽样本两级判定）
//   node gh.mjs list                                    打印缓存中的入口状态
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFile, spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, 'config.json'), 'utf8'))
const STATE = path.join(HERE, 'proxy-state.json')
const TTL = (CFG.proxy_ttl_s || 60) * 1000
const ARGV = process.argv.slice(2)

function run(exe, args, timeoutMs) {
  return new Promise(function (resolve) {
    execFile(exe, args, { maxBuffer: 64 * 1024 * 1024, windowsHide: true, timeout: timeoutMs || 60000, encoding: 'utf8' },
      function (err, out, errout) {
        resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: (out || '').trim(), stderr: (errout || '').trim() })
      })
  })
}
function tail(s) { const l = String(s || '').split(/\r?\n/).filter(Boolean); return l.length ? l[l.length - 1] : '' }
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms) }) }
function mbps(bps) { return (bps / 1048576).toFixed(2) }

function credsRisk(u) {
  return /oauth2:|x-access-token|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_|:\/\/[^/@:]+:[^@/]+@/.test(u)
}
function relayPrefix() {
  const r = CFG.relay
  if (!r || !r.enabled) return null
  let key = process.env[r.key_env] || ''
  if (!key) { try { key = fs.readFileSync(path.join(HERE, r.key_file), 'utf8').trim() } catch (e) {} }
  if (!key) return null
  return r.base.replace('KEY', encodeURIComponent(key))
}
function entryList() {
  const list = CFG.proxies.slice()
  const rp = relayPrefix()
  if (rp) list.unshift(rp)
  return list
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
async function checkOne(prefix) {
  const tmp = path.join(os.tmpdir(), 'ghcanary-' + process.pid + '-' + Math.random().toString(36).slice(2, 8))
  const r = await run('curl.exe', ['-sS', '-L', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '12',
    '-w', '%{http_code} %{time_total} %{size_download}', '-o', tmp, prefix + CFG.proxy_canary], 18000)
  let body = ''
  try { body = fs.readFileSync(tmp, 'utf8') } catch (e) {}
  try { fs.unlinkSync(tmp) } catch (e) {}
  const m = r.stdout.match(/^(\d+)\s+([\d.]+)\s+(\d+)/)
  if (!m) return { prefix, ok: false, ms: 1e9, code: 0, bytes: 0, bps: 0 }
  const code = Number(m[1]), ms = Math.round(Number(m[2]) * 1000)
  // 必须取回约定内容，免得把自建拦截页/错误页当成"通"
  const contentOk = code >= 200 && code < 400 && body.indexOf(CFG.canary_token) >= 0
  const bulk = contentOk ? await bulkSample(prefix) : { code: 0, bytes: 0, bps: 0 }
  return { prefix, ok: contentOk && bulk.bytes > 0, ms, code, bytes: Number(m[3]), bulk_code: bulk.code, bulk_bytes: bulk.bytes, bps: bulk.bps }
}
async function checkAll(force) {
  let st = null
  try { st = JSON.parse(fs.readFileSync(STATE, 'utf8')) } catch (e) {}
  const fresh = st && Date.now() - st.at < TTL && (st.entries || []).some(function (e) { return e.ok })
  if (fresh && !force) return st
  const entries = []
  for (const p of entryList()) entries.push(await checkOne(p))
  st = { at: Date.now(), target: CFG.proxy_canary, entries }
  fs.writeFileSync(STATE, JSON.stringify(st, null, 1))
  return st
}
function order(st) {
  return (st.entries || []).slice().sort(function (a, b) {
    if (a.ok !== b.ok) return a.ok ? -1 : 1
    if ((b.bps || 0) !== (a.bps || 0)) return (b.bps || 0) - (a.bps || 0)
    return a.ms - b.ms
  })
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
  const st = await checkAll(false)
  const cands = order(st).filter(function (e) { return e.ok })
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
  console.log('  并发竞速：' + parts.map(function (p) { return p.entry.prefix.replace(/^https:\/\//, '').slice(0, 22) }).join(' | '))

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
  console.log('完成  ' + name + '  ' + (m ? m[2] : statSize(name)) + ' 字节  ' + mbps(m ? Number(m[3]) : 0) + ' MB/s  经 ' + winner.entry.prefix +
    (winner.tries ? '（续传 ' + winner.tries + ' 次）' : ''))
}

// ---------- 竞速克隆 ----------
async function probeRefs(repo) {
  const st = await checkAll(false)
  const cands = order(st).filter(function (e) { return e.ok })
  const out = []
  await Promise.all(cands.map(async function (e) {
    const u = e.prefix + repo + '/info/refs?service=git-upload-pack'
    const tmp = path.join(os.tmpdir(), 'ghrefs-' + Math.random().toString(36).slice(2, 8))
    const r = await run('curl.exe', ['-sS', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '10',
      '-H', 'User-Agent: git/2.50.0', '-o', tmp, '-w', '%{http_code}', u], 14000)
    let body = ''
    try { body = fs.readFileSync(tmp, 'latin1').slice(0, 200) } catch (e) {}
    try { fs.unlinkSync(tmp) } catch (e) {}
    // 必须是 pkt-line（十六进制长度开头），不是 HTML 页
    const ok = r.stdout === '200' && /^[0-9a-f]{4}# service=git-upload-pack/.test(body)
    out.push({ entry: e, ok, head: body.slice(0, 24) })
  }))
  return out.filter(function (x) { return x.ok }).map(function (x) { return x.entry })
}

async function clone(args) {
  const repo = args.filter(function (a) { return /^https?:\/\//.test(a) })[0]
  if (!repo) { console.error('clone 需要仓库 URL'); process.exit(2) }
  if (credsRisk(repo)) { console.error('拒绝：克隆地址疑似带凭据，不要经公开反代。'); process.exit(2) }
  const rest = args.filter(function (a) { return a !== repo })
  let pool = await probeRefs(repo)
  if (!pool.length) {
    const st = await checkAll(true)
    pool = order(st).filter(function (e) { return e.ok })
    console.log('  info/refs 探测没选出可用入口，退化为按体检带宽顺序重试')
  }
  if (!pool.length) { console.error('没有可用入口'); process.exit(3) }
  const C = CFG.clone || {}
  for (const e of pool) {
    for (let attempt = 1; attempt <= (C.same_retry || 2); attempt++) {
      process.stdout.write('  经 ' + e.prefix.replace(/^https:\/\//, '') + ' 第' + attempt + ' 次 ... ')
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

async function doctor(show) {
  const st = await checkAll(show)
  console.log('入口体检 @ ' + new Date(st.at).toLocaleString() + '  目标 ' + st.target + (show ? '' : '  (缓存 ' + (CFG.proxy_ttl_s || 60) + 's)'))
  for (const e of order(st)) console.log('  ' + (e.ok ? 'OK  ' : 'DEAD') + ' ' + e.prefix.padEnd(30) +
    (e.ms === 1e9 ? '     -' : (String(e.ms) + 'ms').padStart(7)) +
    '  实测 ' + mbps(e.bps || 0).padStart(6) + ' MB/s  code=' + e.code + '/' + e.bulk_code + ' 样本=' + (e.bulk_bytes || 0))
}
function list() {
  try { for (const e of order(JSON.parse(fs.readFileSync(STATE, 'utf8')))) console.log((e.ok ? 'OK   ' : 'DEAD ') + e.prefix + '  ' + mbps(e.bps || 0) + ' MB/s') }
  catch (e) { console.log('无体检记录，先跑 node gh.mjs doctor') }
}

const a = ARGV[0]
if (!a) console.log(['用法:', '  node gh.mjs <github-url> [输出文件名]', '  node gh.mjs clone [git clone 参数...] <repo-url>', '  node gh.mjs doctor --force', '  node gh.mjs list', '说明: 竞速选路，不依赖上次测速结果；带凭据的地址一律拒绝外送'].join('\n'))
else if (a === 'doctor') await doctor(ARGV.includes('--force'))
else if (a === 'list') list()
else if (a === 'clone') await clone(ARGV.slice(1))
else if (/^https?:\/\//.test(a)) await race(a, ARGV[1] || decodeURIComponent(a.split('/').pop().split('?')[0]) || 'download.bin')
else console.log('未识别的参数：' + a)
