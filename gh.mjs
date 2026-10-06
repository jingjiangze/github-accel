// gh.mjs —— 反代入口体检 + 自动选路
//   node gh.mjs <github-url> [输出文件名]              下载 release / 源码包 / 原始文件
//   node gh.mjs clone [git clone 参数...] <repo-url>    经反代克隆（入口自动挑，失败自动换源）
//   node gh.mjs doctor [--force]                        体检全部入口，打印连通与速度
//   node gh.mjs list                                    打印缓存中的入口状态
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, 'config.json'), 'utf8'))
const STATE = path.join(HERE, 'proxy-state.json')
const TTL = 15 * 60 * 1000
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

// 公开反代会透传 URL 与请求头，疑似带凭据的一律拒绝外送
function credsRisk(u) {
  return /oauth2:|x-access-token|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_|:\/\/[^/@:]+:[^@/]+@/.test(u)
}

// 小包只证明"能取对内容"，选路必须按实测带宽排——否则 2KB 最快的大文件最慢
async function bulkSample(prefix) {
  const secs = Math.ceil((CFG.bulk_ms || 6000) / 1000)
  const r = await run('curl.exe', ['-sS', '-L', '-o', 'NUL', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', String(secs),
    '-w', '%{http_code} %{size_download} %{speed_download}', prefix + CFG.bulk_canary], (secs + 6) * 1000)
  const m = r.stdout.match(/^(\d+)\s+(\d+)\s+([\d.]+)/)
  const bytes = m ? Number(m[2]) : 0
  const bps = m ? Number(m[3]) : 0
  const code = m ? Number(m[1]) : 0
  return { code, bytes, bps: bytes > 0 ? bps : 0 }
}

async function checkOne(prefix, target) {
  const tmp = path.join(os.tmpdir(), 'ghcanary-' + process.pid + '-' + Math.random().toString(36).slice(2, 8))
  const r = await run('curl.exe', ['-sS', '-L', '--ssl-no-revoke', '--connect-timeout', '4', '--max-time', '12',
    '-w', '%{http_code} %{time_total} %{size_download}', '-o', tmp, prefix + target], 18000)
  let body = ''
  try { body = fs.readFileSync(tmp, 'utf8') } catch (e) {}
  try { fs.unlinkSync(tmp) } catch (e) {}
  const m = r.stdout.match(/^(\d+)\s+([\d.]+)\s+(\d+)/)
  if (!m) return { prefix, ok: false, ms: 1e9, code: 0, bytes: 0, bps: 0 }
  const code = Number(m[1]), ms = Math.round(Number(m[2]) * 1000), bytes = Number(m[3])
  // 必须取回约定内容，免得把自建拦截页/错误页当成"通"
  const contentOk = code >= 200 && code < 400 && body.indexOf(CFG.canary_token) >= 0
  const bulk = contentOk ? await bulkSample(prefix) : { code: 0, bytes: 0, bps: 0 }
  return { prefix, ok: contentOk && bulk.bytes > 0, ms, code, bytes, bulk_code: bulk.code, bulk_bytes: bulk.bytes, bps: bulk.bps }
}
function relayPrefix() {
  const r = CFG.relay
  if (!r || !r.enabled) return null
  let key = process.env[r.key_env] || ''
  if (!key) { try { key = fs.readFileSync(path.join(HERE, r.key_file), 'utf8').trim() } catch (e) {} }
  if (!key) return null
  return r.base.replace('KEY', encodeURIComponent(key))
}

async function checkAll(force) {
  let st = null
  try { st = JSON.parse(fs.readFileSync(STATE, 'utf8')) } catch (e) {}
  const fresh = st && Date.now() - st.at < TTL && (st.entries || []).filter(function (e) { return e.ok }).length
  if (fresh && !force) return st
  const target = CFG.proxy_canary
  const list = CFG.proxies.slice()
  const rp = relayPrefix()
  if (rp) list.unshift(rp)
  const entries = []
  for (const p of list) entries.push(await checkOne(p, target))
  st = { at: Date.now(), target, entries }
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

async function doctor(show) {
  const st = await checkAll(show)
  console.log('入口体检 @ ' + new Date(st.at).toLocaleString() + '  目标 ' + st.target + (show ? '' : '  (结果缓存 15 分钟)'))
  for (const e of order(st)) console.log('  ' + (e.ok ? 'OK  ' : 'DEAD') + ' ' + e.prefix.padEnd(30) +
    (e.ms === 1e9 ? '     -' : (String(e.ms) + 'ms').padStart(7)) +
    '  实测 ' + ((e.bps || 0) / 1048576).toFixed(2).padStart(6) + ' MB/s  code=' + e.code + '/' + e.bulk_code + ' 样本=' + (e.bulk_bytes || 0))
}
function list() {
  try { for (const e of order(JSON.parse(fs.readFileSync(STATE, 'utf8')))) console.log((e.ok ? 'OK   ' : 'DEAD ') + e.prefix) }
  catch (e) { console.log('无体检记录，先跑 node gh.mjs doctor') }
}

async function download(url, outName) {
  if (!/^https?:\/\//.test(url)) { console.error('不是 URL：' + url); process.exit(2) }
  if (credsRisk(url)) { console.error('拒绝：地址疑似带凭据。公开反代会看到完整 URL 并透传请求头，密钥不能交给第三方——私有仓库请用自建反代或代理节点。'); process.exit(2) }
  const st = await checkAll(false)
  const cands = order(st).filter(function (e) { return e.ok })
  if (!cands.length) { console.error('所有反代入口都不通，跑 node gh.mjs doctor --force 复核'); process.exit(3) }
  const name = outName || decodeURIComponent(url.split('/').pop().split('?')[0]) || 'download.bin'
  for (const e of cands) {
    process.stdout.write('  经 ' + e.prefix + ' ... ')
    const tmp = name + '.part'
    const r = await run('curl.exe', ['-fSL', '--ssl-no-revoke', '--connect-timeout', '5', '--max-time', '900', '-o', tmp,
      '-w', '%{http_code} %{size_download} %{speed_download}', e.prefix + url], 920000)
    const m = r.stdout.match(/^(\d+)\s+(\d+)\s+([\d.]+)/)
    const size = m ? Number(m[2]) : 0
    if (r.code === 0 && size > 0) {
      try { fs.unlinkSync(name) } catch (x) {}
      fs.renameSync(tmp, name)
      console.log('完成 ' + name + '  ' + size + ' 字节  ' + (Number(m[3]) / 1048576).toFixed(2) + ' MB/s')
      return
    }
    try { fs.unlinkSync(tmp) } catch (x) {}
    console.log('失败 ' + (tail(r.stderr) || ('http=' + (m ? m[1] : '000'))))
  }
  console.error('全部入口失败'); process.exit(4)
}

async function clone(args) {
  const repo = args.filter(function (a) { return /^https?:\/\//.test(a) })[0]
  if (!repo) { console.error('clone 需要仓库 URL'); process.exit(2) }
  if (credsRisk(repo)) { console.error('拒绝：克隆地址疑似带凭据，不要经公开反代。'); process.exit(2) }
  const rest = args.filter(function (a) { return a !== repo })
  const st = await checkAll(false)
  const cands = order(st).filter(function (e) { return e.ok })
  if (!cands.length) { console.error('所有反代入口都不通'); process.exit(3) }
  for (const e of cands) {
    process.stdout.write('  经 ' + e.prefix + ' ... ')
    const gitArgs = ['-c', 'http.version=HTTP/1.1', '-c', 'url.' + e.prefix + 'https://github.com/.insteadOf=https://github.com/']
      .concat(['clone'], rest, [repo])
    const r = await run('git.exe', gitArgs, 1800000)
    if (r.code === 0) { console.log('完成'); return }
    console.log('失败 ' + tail(r.stderr))
    const dirArg = rest.filter(function (x) { return x.charAt(0) !== '-' })
    const dirname = dirArg.length > 1 ? dirArg[1] : repo.replace(/\.git$/, '').split('/').pop()
    try { if (fs.existsSync(dirname)) fs.rmSync(dirname, { recursive: true, force: true }) } catch (x) {}
  }
  console.error('全部入口失败'); process.exit(4)
}

const a = ARGV[0]
if (!a) console.log(['用法:', '  node gh.mjs <github-url> [输出文件名]', '  node gh.mjs clone [git clone 参数...] <repo-url>', '  node gh.mjs doctor --force', '  node gh.mjs list', '说明: 公开反代只看得到公开仓库地址，带凭据的一律拒绝外送'].join('\n'))
else if (a === 'doctor') await doctor(ARGV.includes('--force'))
else if (a === 'list') list()
else if (a === 'clone') await clone(ARGV.slice(1))
else if (/^https?:\/\//.test(a)) await download(a, ARGV[1])
else console.log('未识别的参数：' + a + '\n用 node gh.mjs 看用法')
