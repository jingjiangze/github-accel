// hostsio.mjs —— hosts 文件读写（命令式外壳集中于此；判定核心留在调用方）。
// 2026-10-13 v2 重写 + 当日事故教训（务必保留注释）：
//  - 本机实测三条结论：etc 目录不可创建文件（EACCES）；跨目录 rename 到 hosts = EPERM；
//    .NET File.Replace 在本机失败时会"先移走目标再失败"，造成 hosts 缺失 —— **永久禁用**。
//  - 因此唯一可行写入原语 = 直接 writeFileSync；安全策略 = 写前备份 + 直写 + 写后逐字节读回比对
//    + 比对失败重写一次 + 仍失败则从备份恢复并报错；hosts 缺失 → 拒绝继续（重建需提权，指向 repair-hosts.ps1）。
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// ---------- 纯函数 ----------
export function stripBlock(text, markS, markE) {
  const i = text.indexOf(markS)
  if (i < 0) return text
  const j = text.indexOf(markE, i)
  return j < 0 ? text : text.slice(0, i) + text.slice(j + markE.length)
}
// 与旧版 writeHosts 逐字节一致：去旧块 → 尾部换行归一 → '\r\n' + 新块 + '\r\n'
export function composeHosts(cur, block, markS, markE) {
  const rest = stripBlock(cur, markS, markE).replace(/[\r\n]+$/, '')
  return rest + '\r\n' + block + '\r\n'
}
// 解析标记块内的 "IP 域" 行 → Map<dom, Set<ip>>（isIp/isDom 由调用方注入，保持本模块无业务依赖）
export function parsePins(text, markS, markE, isIp, isDom) {
  const m = new Map()
  const i = text.indexOf(markS)
  const j = text.indexOf(markE, i)
  if (i < 0 || j < 0) return m
  for (const line of text.slice(i, j).split(/\r?\n/)) {
    const s = line.trim()
    if (!s || s.charAt(0) === '#') continue
    const p = s.split(/\s+/)
    if (p.length >= 2 && isIp(p[0]) && isDom(p[1])) {
      if (!m.has(p[1])) m.set(p[1], new Set())
      m.get(p[1]).add(p[0])
    }
  }
  return m
}

// ---------- IO ----------
export function readHosts(p) {
  try { return fs.readFileSync(p, 'utf8') } catch (e) { return null }
}
export function readBackEqual(p, expected) {
  try { return fs.readFileSync(p, 'utf8') === expected } catch (e) { return false }
}
// 唯一可行写入原语（2026-10-13 三条实测排除 rename / File.Replace，详见头注）
export function writeHostsFile(p, content) { fs.writeFileSync(p, content) }
// 写前备份 + 轮转。命名防撞：同一秒内多写不再互相覆盖（旧版同秒会重名）
export function backupRotate(srcPath, bdir, keep) {
  const cur = readHosts(srcPath)
  if (cur === null) return null
  fs.mkdirSync(bdir, { recursive: true })
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
  let bp = path.join(bdir, 'hosts-' + stamp)
  let n = 2
  while (fs.existsSync(bp)) { bp = path.join(bdir, 'hosts-' + stamp + '-' + n); n++ }
  fs.writeFileSync(bp, cur)
  const all = fs.readdirSync(bdir).filter(function (f) { return f.indexOf('hosts-') === 0 }).sort()
  while (all.length > (keep || 5)) fs.unlinkSync(path.join(bdir, all.shift()))
  return bp
}
// 安全提交：备份 → 直写 → 读回比对（失败重写一次）→ 仍失败从备份恢复并报错。hosts 缺失拒绝继续。
export function commitHosts(o) {
  const cur = readHosts(o.hostsPath)
  if (cur === null) return { ok: false, reason: 'missing' }
  const backup = backupRotate(o.hostsPath, o.bdir, o.keep || 5)
  const content = composeHosts(cur, o.block, o.markS, o.markE)
  try { writeHostsFile(o.hostsPath, content) } catch (e) {
    return { ok: false, reason: 'write', error: (e && (e.code || e.message)) || String(e), backup: backup }
  }
  if (readBackEqual(o.hostsPath, content)) return { ok: true, mode: 'write', backup: backup }
  try { writeHostsFile(o.hostsPath, content) } catch (e) {}
  if (readBackEqual(o.hostsPath, content)) return { ok: true, mode: 'write-retry', backup: backup }
  if (backup) { try { fs.copyFileSync(backup, o.hostsPath) } catch (e) {} }
  return { ok: false, reason: 'readback', backup: backup }
}

// 自测仅在本文件是入口时运行（防止劫持导入者的 --selftest）
const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
if (isMain && process.argv.includes('--selftest')) {
  let bad = 0
  const T = function (name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want)
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
  }
  const MKS = '# >>> t-s >>>', MKE = '# <<< t-e <<<'
  const BLOCK = MKS + '\r\n# gen 1\r\n9.9.9.9  test.example\r\n1.1.1.1  a.example\r\n' + MKE
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'accel-hostsio-'))

  // 1) composeHosts 与旧版 writeHosts 逐字节一致：去旧块 + 归一尾部换行 + '\r\n'+新块+'\r\n'
  const cur = 'std-line\r\n' + MKS + '\r\nold content\r\n' + MKE + '\r\n'
  T('compose 去旧块换新块', composeHosts(cur, BLOCK, MKS, MKE), 'std-line\r\n' + BLOCK + '\r\n')
  // 无旧块：直接拼在尾部
  T('compose 无旧块', composeHosts('header\r\n\r\n', BLOCK, MKS, MKE), 'header\r\n' + BLOCK + '\r\n')
  // 空块（--revert 语义：rest + '\r\n\r\n'）
  T('compose 空块', composeHosts('std\r\n' + MKS + '\r\nx\r\n' + MKE + '\r\n', '', MKS, MKE), 'std\r\n\r\n')

  // 2) parsePins：只收"IP 域"行，跳过注释/坏行
  const pins = parsePins('head\r\n' + MKS + '\r\n# cmt\r\n9.9.9.9  test.example\r\nbad line\r\n1.1.1.1  a.example\r\n' + MKE + '\r\ntail', MKS, MKE, function (s) { return s.indexOf('.') > 0 }, function (s) { return s.indexOf('.') > 0 })
  T('parsePins 收两条', [pins.get('test.example').has('9.9.9.9'), pins.get('a.example').has('1.1.1.1')], [true, true])
  T('parsePins 跳过坏行', pins.size, 2)

  // 3) commitHosts 成功路径：写入 + 备份 + 读回一致
  const hp = path.join(sandbox, 'hosts')
  const bdir = path.join(sandbox, 'backups')
  fs.writeFileSync(hp, 'orig\r\n' + MKS + '\r\nx\r\n' + MKE + '\r\n')
  const r1 = commitHosts({ hostsPath: hp, bdir: bdir, block: BLOCK, markS: MKS, markE: MKE, keep: 5 })
  T('commit 成功', [r1.ok, !!r1.backup], [true, true])
  T('commit 后内容', fs.readFileSync(hp, 'utf8'), 'orig\r\n' + BLOCK + '\r\n')
  T('commit 备份了原内容', fs.readFileSync(r1.backup, 'utf8').indexOf('orig') === 0, true)

  // 4) hosts 缺失：拒绝继续、不创建文件
  const miss = path.join(sandbox, 'not-exist')
  const r2 = commitHosts({ hostsPath: miss, bdir: bdir, block: BLOCK, markS: MKS, markE: MKE, keep: 5 })
  T('缺失时拒绝', [r2.ok, r2.reason, fs.existsSync(miss)], [false, 'missing', false])

  // 5) 备份轮转：keep=2
  for (let i = 0; i < 4; i++) commitHosts({ hostsPath: hp, bdir: bdir, block: BLOCK + i, markS: MKS, markE: MKE, keep: 2 })
  T('备份轮转保留 2 份', fs.readdirSync(bdir).filter(function (f) { return f.indexOf('hosts-') === 0 }).length, 2)

  // 6) readBackEqual
  T('读回一致', readBackEqual(hp, fs.readFileSync(hp, 'utf8')), true)
  T('读回不一致', readBackEqual(hp, 'different'), false)

  // 7) 读回失败自动修复：破坏文件后 commit 依旧成功且内容正确
  fs.writeFileSync(hp, 'broken')
  const r3 = commitHosts({ hostsPath: hp, bdir: bdir, block: BLOCK + 'fix', markS: MKS, markE: MKE, keep: 2 })
  T('无块文件可补块', [r3.ok, fs.readFileSync(hp, 'utf8')], [true, 'broken\r\n' + BLOCK + 'fix\r\n'])

  fs.rmSync(sandbox, { recursive: true, force: true })
  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测全部通过')
  process.exit(bad ? 1 : 0)
}
