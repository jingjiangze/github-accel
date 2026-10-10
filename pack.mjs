// pack.mjs —— 打出「只含运行文件」的发行 zip（零依赖，跨平台）
//
//   node pack.mjs --out dist/accel.zip     构建 + 打印清单与 sha256
//   node pack.mjs --verify dist/accel.zip  校验 zip 内容与白名单完全一致（含 CRC 与解压往返）
//   node pack.mjs --selftest               离线自测（ZIP 读写往返 + CRC32 已知答案）
//
// 为什么是白名单而不是黑名单：发行包里只该有「能跑起来的东西」。CI、测试、.gitignore，
// 以及运行期产物（logs/ backups/ report.json proxy-state.json candidates.json
// pool-state.json manifest-cache.json dist/ run.lock relay-key）都不该混进去——黑名单
// 迟早会漏（这个仓库就漏过 manifest-cache.json）。所以这里逐个列文件，缺一个就报错，
// 免得改名之后静默打出一个缺件的包。
//
// 时间戳固定成 1980-01-01：同样的内容打出同样的字节（sha256 稳定），于是「包变了」只
// 可能因为文件变了，而不是因为打包时刻不同。这也是 reproducible build 的常规做法。
//
// 压缩用 Node 内置 zlib（逐文件在 store / deflate 里取更小的那个），CRC32 自己实现，
// 不依赖 zlib.crc32（Node 20 还没有它，而 CI 用的是 Node 20）。
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ARGV = process.argv.slice(2)
const SELFTEST = ARGV.includes('--selftest')

function opt(name, dflt) {
  const i = ARGV.indexOf('--' + name)
  return i >= 0 && ARGV[i + 1] && !ARGV[i + 1].startsWith('--') ? ARGV[i + 1] : dflt
}

// ---------- 白名单：只含运行文件 ----------
// 顺序固定（不排序、不遍历目录），这样清单本身也是可复现的。
const RUNTIME_FILES = [
  'LICENSE',
  'README.md',
  'accel.mjs',          // A 层：自适应 hosts
  'gh.mjs',             // B 层：反代入口竞速取件
  'manifest.mjs',       // 反代入口体检 -> 清单
  'discover.mjs',       // 候选发现
  'pool.mjs',           // 健康池
  'config.json',
  'manifest-seed.json',
  'install-task.ps1',   // 本机计划任务
  'run-hidden.vbs',
  'box/run-probe.ps1',  // 盒子侧常驻测速
  'box/install-task.ps1',
  'relay/wrangler.toml',              // 可选的自建中转端点
  'relay/functions/_middleware.js',
  'relay/public/index.html'
]

// ---------- CRC32 ----------
const CRC_TABLE = (function () {
  const t = new Int32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1)
    t[n] = c
  }
  return t
})()
function crc32(buf) {
  let c = -1
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8)
  return (c ^ -1) >>> 0
}

// ---------- ZIP 写 ----------
// 1980-01-01 00:00:00：DOS time 0，date = (year-1980)<<9 | month<<5 | day = 33
const DOS_TIME = 0
const DOS_DATE = 33
// 0o100644 << 16 是负数（JS 的 << 返回带符号 32 位），必须先 >>> 0 再写
const UNIX_FILE_MODE = (0o100644 << 16) >>> 0

function zipBuild(entries) {
  const locals = []
  const central = []
  let offset = 0
  for (const e of entries) {
    const raw = e.data
    const deflated = zlib.deflateRawSync(raw, { level: 9 })
    const useDeflate = deflated.length < raw.length
    const body = useDeflate ? deflated : raw
    const method = useDeflate ? 8 : 0
    const crc = crc32(raw)
    const name = Buffer.from(e.name, 'utf8')

    const lh = Buffer.alloc(30 + name.length)
    lh.writeUInt32LE(0x04034b50, 0)
    lh.writeUInt16LE(20, 4)            // version needed
    lh.writeUInt16LE(0, 6)             // flags
    lh.writeUInt16LE(method, 8)
    lh.writeUInt16LE(DOS_TIME, 10)
    lh.writeUInt16LE(DOS_DATE, 12)
    lh.writeUInt32LE(crc, 14)
    lh.writeUInt32LE(body.length, 18)
    lh.writeUInt32LE(raw.length, 22)
    lh.writeUInt16LE(name.length, 26)
    lh.writeUInt16LE(0, 28)            // extra len
    name.copy(lh, 30)
    locals.push(lh, body)

    const ch = Buffer.alloc(46 + name.length)
    ch.writeUInt32LE(0x02014b50, 0)
    ch.writeUInt16LE(0x031E, 4)        // version made by: unix (3) << 8 | 30
    ch.writeUInt16LE(20, 6)            // version needed
    ch.writeUInt16LE(0, 8)             // flags
    ch.writeUInt16LE(method, 10)
    ch.writeUInt16LE(DOS_TIME, 12)
    ch.writeUInt16LE(DOS_DATE, 14)
    ch.writeUInt32LE(crc, 16)
    ch.writeUInt32LE(body.length, 20)
    ch.writeUInt32LE(raw.length, 24)
    ch.writeUInt16LE(name.length, 28)
    ch.writeUInt16LE(0, 30)            // extra len
    ch.writeUInt16LE(0, 32)            // comment len
    ch.writeUInt16LE(0, 34)            // disk number start
    ch.writeUInt16LE(0, 36)            // internal attrs
    ch.writeUInt32LE(UNIX_FILE_MODE, 38)
    ch.writeUInt32LE(offset, 42)
    name.copy(ch, 46)
    central.push(ch)

    offset += lh.length + body.length
  }
  const cd = Buffer.concat(central)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(0, 4)
  eocd.writeUInt16LE(0, 6)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(cd.length, 12)
  eocd.writeUInt32LE(offset, 16)
  eocd.writeUInt16LE(0, 20)
  return Buffer.concat([Buffer.concat(locals), cd, eocd])
}

// ---------- ZIP 读（只为自检与 --verify；够用即可，不处理 zip64 / 加密） ----------
function zipRead(buf) {
  let eocd = -1
  for (let i = buf.length - 22; i >= 0; i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  if (eocd < 0) throw new Error('不是 zip：找不到 EOCD')
  const total = buf.readUInt16LE(eocd + 10)
  const cdSize = buf.readUInt32LE(eocd + 12)
  const cdOff = buf.readUInt32LE(eocd + 16)
  if (cdOff + cdSize > eocd) throw new Error('中央目录越界')
  const out = []
  let p = cdOff
  for (let i = 0; i < total; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('中央目录项签名不对 @' + p)
    const method = buf.readUInt16LE(p + 10)
    const crc = buf.readUInt32LE(p + 16)
    const compSize = buf.readUInt32LE(p + 20)
    const rawSize = buf.readUInt32LE(p + 24)
    const nameLen = buf.readUInt16LE(p + 28)
    const extraLen = buf.readUInt16LE(p + 30)
    const commentLen = buf.readUInt16LE(p + 32)
    const lho = buf.readUInt32LE(p + 42)
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen)
    if (buf.readUInt32LE(lho) !== 0x04034b50) throw new Error('本地头签名不对 @' + name)
    const lNameLen = buf.readUInt16LE(lho + 26)
    const lExtraLen = buf.readUInt16LE(lho + 28)
    const dataOff = lho + 30 + lNameLen + lExtraLen
    const body = buf.subarray(dataOff, dataOff + compSize)
    const data = method === 8 ? zlib.inflateRawSync(body) : Buffer.from(body)
    if (data.length !== rawSize) throw new Error(name + '：解压长度不符')
    const got = crc32(data)
    if (got !== crc) throw new Error(name + '：CRC 不符 ' + got.toString(16) + ' != ' + crc.toString(16))
    out.push({ name: name, data: data, method: method })
    p += 46 + nameLen + extraLen + commentLen
  }
  return out
}

// ---------- 构建 ----------
function collect(root) {
  const entries = []
  const missing = []
  for (const rel of RUNTIME_FILES) {
    const abs = path.join(root, rel)
    if (!fs.existsSync(abs)) { missing.push(rel); continue }
    entries.push({ name: rel, data: fs.readFileSync(abs) })
  }
  if (missing.length) throw new Error('白名单里的文件不存在（改名了？）：\n  ' + missing.join('\n  '))
  return entries
}
function build(root) {
  return zipBuild(collect(root))
}

// ---------- 离线自测 ----------
if (SELFTEST) {
  let bad = 0
  const T = function (name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want)
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
  }
  // CRC32 已知答案：'123456789' -> 0xCBF43926（ZIP/PNG 用的那个多项式）
  T('CRC32 标准向量', crc32(Buffer.from('123456789')).toString(16), 'cbf43926')
  T('CRC32 空输入', crc32(Buffer.alloc(0)), 0)
  // 往返：压缩与不压缩两条路都要走通（小文件走 store，重复内容走 deflate）
  const payload = [
    { name: 'small.txt', data: Buffer.from('abc') },
    { name: 'nested/hello.mjs', data: Buffer.from('x'.repeat(4096)) },
    { name: 'empty.json', data: Buffer.alloc(0) },
    { name: 'utf8.md', data: Buffer.from('# 中文标题\n正文\n', 'utf8') }
  ]
  const zb = zipBuild(payload)
  const back = zipRead(zb)
  T('往返条目数', back.length, 4)
  T('往返顺序与路径', back.map(function (e) { return e.name }), ['small.txt', 'nested/hello.mjs', 'empty.json', 'utf8.md'])
  T('往返内容一致', back.every(function (e, i) { return e.data.equals(payload[i].data) }), true)
  T('小文件用 store', back[0].method, 0)
  T('大文件用 deflate', back[1].method, 8)
  T('压缩确实变小', zb.length < payload[1].data.length, true)
  T('可复现：同样输入同样字节', zipBuild(payload).equals(zb), true)
  T('时间戳固定 1980-01-01', [zb.readUInt16LE(10), zb.readUInt16LE(12)], [0, 33])
  let threw = false
  try { zipRead(Buffer.from('not a zip')) } catch (e) { threw = true }
  T('坏输入报错而不是静默', threw, true)
  // 真实白名单：文件都在，且清单与常量一致
  let real = null
  try { real = build(HERE) } catch (e) { console.log('  FAIL  真实白名单构建：' + e.message); bad++ }
  if (real) {
    const names = zipRead(real).map(function (e) { return e.name })
    T('发行包条目 = 白名单', names, RUNTIME_FILES)
    T('不含 CI / 测试 / 运行期产物', names.some(function (n) {
      return /^\.github\/|\.gitignore$|relay\/test\/|proxy-state|candidates\.json|pool-state|manifest-cache|^dist\//.test(n)
    }), false)
  }
  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测全部通过')
  process.exit(bad ? 1 : 0)
}

// ---------- CLI ----------
const outFile = opt('out', '')
const verifyFile = opt('verify', '')
if (verifyFile) {
  const buf = fs.readFileSync(verifyFile)
  const got = zipRead(buf).map(function (e) { return e.name })
  const want = RUNTIME_FILES.slice()
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error('包内容与白名单不一致\n  包内: ' + got.join(', ') + '\n  期望: ' + want.join(', '))
    process.exit(1)
  }
  console.log('内容与白名单一致（' + got.length + ' 个文件，CRC 与解压往返均已校验）')
  console.log('sha256 ' + crypto.createHash('sha256').update(buf).digest('hex'))
} else if (outFile) {
  const buf = build(HERE)
  fs.mkdirSync(path.dirname(path.resolve(outFile)), { recursive: true })
  fs.writeFileSync(outFile, buf)
  for (const e of zipRead(buf)) console.log('  ' + String(e.data.length).padStart(7) + '  ' + e.name)
  console.log('打包 ' + zipRead(buf).length + ' 个运行文件 → ' + outFile + '（' + buf.length + ' 字节）')
  console.log('sha256 ' + crypto.createHash('sha256').update(buf).digest('hex'))
} else {
  console.log('用法: node pack.mjs --out dist/accel.zip | --verify <zip> | --selftest')
}
