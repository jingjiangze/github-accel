// ip.mjs —— 纯 IP 工具（零 IO、零配置读取）：全工具唯一的 IP 形式校验/分类来源。
// 2026-10-13 v2 重写：此前 fam/isV6/isFakeIp 等散落在 accel/discover/pool 三处各自维护，
// 曾出现"三处口径不一致、垃圾地址混进候选池"的事故面。这里统一收口，并用 node:net 严格校验
// （比自写正则严：组数、HE 合法性都会被拒）。
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// ---------- 形式与规范化 ----------
export function fam(ip) { return net.isIP(String(ip === undefined || ip === null ? '' : ip).trim()) }
export function isV4(ip) { return fam(ip) === 4 }
export function isV6(ip) { return fam(ip) === 6 }
export function num4(ip) {
  const p = String(ip).trim().split('.')
  return (((+p[0]) << 24) | ((+p[1]) << 16) | ((+p[2]) << 8) | (+p[3])) >>> 0
}
export function str4(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.') }
// v6 → 8 组（十进制→16 进制规范形式，去前导零）；非法 → null
export function expand6(ip) {
  const t = String(ip === undefined || ip === null ? '' : ip).trim().toLowerCase().split('%')[0]
  if (net.isIP(t) !== 6) return null
  const parts = t.split('::')
  const head = parts[0] ? parts[0].split(':') : []
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : []
  if (head.length + tail.length > 8) return null
  const g = head.concat(new Array(8 - head.length - tail.length).fill('0'), tail)
  return g.map(function (x) { return parseInt(x || '0', 16).toString(16) })
}
// 同一 /24（v4）或 /64（v6）当作一个故障域；v6 用规范化前缀（不同写法归一）
export function prefixOf(ip) {
  const t = String(ip === undefined || ip === null ? '' : ip).trim()
  if (fam(t) === 4) return t.split('.').slice(0, 3).join('.')
  const g = expand6(t)
  return g ? g.slice(0, 4).join(':') : ''
}

// ---------- 段判定 ----------
export function inRange4(ip, cidr) {
  if (fam(ip) !== 4) return false
  const p = String(cidr).split('/')
  const mask = p[1] ? ((~0 << (32 - Number(p[1]))) >>> 0) : 0xffffffff
  return (num4(ip) & mask) === (num4(String(p[0]).trim()) & mask)
}
export function inRange6(ip, cidr) {
  const a = expand6(ip)
  const p = String(cidr).split('/')
  const b = expand6(String(p[0]).trim())
  if (!a || !b) return false
  let bits = Number(p[1] || 128)
  for (let i = 0; i < 8 && bits > 0; i++) {
    const take = Math.min(16, bits)
    const mask = take >= 16 ? 0xffff : ((0xffff << (16 - take)) & 0xffff)
    if ((parseInt(a[i], 16) & mask) !== (parseInt(b[i], 16) & mask)) return false
    bits -= take
  }
  return true
}
// 代理内核（mihomo/Clash）的 fake-ip 段：系统解析落在这里 = DNS 被 TUN dns-hijack 接管，
// hosts 层被架空，工具写到这里的固定必然复核失败——识别出来就整轮跳过。
export const FAKE4_DEFAULT = ['198.18.0.0/16']
export const FAKE6_DEFAULT = ['fdfe:dcba:9876::/64']
export function isFakeIp(ip, ranges4, ranges6) {
  const f = fam(ip)
  if (f === 4) return (ranges4 || FAKE4_DEFAULT).some(function (c) { return inRange4(ip, c) })
  if (f === 6) return (ranges6 || FAKE6_DEFAULT).some(function (c) { return inRange6(ip, c) })
  return false
}
// 公网域名解析到回环/内网/链路本地 = 环境被本地代理或内核接管，这种"解析"不能当泄漏证据
export function isLocalIp(ip) {
  const f = fam(ip)
  if (f === 4) {
    return inRange4(ip, '127.0.0.0/8') || inRange4(ip, '10.0.0.0/8') || inRange4(ip, '172.16.0.0/12') ||
      inRange4(ip, '192.168.0.0/16') || inRange4(ip, '169.254.0.0/16')
  }
  if (f === 6) return inRange6(ip, '::1/128') || inRange6(ip, 'fe80::/10') || inRange6(ip, 'fc00::/7')
  return false
}

// 自测仅在"本文件是入口"时运行（否则会劫持导入者的 --selftest：曾实机踩到
// accel --selftest 被 ip.mjs 的进程级 process.exit 抢跑）
const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
if (isMain && process.argv.includes('--selftest')) {
  let bad = 0
  const T = function (name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want)
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
  }
  // fam：net.isIP 基底（比自写正则严：组数/HE 合法性都拒）
  T('fam v4', fam('20.205.243.166'), 4)
  T('fam v6', fam('2606:50c0:8000::153'), 6)
  T('fam 拒三冒号', fam('2606:50c0:8000:::1'), 0)
  T('fam 拒多段 ::', fam('a::b::c'), 0)
  T('fam 拒 9 组', fam('1:2:3:4:5:6:7:8:9'), 0)
  T('fam 空', fam(''), 0)
  T('fam 带空白可容错', fam(' 104.17.208.5 '), 4)
  // expand6：8 组规范化（去前导零）
  T('expand6 常规', expand6('2606:50c0:8000::153'), ['2606', '50c0', '8000', '0', '0', '0', '0', '153'])
  T('expand6 ::1', expand6('::1'), ['0', '0', '0', '0', '0', '0', '0', '1'])
  T('expand6 非法', expand6('2606:50c0:8000:::1'), null)
  // prefixOf：v4=/24；v6=规范化 /64（前 4 组）——同一 /64 的不同写法必须归一
  T('prefix v4', prefixOf('104.17.208.5'), '104.17.208')
  T('prefix v6', prefixOf('2606:50c0:8000::153'), '2606:50c0:8000:0')
  T('prefix v6 不同 /64 不同前缀', prefixOf('2606:50c0:8001::153'), '2606:50c0:8001:0')
  T('prefix v6 等价写法归一', prefixOf('2606:50c0:8000:0:0:0:0:153'), prefixOf('2606:50c0:8000::153'))
  T('prefix 非法给空串', prefixOf('2606:50c0:8000:::1'), '')
  // 段判定
  T('inRange4 命中', inRange4('198.18.0.30', '198.18.0.0/16'), true)
  T('inRange4 不命中', inRange4('198.19.0.1', '198.18.0.0/16'), false)
  T('inRange6 命中', inRange6('fdfe:dcba:9876::1', 'fdfe:dcba:9876::/64'), true)
  T('inRange6 不命中', inRange6('fdfe:dcba:9877::1', 'fdfe:dcba:9876::/64'), false)
  // fake-ip / 本地段（默认段参数）
  T('isFakeIp 4 命中', isFakeIp('198.18.0.30'), true)
  T('isFakeIp 4 不命中', isFakeIp('198.19.0.1'), false)
  T('isFakeIp 6 命中', isFakeIp('fdfe:dcba:9876::1'), true)
  T('isFakeIp 公网不命中', isFakeIp('20.205.243.166'), false)
  T('isFakeIp 空', isFakeIp(''), false)
  T('isLocalIp 回环', isLocalIp('127.0.0.1'), true)
  T('isLocalIp 私网', isLocalIp('192.168.0.1'), true)
  T('isLocalIp 172.32 不算', isLocalIp('172.32.0.1'), false)
  T('isLocalIp 链路本地 v6', isLocalIp('fe80::1'), true)
  T('isLocalIp 唯一本地 v6', isLocalIp('fc00::1'), true)
  T('isLocalIp 公网不算', isLocalIp('2606:4700::6811:6fb8'), false)
  // num4/str4
  T('num4/str4 往返', str4(num4('104.17.208.5')), '104.17.208.5')
  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测全部通过')
  process.exit(bad ? 1 : 0)
}
