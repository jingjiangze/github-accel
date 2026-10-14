// clash.mjs —— 侦测本机 Clash(mihomo) 状态（**只读**，绝不改 Clash 配置）
//
// 2026-10-13：用户要求「hosts 侦测到 Clash 后自适应」。本模块负责"侦测"这一半：
// 通过 mihomo 的命名管道(external-controller-pipe)读运行状态与当前出口节点，
// 供 accel 在报告里记录、并据此判断 hosts 钉是否会被 Clash 绕过。
//
// 实测要点（勿重复踩）：
//  - mihomo 的 TCP 控制器常被关掉(external-controller: '')，只有命名管道可用；
//    管道名形如 \\.\pipe\verge-mihomo-<release|production>-<hash>，重启后 hash 不变但前缀可能变 → 必须枚举。
//  - 管道名不要从 config.yaml 读（那是生成时的旧名，实测已过期：配置写 sidecar-release-*，实际是 production-*）。
//  - /proxies 出于安全**不返回节点 server**（只有 name/type/history 等），所以"读节点 IP"必须靠订阅文件解析，不可靠 → 不做。
//  - 用 node:http 的 socketPath 直连管道最稳（PowerShell 的 NamedPipeClientStream 会阻塞且编码坑多）。
import fs from 'node:fs'
import http from 'node:http'

const GROUP_TYPES = ['Selector', 'URLTest', 'Fallback', 'LoadBalance', 'Relay']

// ---------- 纯函数（可离线自测） ----------
// 从某个组出发，跟随 now 直到叶子节点（防御环）
export function followChain(proxies, start, maxHops) {
  const chain = []
  let cur = start
  const limit = maxHops || 8
  for (let i = 0; i < limit && cur; i++) {
    const g = proxies[cur]
    if (!g) break
    const isGroup = GROUP_TYPES.indexOf(g.type) >= 0
    chain.push({ name: cur, type: g.type, now: isGroup ? g.now : undefined })
    if (!isGroup) break
    cur = g.now
  }
  return chain
}
// 从链里取出"终点是不是真节点"（终点是 DIRECT/REJECT 或组类型则不算节点）
export function chainEnd(chain) {
  if (!chain || !chain.length) return { kind: 'none', name: null }
  const last = chain[chain.length - 1]
  if (last.name === 'DIRECT' || last.name === 'REJECT') return { kind: last.name, name: last.name }
  if (GROUP_TYPES.indexOf(last.type) >= 0) return { kind: 'group', name: last.name }
  return { kind: 'node', name: last.name }
}
// 汇总一份可读状态
// github 家族实际走的策略组名（按优先级探测）。
// 2026-10-14 修正：原先只硬编码 'GH直连优先'——那是 2026-10-13 试过并已回滚的组名
// （见 README「尝试过并已回滚」），真实配置里根本不存在（184 个代理条目 0 命中），
// 导致下面 githubDirect 恒为 null、accel 里对应的提示分支永不触发（死代码）。
// 现改为：优先用订阅自带的 '🐙 GitHub'（本机 edgetunnel 订阅实测存在），
// 再回退到历史组名，保证两种配置都能侦测到。
const GITHUB_GROUP_NAMES = ['🐙 GitHub', 'GH直连优先']
function findGithubGroup(proxies) {
  if (!proxies) return null
  for (const name of GITHUB_GROUP_NAMES) {
    if (proxies[name]) return { name: name, group: proxies[name] }
  }
  // 兜底：名字里带 github 的组（订阅可能改名）
  for (const k of Object.keys(proxies)) {
    if (/github/i.test(k)) return { name: k, group: proxies[k] }
  }
  return null
}
export function summarize(configs, proxies, startGroup) {
  const chain = followChain(proxies || {}, startGroup || '🚀 节点选择')
  const end = chainEnd(chain)
  const gh = findGithubGroup(proxies)
  return {
    mode: (configs && configs.mode) || null,
    tun: !!(configs && configs.tun && configs.tun.enable),
    mixedPort: (configs && configs['mixed-port']) || null,
    chain: chain,
    end: end,
    // 我们钉的域会不会被 Clash 丢给节点：终点是 node 就是"会"（hosts 钉对走代理的应用无效）
    viaNode: end.kind === 'node',
    // github 家族由哪个策略组接管、当前选中什么（无该组则为 null）
    githubDirect: gh ? { name: gh.name, now: gh.group.now, type: gh.group.type } : null
  }
}

// ---------- IO ----------
export function findPipes() {
  const out = []
  try {
    for (const p of fs.readdirSync('\\\\.\\pipe\\')) if (/^verge-mihomo-/.test(p)) out.push('\\\\.\\pipe\\' + p)
  } catch (e) {}
  return out
}
function apiGet(pipe, p) {
  return new Promise(function (resolve) {
    const req = http.request({ socketPath: pipe, path: p, method: 'GET', timeout: 4000 }, function (res) {
      let b = ''
      res.setEncoding('utf8')
      res.on('data', function (c) { b += c })
      res.on('end', function () { resolve({ code: res.statusCode, body: b }) })
    })
    req.on('error', function (e) { resolve({ code: 0, err: e.code || e.message }) })
    req.on('timeout', function () { req.destroy(); resolve({ code: 0, err: 'timeout' }) })
    req.end()
  })
}
// 读一次完整状态；Clash 没跑/管道读不到 → { up:false }
export async function readState(startGroup) {
  const pipes = findPipes()
  for (const pipe of pipes) {
    const v = await apiGet(pipe, '/version')
    if (v.code !== 200) continue
    let version = ''
    try { version = JSON.parse(v.body).version || '' } catch (e) {}
    const c = await apiGet(pipe, '/configs')
    const x = await apiGet(pipe, '/proxies')
    let configs = null, proxies = null
    try { configs = JSON.parse(c.body) } catch (e) {}
    try { proxies = JSON.parse(x.body) } catch (e) {}
    if (!configs || !proxies) continue
    const s = summarize(configs, proxies.proxies, startGroup)
    return Object.assign({ up: true, pipe: pipe, version: version }, s)
  }
  return { up: false }
}
// 给一行日志用的短描述
export function describe(state) {
  if (!state || !state.up) return '未运行'
  const e = state.end || {}
  const tgt = e.kind === 'node' ? ('出口节点 ' + e.name) : (e.kind === 'DIRECT' ? '直连' : e.kind)
  return '运行中（mode=' + state.mode + '，tun=' + (state.tun ? 'on' : 'off') + '，' + tgt + '）'
}

const isMain = process.argv[1] && process.argv[1].replace(/\\/g, '/').endsWith('/clash.mjs')
if (isMain && process.argv.includes('--selftest')) {
  let bad = 0
  const T = function (name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want)
    if (!ok) bad++
    console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
  }
  const P = {
    '🚀 节点选择': { type: 'Selector', now: '♻️ 自动选择' },
    '♻️ 自动选择': { type: 'URLTest', now: '优选-136' },
    '优选-136': { type: 'Vless', server: 'x' },
    '直连组': { type: 'Fallback', now: 'DIRECT' },
    'DIRECT': { type: 'Direct' },
    '环A': { type: 'Selector', now: '环B' },
    '环B': { type: 'Selector', now: '环A' }
  }
  T('跟随链到节点', followChain(P, '🚀 节点选择').map(function (x) { return x.name }), ['🚀 节点选择', '♻️ 自动选择', '优选-136'])
  T('终点是节点', chainEnd(followChain(P, '🚀 节点选择')), { kind: 'node', name: '优选-136' })
  T('终点是直连', chainEnd(followChain(P, '直连组')), { kind: 'DIRECT', name: 'DIRECT' })
  T('防环', followChain(P, '环A').length <= 8, true)
  T('未知组', followChain(P, '不存在'), [])
  const s = summarize({ mode: 'rule', tun: { enable: false }, 'mixed-port': 7897 }, P, '🚀 节点选择')
  T('汇总 mode', s.mode, 'rule')
  T('汇总 viaNode', s.viaNode, true)
  T('汇总 直连组不算节点', summarize({ mode: 'rule' }, P, '直连组').viaNode, false)

  // github 策略组侦测（2026-10-14 修：原先硬编码 'GH直连优先'，真实配置里不存在 → 恒 null）
  const PG = Object.assign({}, P, {
    '🐙 GitHub': { type: 'URLTest', now: 'DIRECT' },
    'GH直连优先': { type: 'Fallback', now: 'DIRECT' }
  })
  T('侦测到订阅自带 github 组', summarize({}, PG, '🚀 节点选择').githubDirect,
    { name: '🐙 GitHub', now: 'DIRECT', type: 'URLTest' })
  // 只有历史组名时也要能侦测（回退）
  T('回退到 GH直连优先', summarize({}, Object.assign({}, P, { 'GH直连优先': { type: 'Fallback', now: 'DIRECT' } }), '🚀 节点选择').githubDirect,
    { name: 'GH直连优先', now: 'DIRECT', type: 'Fallback' })
  // 改名兜底
  T('改名兜底 github-ish', summarize({}, Object.assign({}, P, { 'my-github-proxy': { type: 'Selector', now: 'DIRECT' } }), '🚀 节点选择').githubDirect,
    { name: 'my-github-proxy', now: 'DIRECT', type: 'Selector' })
  // 完全没有 → null（不是崩）
  T('无 github 组则为 null', summarize({}, P, '🚀 节点选择').githubDirect, null)

  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测全部通过')
  process.exit(bad ? 1 : 0)
}
