// probe.mjs —— 探测/复核的判定核心（纯函数；curl 执行留在 accel.mjs 外壳）。
// 2026-10-13 v2 重写：解析与判定从 accel.mjs 里拆出来，让 "code=000 也算生效" 这类事故模式
// （objects 坏钉存活一整天）能被离线用例直接钉死。
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// ---------- 解析（纯） ----------
// curl -w '%{http_code} %{time_total} %{size_download} %{remote_ip}' 的输出
export function parseProbeOut(out) {
  const m = String(out).match(/^(\d+)\s+([\d.]+)\s+(\d+)\s*(\S*)/)
  if (!m) return { code: 0, ms: 0, bytes: 0, rip: '', parsed: false }
  return { code: Number(m[1]), ms: Math.round(Number(m[2]) * 1000), bytes: Number(m[3]), rip: m[4] || '', parsed: true }
}
// curl -w '%{http_code} %{time_total} %{remote_ip}' 的输出（verify 用；code 放最前，空 rip 也不会错位）
export function parseVerifyOut(out) {
  const m = String(out).match(/^(\d+)\s+([\d.]+)\s*(\S*)/)
  if (!m) return { code: 0, ms: 0, rip: '', parsed: false }
  return { code: Number(m[1]), ms: Math.round(Number(m[2]) * 1000), rip: m[3] || '', parsed: true }
}

// ---------- 判定（纯） ----------
// 单次探测判定：响应码在允许集 + 字节数下限 + 可选时延上限
export function judgeProbe(pr, policy) {
  const allow = (policy && policy.allow) || [200, 301, 302, 404]
  const minBytes = (policy && policy.minBytes) || 1
  const maxMs = (policy && policy.maxMs) || 0
  const ok = allow.indexOf(pr.code) >= 0 && pr.bytes >= minBytes && (!maxMs || pr.ms <= maxMs)
  return { ok: ok, code: pr.code, ms: pr.ms, bytes: pr.bytes, rip: pr.rip }
}
// 多次采样归纳：strict=每一轮都过才算（取最慢计时，防抖动 IP 侥幸）；非 strict=任一过取最快
export function summarizeProbes(list, strict) {
  const good = list.filter(function (r) { return r.ok })
  if (!good.length) return { ok: false, ms: 1e9, code: (list[list.length - 1] || {}).code || 0, bytes: 0, tries: list.length }
  const times = good.map(function (r) { return r.ms })
  return {
    ok: strict ? good.length === list.length : true,
    ms: strict ? Math.max.apply(null, times) : Math.min.apply(null, times),
    code: good[0].code, bytes: good[0].bytes, tries: list.length
  }
}
// 整链复核判定：fake/本地接管 → inactive（不能据此撤销）；无响应（含 code=000）→ noresp；
// 落点不在 expect → leak；响应码不在允许集 → codefail；否则 ok。
export function judgeVerify(v, ctx) {
  const rip = v.rip
  if (rip && ((ctx.isFake && ctx.isFake(rip)) || (ctx.isLocal && ctx.isLocal(rip)))) {
    return { kind: 'inactive', code: v.code, ms: v.ms, rip: rip, detail: '连到 ' + rip + '（fake-ip/本地代理接管），本轮不复核，保留现有固定' }
  }
  if (!rip || !v.parsed || v.code === 0) {
    return { kind: 'noresp', code: v.code, ms: v.ms, rip: rip, detail: '连接失败 ' + (v.parsed ? v.code : '000') + (rip ? '（连到 ' + rip + ' 但无响应）' : '') }
  }
  if (ctx.expect.indexOf(rip) < 0) {
    return { kind: 'leak', code: v.code, ms: v.ms, rip: rip, detail: '泄漏到未钉的 ' + rip + '（写入的是 ' + ctx.expect.join('/') + '）' }
  }
  if (ctx.allow.indexOf(v.code) < 0) {
    return { kind: 'codefail', code: v.code, ms: v.ms, rip: rip, detail: rip + ' 响应码 ' + v.code + '（' + v.ms + 'ms）不在允许集 ' + ctx.allow.join('/') + '，落地不成立' }
  }
  return { kind: 'ok', code: v.code, ms: v.ms, rip: rip, detail: rip + ' ' + v.code + ' ' + v.ms + 'ms' }
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
  // parseProbeOut：curl -w '%{http_code} %{time_total} %{size_download} %{remote_ip}'
  T('probe 解析常规', parseProbeOut('404 0.1819 1234 2606:50c0:8000::153'), { code: 404, ms: 182, bytes: 1234, rip: '2606:50c0:8000::153', parsed: true })
  T('probe 解析超时(000,rip 空)', parseProbeOut('000 15.002 0 '), { code: 0, ms: 15002, bytes: 0, rip: '', parsed: true })
  T('probe 解析垃圾', parseProbeOut(''), { code: 0, ms: 0, bytes: 0, rip: '', parsed: false })
  // judgeProbe：允许码 + 字节下限 + 时延上限
  const pol = { allow: [200, 404], minBytes: 1, maxMs: 4000 }
  T('judge 允许码过', judgeProbe({ code: 404, ms: 100, bytes: 10 }, pol).ok, true)
  T('judge code=000 不过', judgeProbe({ code: 0, ms: 100, bytes: 0 }, pol).ok, false)
  T('judge 不在允许集不过', judgeProbe({ code: 503, ms: 100, bytes: 10 }, pol).ok, false)
  T('judge 字节不足不过', judgeProbe({ code: 200, ms: 100, bytes: 0 }, { allow: [200], minBytes: 8192 }, false).ok, false)
  T('judge 超时延不过', judgeProbe({ code: 200, ms: 8026, bytes: 10 }, pol).ok, false)
  // summarizeProbes：strict=全过取最慢；非 strict=任一过取最快
  const P = function (code, ms) { return { code: code, ms: ms, bytes: 10, ok: code === 200 } }
  T('strict 3 连全过', summarizeProbes([P(200, 100), P(200, 200), P(200, 150)], true).ok, true)
  T('strict 取最慢', summarizeProbes([P(200, 100), P(200, 200), P(200, 150)], true).ms, 200)
  T('strict 一败即败', summarizeProbes([P(200, 100), P(0, 1), P(200, 150)], true).ok, false)
  T('非 strict 从宽', summarizeProbes([P(0, 1), P(200, 300)], false).ok, true)
  T('非 strict 取最快', summarizeProbes([P(0, 1), P(200, 300)], false).ms, 300)
  T('全败给 1e9', summarizeProbes([P(0, 1), P(0, 2)], true).ms, 1e9)
  // parseVerifyOut：curl -w '%{http_code} %{time_total} %{remote_ip}'
  T('verify 解析常规', parseVerifyOut('404 0.189 2606:50c0:8001::153'), { code: 404, ms: 189, rip: '2606:50c0:8001::153', parsed: true })
  T('verify 解析 000 空 rip', parseVerifyOut('000 15.002 '), { code: 0, ms: 15002, rip: '', parsed: true })
  T('verify 解析垃圾', parseVerifyOut(''), { code: 0, ms: 0, rip: '', parsed: false })
  // judgeVerify：整链判定（本组用例就是对 10-12 事故的直接回归）
  const ctx = {
    expect: ['20.27.177.113', '2606:50c0:8001::153'],
    allow: [200, 301, 302, 404],
    isFake: function (ip) { return ip === '198.18.0.30' },
    isLocal: function (ip) { return ip === '127.0.0.1' }
  }
  T('judge verify 正常生效', judgeVerify(parseVerifyOut('200 0.44 20.27.177.113'), ctx).kind, 'ok')
  T('judge verify code=000(事故回归)', judgeVerify(parseVerifyOut('000 15.002 185.199.108.133'), { expect: ['185.199.108.133'], allow: [404], isFake: ctx.isFake, isLocal: ctx.isLocal }).kind, 'noresp')
  T('judge verify 泄漏', judgeVerify(parseVerifyOut('200 0.3 1.1.1.1'), ctx).kind, 'leak')
  T('judge verify 响应码不成立', judgeVerify(parseVerifyOut('503 0.3 20.27.177.113'), ctx).kind, 'codefail')
  T('judge verify fake 让路', judgeVerify(parseVerifyOut('200 0.3 198.18.0.30'), ctx).kind, 'inactive')
  T('judge verify 本地让路', judgeVerify(parseVerifyOut('200 0.3 127.0.0.1'), ctx).kind, 'inactive')
  T('judge verify 404 允许集内', judgeVerify(parseVerifyOut('404 0.19 2606:50c0:8001::153'), ctx).kind, 'ok')
  console.log(bad ? '  自测失败 ' + bad + ' 项' : '  自测全部通过')
  process.exit(bad ? 1 : 0)
}
