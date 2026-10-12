// bench.mjs —— 内存/资源自查（本机最小服务约束的验收工具）
//
//   node bench.mjs            跑一轮 accel + gh doctor，各自打印内存峰值（MB）
//   node bench.mjs --check    同上，但超过预算即退出码非 0（供计划任务/CI 用）
//
// 为什么单独有这个：本机约束是「最小服务、内存不能超过百兆」。工具是计划任务短跑（无常驻），
// 所以唯一需要守住的数字就是**单轮进程内存峰值**。这里量 maxRSS（Windows=PeakWorkingSet），
// 比 heapUsed 全——本工具大量用 Buffer 存 curl 输出，只看堆会严重低估。
import fs from 'node:fs'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ARGV = process.argv.slice(2)
const CHECK = ARGV.includes('--check')
// 预算（MB）：单轮进程内存峰值。实测 2026-10-13：accel 52.5 / gh doctor 47.6，
// 留一倍余量；这个数字是"超了就是回归"的告警线，不是优化目标。
const BUDGET_MB = 100
const runOnce = function (rel, args, timeoutMs) {
  return new Promise(function (resolve) {
    // 内存探针：写成临时 wrapper 再跑（node -e 与文件参数混用时 -e 代码不会 import 目标文件，
    // 这是 2026-10-13 实测踩到的坑——探针必须放在 wrapper 里，由 wrapper 去 import 被测脚本）
    const wrap = 'process.on("exit",function(){var u=process.resourceUsage();console.log("__PEAK_RSS_MB__="+(u.maxRSS/1024).toFixed(1))});'
      + 'await import(' + JSON.stringify('file:///' + path.join(HERE, rel).replace(/\\/g, '/')) + ');'
    const tmp = path.join(HERE, '_bench-probe-' + rel.replace(/\.mjs$/, '') + '.mjs')
    fs.writeFileSync(tmp, wrap)
    execFile(process.execPath, [tmp].concat(args || []),
      { maxBuffer: 32 * 1024 * 1024, windowsHide: true, timeout: timeoutMs || 300000, encoding: 'utf8' },
      function (err, out) {
        try { fs.unlinkSync(tmp) } catch (e) {}
        const m = String(out).match(/__PEAK_RSS_MB__=([\d.]+)/)
        const peak = m ? Number(m[1]) : -1
        const last = String(out).split(/\r?\n/).filter(Boolean).slice(-1)[0] || ''
        resolve({ rel: rel, peak: peak, line: last, code: err ? 1 : 0 })
      })
  })
}
const report = async function () {
  console.log('资源自查 @ ' + new Date().toLocaleString() + '  预算 ' + BUDGET_MB + ' MB/进程')
  const jobs = [
    { rel: 'accel.mjs', args: [], ms: 600000, label: 'A 层选路 + 落地复核' },
    { rel: 'gh.mjs', args: ['doctor', '--force'], ms: 600000, label: 'B 层入口体检' }
  ]
  let over = 0
  for (const j of jobs) {
    const r = await runOnce(j.rel, j.args, j.ms)
    const ok = r.peak > 0 && r.peak < BUDGET_MB
    if (!ok) over++
    console.log('  ' + (ok ? 'OK  ' : 'OVER') + ' ' + j.rel.padEnd(12) + '峰值 ' +
      r.peak.toFixed(1).padStart(5) + ' MB   ' + j.label + (r.peak < 0 ? '（探针未取到）' : ''))
    if (r.line) console.log('        ' + r.line)
  }
  // 最小服务形态自查：运行期数据不应无限膨胀（常驻的替代物）
  const files = ['candidates.json', 'pool-state.json', 'report.json', 'proxy-state.json', 'meta-cache.json']
  console.log('  运行期文件体积：')
  for (const f of files) {
    try { console.log('        ' + f.padEnd(22) + (fs.statSync(path.join(HERE, f)).size / 1024).toFixed(1) + ' KB') }
    catch (e) { console.log('        ' + f.padEnd(22) + '（无）') }
  }
  console.log(over ? '  超预算 ' + over + ' 项' : '  全部低于预算')
  return over
}
const n = await report()
if (CHECK && n) process.exit(2)
process.exit(0)
