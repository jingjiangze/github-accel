// relay 中间件行为验证：把 globalThis.fetch 打桩，直接驱动跳转链。
// 源文件每次现读现拷到临时目录，避免测试副本与真源漂移，也不往仓库里写东西。
//   node relay/test/middleware.test.mjs
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SRC = path.join(HERE, '..', 'functions', '_middleware.js')
const TMP = path.join(os.tmpdir(), '_mw_' + process.pid + '_' + Date.now() + '.mjs')
fs.writeFileSync(TMP, fs.readFileSync(SRC, 'utf8'))

const KEY = 'test-key-123'
const realFetch = globalThis.fetch
let calls = []
let current = function () { return new Response('unset', { status: 500 }) }
globalThis.fetch = async function (url, opts) {
  calls.push({ url: String(url), opts: opts })
  return current(String(url), opts)
}
const setFetch = function (fn) { current = fn }

const { onRequest } = await import(pathToFileURL(TMP).href)

function req(targetPath, init) {
  return new Request('https://relay.example/r/' + KEY + '/' + targetPath, init)
}
function ctx(request, key) {
  return { request: request, env: { RELAY_KEY: key === undefined ? KEY : key }, next: function () { return new Response('next', { status: 404 }) } }
}
let bad = 0
function T(name, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want)
  if (!ok) bad++
  console.log('  ' + (ok ? 'PASS' : 'FAIL') + '  ' + name + ' = ' + JSON.stringify(got) + (ok ? '' : '，期望 ' + JSON.stringify(want)))
}

// 1. 密钥不对直接 403
setFetch(function () { return new Response('x', { status: 200 }) })
T('错误密钥 403', (await onRequest(ctx(req('https://github.com/a'), 'WRONG'))).status, 403)

// 2. 非白名单域 403（relay 不是开放代理）
T('非白名单域 403', (await onRequest(ctx(req('https://example.com/a')))).status, 403)
T('白名单外未发请求', calls.length, 0)

// 3. 直连 200：Range 透传、Authorization 默认剥离、分片响应头回传、redirect=manual
calls = []
setFetch(function () {
  return new Response('hello', { status: 200, headers: { 'content-type': 'text/plain', 'accept-ranges': 'bytes', 'content-range': 'bytes 0-4/10', etag: 'W/"1"' } })
})
const r3 = await onRequest(ctx(req('https://github.com/a/b', { headers: { range: 'bytes=0-4', 'if-range': 'W/"1"', authorization: 'Bearer secret' } })))
T('直连 200', r3.status, 200)
T('Range 已透传上游', calls[0].opts.headers.get('range'), 'bytes=0-4')
T('If-Range 已透传上游', calls[0].opts.headers.get('if-range'), 'W/"1"')
T('Authorization 默认剥离', calls[0].opts.headers.get('authorization'), null)
T('redirect 用 manual', calls[0].opts.redirect, 'manual')
T('Content-Range 已回传', r3.headers.get('content-range'), 'bytes 0-4/10')
T('Accept-Ranges 已回传', r3.headers.get('accept-ranges'), 'bytes')
T('ETag 已回传', r3.headers.get('etag'), 'W/"1"')
T('正文未损坏', await r3.text(), 'hello')

// 4. release 资产 302 到 release-assets.githubusercontent.com：必须跟随（这是 release 下载的常态）
calls = []
setFetch(function (url) {
  if (url.indexOf('github.com') >= 0) return new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/x' } })
  return new Response('asset', { status: 200 })
})
const r4 = await onRequest(ctx(req('https://github.com/a/b/releases/download/v1/x.zip')))
T('release-assets 跳转被跟随', r4.status, 200)
T('确实走了两跳', calls.length, 2)
T('第二跳也用 manual', calls[1].opts.redirect, 'manual')
T('x-relay-target 为终点域', r4.headers.get('x-relay-target'), 'release-assets.githubusercontent.com')

// 5. 核心 P0：跳到白名单外的域必须被拦，而不是跟着走
calls = []
setFetch(function () { return new Response(null, { status: 302, headers: { location: 'https://evil.example.com/x' } }) })
const r5 = await onRequest(ctx(req('https://github.com/a/b')))
T('跳转到非白名单域 403', r5.status, 403)
T('非白名单只请求了一次', calls.length, 1)

// 6. 相对 Location 要按当前跳解析，而不是拼成畸形 URL
calls = []
setFetch(function (url) {
  if (url.indexOf('/start') >= 0) return new Response(null, { status: 302, headers: { location: '/rel' } })
  return new Response('ok', { status: 200 })
})
await onRequest(ctx(req('https://github.com/start')))
T('相对 Location 解析正确', calls[1].url, 'https://github.com/rel')

// 7. 无限跳转要有上限，不能一直跟
calls = []
setFetch(function () { return new Response(null, { status: 302, headers: { location: 'https://github.com/loop' } }) })
T('超过跳数上限 508', (await onRequest(ctx(req('https://github.com/loop')))).status, 508)

// 8. 3xx 但没有 Location：原样回给客户端，不自己编
setFetch(function () { return new Response('moved', { status: 301 }) })
const r8 = await onRequest(ctx(req('https://github.com/noloc')))
T('无 Location 的 3xx 原样回传', r8.status, 301)

// 9. POST 的 content-type 要透传（git-upload-pack 依赖）
calls = []
setFetch(function () { return new Response('pkt', { status: 200 }) })
await onRequest(ctx(req('https://github.com/a.git/git-upload-pack', { method: 'POST', headers: { 'content-type': 'application/x-git-upload-pack-request' }, body: 'x' })))
T('POST content-type 透传', calls[0].opts.headers.get('content-type'), 'application/x-git-upload-pack-request')

globalThis.fetch = realFetch
try { fs.unlinkSync(TMP) } catch (e) {}
console.log(bad ? '  relay 自测失败 ' + bad + ' 项' : '  relay 自测全部通过')
process.exit(bad ? 1 : 0)
