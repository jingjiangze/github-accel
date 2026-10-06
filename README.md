# accel —— 本机实测选路的 GitHub 加速层（hosts + 反代）

面向 Windows（Git Bash / PowerShell 皆可），**不需要管理员权限**。两层互补，各自解决实测确认不同的故障面：

| 层 | 文件 | 解决什么 |
|---|---|---|
| A 自适应 hosts | `accel.mjs` | 头像、raw、归档包、npm/jsDelivr 等**能靠 IP 救**的通道：候选 IP 逐条本机 TLS 实测，只有确实更快才写入 |
| B 反代选路 | `gh.mjs` | `github.com` 主页首跳、release 下载、`git clone` 这类**换 IP 无效**的通道：按实测带宽挑入口，失败自动换源 |

设计取向是**宁可不写，也不写坏**：写错的 hosts 条目比不写更糟（浏览器全站受影响），所以每条固定都要过"多轮实测 + 写入后真实解析复核"，复核不过当场撤销。

## 快速开始

```bat
:: 1. 手动跑一轮，先看判定不动文件
node accel.mjs --dry -v

:: 2. 正式写入（自动备份原 hosts，只替换标记块）
node accel.mjs

:: 3. 装每 10 分钟一轮的无窗口计划任务（免提权）
powershell -NoProfile -ExecutionPolicy Bypass -File install-task.ps1

:: 下载 release / 源码包
node gh.mjs https://github.com/git-lfs/git-lfs/releases/download/v3.6.1/git-lfs-windows-amd64-v3.6.1.zip

:: 克隆（直连 clone 在这类线路上普遍失败）
node gh.mjs clone --depth 1 https://github.com/octocat/Hello-World.git

:: 回滚
node accel.mjs --revert
schtasks /delete /tn QoderAccel /f
```

## 为什么不做成"直接改 hosts 就完事"的加速器

这些是本仓库所有判定的来源，都是**同一台机器同一时段**的实测数字，不是转述：

1. **社区列表的"最快 IP"是境外 Runner 测的**。GitHub520 给的 4 个关键条目在本线路 0/4 可用（`20.205.243.166` 主页拿到 200 后 body 卡死、`185.199.111.133` 对 objects 直接失败、`59.24.3.173` 对 gist 失败）。同一个列表换一条线路结论就变，所以候选只当作"待测集合"。
2. **干扰针对 `github.com` 这条业务本身，与 IP 无关**。同一台主机 `20.205.243.165` 上只换 SNI：`codeload.github.com` → 301 正常，`github.com` → TLS 完成后不回 body。所以主页 / release 首跳 / `git clone` 无法靠固定 IP 修，必须走反代。
3. **只写 IPv4 的 hosts 会被 AAAA 抢先**。给 `raw.githubusercontent.com` 固定 IPv4 后，真实请求仍走 `2606:50c0:8003::154` 并超时。本工具因此对候选同时探 A/AAAA 记录，两族都实测可用才写，否则跳过。
4. **反代入口需要内容级体检**。仅看 HTTP 200 会把自建拦截页当"通"（某入口对 2.4KB 样本回 200 但只有 543 字节的错误页，另一入口小文件正常、5MB 样本直接断流）。`gh.mjs doctor` 用固定内容标记 + 大文件带宽样本两级判定，并按 MB/s 排序选路。

## 用法与配置

`config.json` 的关键项：

- `sources`：候选 IP 列表源，jsDelivr 优先、`raw.githubusercontent.com` 兜底（实测后者会间歇 5xx/超时）。
- `domains`：每个域名的探测路径 `canary`、可接受状态码 `expect`、`strict`（多轮必须全通过）。`github.com` 必须 `strict`。
- `probe.win_ratio`：比现状快多少才写入（默认 0.85，即至少快 15%）。
- `probe.retries` / `budget_ms`：每 IP 探测轮数与单轮上限。
- `deny`：永不固定的域名。
- `proxies`：反代入口清单，`gh.mjs doctor --force` 重新体检。

产物：`logs/`（每轮判定）、`report.json`（逐域明细，含每个 IP 的实测毫秒）、`backups/`（原 hosts，保留 5 份）、`proxy-state.json`（入口缓存 15 分钟）。

## 安全边界

- 公开反代会看到你要下载的完整地址并透传请求头。`gh.mjs` 对疑似带凭据的输入（`oauth2:`、`ghp_*`、`github_pat_*`、URL 内嵌账密）**直接拒绝外送**，私有仓库请自建反代或走代理节点。
- hosts 只替换 `# >>> accel-start >>> ... # <<< accel-end <<<` 标记块，其余行原样保留；每轮先备份。
- Clash/mihomo 的 TUN 或系统代理任一开启后，内核不读系统 hosts（`use-system-hosts: false`），A 层会被架空——此时应把 GitHub 域名规则改为直连组，或只依赖 B 层。

## 私有中转端点（`relay/`，可选）

公开反代看得到你要下载的完整 URL，还会透传请求头。`relay/` 是自带的 Cloudflare Pages Functions
端点，用来把这层暴露收回去：

- 路径 `/r/<密钥>/https://github.com/...`；密钥用定长比较，不匹配直接 403；
- **域名白名单**只放行 GitHub 相关 host，`example.com` 之类一律 403 —— 它不是开放代理；
- 默认剥离客户端的 `Authorization` / `Cookie`（只有显式设 `RELAY_ALLOW_AUTH=1` 才透传）；
- 不做 `api.github.com` 中转：CF 出口 IP 访问 api 一律 403（GitHub 拉黑 CF 段），这是实测结论。

部署（需要自己的 CF 账号，全程可删）：

```bat
cd relay
npx wrangler pages project create gh-accel-relay --production-branch main
npx wrangler pages deploy --branch main
```

`RELAY_KEY` 以 secret 形式写进 Pages 环境变量，本地副本放 `relay-key`（已 gitignore，
仓库是公开的，密钥不入库）。配好后 `config.json` 的 `relay.base` 指向
`https://<项目名>.pages.dev/r/KEY/`，`gh.mjs` 会自动把它插到候选入口最前面参与测速排序。

**坑（踩过的）**：Pages 的 `functions/` 必须在**项目根**（和 `wrangler.toml` 同级）。把它放进部署目录
`public/` 里时，wrangler 会静默打印 `No Functions. Shimming...`，所有请求直接返回静态页——
密钥闸门形同虚设。本仓库的结构是 `relay/wrangler.toml` + `relay/functions/` + `relay/public/`。

## 参考

- [creazyboyone/FastGithub](https://github.com/creazyboyone/FastGithub) —— "加速器式"本地加速的形态参照（改 hosts / 本地反代一体化）。本项目是零依赖脚本层，不常驻进程、不改系统证书。
- [ittuann/GitHub-IP-hosts](https://github.com/ittuann/GitHub-IP-hosts) —— 候选 IP 列表源之一，本仓库将其与 GitHub520 互为候选源。
- [521xueweihan/GitHub520](https://github.com/521xueweihan/GitHub520) —— 候选 IP 列表源之二。
- [hunshcn/gh-proxy](https://github.com/hunshcn/gh-proxy) —— 反代入口的自建方案（Cloudflare Workers），需要私有入口时用它。

以上游项目的文档/数据改进，均以 PR 形式提交并等待审查，不在本地改动别人的项目。

## License

MIT
