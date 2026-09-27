# miniProxy-plus

一个轻量级 PHP Web 代理，在 [miniProxy](https://github.com/joshdick/miniProxy) 基础上
增加了 **现代网页适配**与可选的 **CAP 人机验证闸门**，用于防止代理被匿名滥用。

原始文件 `miniproxy.php` 在两个分支上均**未做任何修改**，作为回退依据完整保留。
所有改造都在新增的入口副本上进行。

---

## 一、三个文件，按需选择

| 文件 | 分支 | 人机验证 | 现代网页适配 | 适合谁 |
|---|---|---|---|---|
| `miniproxy.php` | 两分支共有 | ✗ | ✗ | 内网自用、已有限流、需要最简部署 |
| `miniproxy-plus.php` | `main` | ✗ | ✓ | 公网部署、需要兼容现代站点 |
| `miniproxy_captcha.php` | `feat/captcha-gate` | ✓ | ✓ | 公网部署、既要防刷又要兼容现代站点 |

```
main 分支                              feat/captcha-gate 分支
├─ miniproxy.php        ← 未改动        ├─ miniproxy.php          ← 未改动
├─ miniproxy-plus.php   ← 现代适配      ├─ miniproxy_captcha.php  ← 闸门 + 现代适配
└─ test_modern.php                       ├─ captcha/
                                           │  ├─ gate.php          闸门核心库
                                           │  ├─ config.php        集中配置
                                           │  ├─ verify.php        独立验证页
                                           │  ├─ callback.php      token 服务端校验
                                           │  ├─ test_gate.php     闸门单元测试
                                           │  └─ README.md         详细部署说明
                                           └─ test_modern.php
```

`miniproxy-plus.php` 与 `miniproxy_captcha.php` 自 `START CONFIGURATION` 起的代理逻辑
**逐字节一致**（MD5 同为 `b5ff664f06af264a76ae4a59871f9378`），两者不会因重复修改而分叉。

---

## 二、现代网页适配修了什么

不是凭空加功能，而是用两个现代代理的入口分别抓真实站点，把问题一个个测出来再修。
以下 6 个缺陷均经实测确认：

### 1. `proxifySrcset()` 致命错误（500）

```php
// 原版
$components = array_map("trim", str_split($source, strrpos($source, " ")));
```

`srcset` 条目的描述符是可选的，没有空格时 `strrpos()` 返回 `false`，
`str_split()` 直接抛致命错误。**访问 wikipedia.org 会得到 500**。

改为按逗号切分后单独解析描述符，并正确处理含逗号的 `data:` URI。

### 2. CSP 透传，页面被浏览器拦死

`Content-Security-Policy` 原样转发，但其中的 `default-src 'self'`、`worker-src 'self'`
指向的是**真实源站**，不是代理。结果是代理页自身的脚本、样式、字体、AJAX 全部被拦。

### 3. HSTS 泄漏

`Strict-Transport-Security` 透传会把真实源站钉死为 HTTPS，并影响通过代理访问的
其他子域。

### 4. 响应头黑名单只剥 3 项

原版只剥离 `Content-Length` / `Transfer-Encoding` / `Content-Encoding`。
现补充：

- `Content-Security-Policy`（含 `-Report-Only`）
- `Strict-Transport-Security`
- `Cross-Origin-Embedder-Policy` / `-Opener-Policy` / `-Resource-Policy`
- `Alt-Svc`（会通告 HTTP/3 端点，绕过代理）
- `Reporting-Endpoints` / `Report-To`
- `Permissions-Policy` / `Feature-Policy`
- `X-Frame-Options`

### 5. 现代属性完全没处理

只重写 `href` / `src`。现补充：

- `data-src`、`data-srcset`、`data-lazy-src`、`data-original`、`data-image`、
  `data-poster`、`data-bg`、`data-url`、`data-href` 等懒加载属性
- `srcset` / `imagesrcset` 从仅 `<img>` 扩展到所有元素
- 移除 `integrity`（SRI 哈希与代理源不匹配会被浏览器拦）
- 移除 `nonce`（CSP 已被剥离，留着反而让内联脚本失败）
- 中和 `<base href>`（否则所有相对 URL 都解析到真实源站）
- **绝对 URL 也强制走代理**：原版 `rel2abs()` 对绝对 URL 原样返回，
  导致 `href="https://evil.com"` 会让浏览器直接离开代理

### 6. 客户端只 patch 了 XMLHttpRequest

现代站点早就不用 XHR 了。现补充：

- `window.fetch`（含 `Request` 对象形态）
- `navigator.sendBeacon`
- `window.open`
- `blob:` / `data:` / `about:` 等协议直连的例外

### 另外三项健壮性修复

- PHP 8.2+ 的 `mb_convert_encoding(..., "HTML-ENTITIES", ...)` 废弃警告，
  改为转 UTF-8 后 `mb_encode_numericentity()`，渲染结果等价
- 关闭 `display_errors`，避免 PHP 警告/弃用提示混进代理 HTML 破坏页面
- cURL 增加连接与总超时（10s / 30s），避免慢站点拖到 `max_execution_time` 返回裸 500

---

## 三、环境要求

| 项目 | 要求 |
|---|---|
| PHP | `miniproxy.php` ≥ 5.4.7；两个新版入口 ≥ 5.6（用到 `hash_equals`） |
| 扩展 | `curl`、`mbstring`、`xml` 三者必装 |
| Session | 仅 `feat/captcha-gate` 分支需要 PHP Session 可写 |
| 网络 | 仅 `feat/captcha-gate` 分支需出站可访问 `captcha.api.968111.xyz` |

检查命令：

```bash
php -v
php -m | grep -Ei 'curl|mbstring|xml'
```

---

## 四、部署 `miniproxy-plus.php`（main 分支）

```bash
git clone https://github.com/Johnsheng1/miniproxy-plus.git
cd miniproxy-plus && git checkout main
```

1. 上传 `miniproxy-plus.php` 到站点目录；
2. 浏览器访问 `https://你的域名/miniproxy-plus.php`，看到代理首页即成功；
3. 按需修改文件顶部 `/*** START CONFIGURATION ***/` 区域的配置项。

### 配置项（与原版完全一致）

| 变量 | 默认 | 说明 |
|---|---|---|
| `$whitelistPatterns` | `[]` | 允许代理的 URL 正则白名单，空数组 = 允许任意 URL |
| `$blacklistPatterns` | `[]` | 禁止代理的 URL 正则黑名单 |
| `$forceCORS` | `true` | 给被代理站点输出 CORS 头 |
| `$disallowLocal` | `true` | 禁止代理内网地址（防 SSRF，**别关**） |
| `$anonymize` | `true` | 不透传客户端 IP 给上游（`X-Forwarded-For`） |
| `$startURL` | `""` | 直接访问时的默认代理目标，留空则显示首页 |
| `$landingExampleURL` | `"https://google.com"` | 首页表单里的示例 URL |

用法：在 URL 后拼上要代理的地址。

```
https://你的域名/miniproxy-plus.php?https://example.com
```

---

## 五、部署 `miniproxy_captcha.php`（feat/captcha-gate 分支）

### 1. 取代码

```bash
git clone https://github.com/Johnsheng1/miniproxy-plus.git
cd miniproxy-plus && git checkout feat/captcha-gate
```

### 2. 上传文件，保持目录结构

`captcha/` 必须与入口副本**同级**（代码通过 `__DIR__` 定位，不可拆分）：

```
站点根目录/
├─ miniproxy.php            ← 原文件，可不上传
├─ miniproxy_captcha.php    ← 新入口
└─ captcha/
   ├─ config.php
   ├─ gate.php
   ├─ verify.php
   ├─ callback.php
   └─ test_gate.php         ← 可不上传，仅本地测试用
```

### 3. 配置 CA 根证书（最容易踩的坑）

PHP 的 curl 若找不到 CA bundle，请求 CAP API 会失败，表现为**永远验证不过**。

```bash
php -r 'var_dump(ini_get("curl.cainfo"));'
```

若输出空字符串，在 `php.ini` 中补两行并重启 PHP：

```ini
; Linux
curl.cainfo = "/etc/ssl/certs/ca-certificates.crt"
openssl.cafile = "/etc/ssl/certs/ca-certificates.crt"

; Windows 需先从 https://curl.se/ca/cacert.pem 下载后指定路径
curl.cainfo = "C:/php/extras/ssl/cacert.pem"
openssl.cafile = "C:/php/extras/ssl/cacert.pem"
```

### 4. 确定对外入口（必做）

`/miniproxy.php` **不在闸门保护范围内**，直接暴露等于没装验证。二选一：

**方式 A**：改用新地址作为对外入口

```
https://你的域名/miniproxy_captcha.php?https://example.com
```

**方式 B**：保持原 URL，用 Web Server 重写（推荐）

Nginx：

```nginx
location = /miniproxy.php {
    rewrite ^ /miniproxy_captcha.php last;
}
```

Apache `.htaccess`：

```apache
RewriteEngine On
RewriteRule ^miniproxy\.php$ /miniproxy_captcha.php [L]
```

两种方式都**不需要修改 PHP 原文件**。若同时保留原文件可访问，建议用 Nginx 直接挡掉：

```nginx
location = /miniproxy.php { return 404; }
```

### 5. 按站点情况调整配置

编辑 `captcha/config.php`：

| 配置项 | 默认 | 何时改 |
|---|---|---|
| `CAPTCHA_FORCE_HTTPS` | `false` | **站点上了 HTTPS 就改 `true`**，否则验证 token 可能被抓包重放 |
| `CAPTCHA_VERIFIED_TTL` | `1800` | 验证通过后的有效期（秒），0.5 小时 |
| `CAPTCHA_FAILURE_LIMIT` | `5` | 多少分钟内允许失败几次 |
| `CAPTCHA_FAILURE_WINDOW` | `300` | 失败计数的时间窗口（秒） |
| `CAPTCHA_IP_REQUEST_LIMIT` | `30` | 单 IP 在窗口内的最大提交次数 |
| `CAPTCHA_TIMEOUT` | `8` | 请求 CAP API 的总超时（秒） |
| `CAP_API_ENDPOINT` | `https://captcha.api.968111.xyz/api/` | 自建 CAP 服务时改这里 |

若整套部署在子目录（如 `/proxy/`）且被反向代理改写导致路径推导失败：

```php
define('CAPTCHA_BASE_PATH', '/proxy');   // 不要以 / 结尾
```

### 6. 部署后自检

```bash
# 语法检查：应全部 No syntax errors
for f in miniproxy_captcha.php captcha/config.php captcha/gate.php \
         captcha/verify.php captcha/callback.php; do
  php -l $f
done

# 安全逻辑单元测试：期望"通过 51 项，失败 0 项"
php captcha/test_gate.php

# 现代网页适配测试：期望"通过 52 项，失败 0 项"
php test_modern.php

# 未验证访问应返回 302 跳验证页
curl -sI "https://你的域名/miniproxy_captcha.php?https://example.com" | grep -i location
# 期望：Location: https://你的域名/captcha/verify.php?redirect=...
```

然后浏览器打开同一地址，应看到验证页 → 完成验证 → 自动回到代理内容；
**0.5 小时内**再访问其他代理目标不再要求验证。

---

## 六、CAP 验证流程与安全设计（`feat/captcha-gate`）

```
访问受保护页 → 闸门检查 Session
                 ├─ 已通过且在有效期内 → 放行，直接代理
                 └─ 未通过/已过期 → 302 到 captcha/verify.php?redirect=<安全处理后的原URL>
                                        ↓
                             前端 cap-widget 完成 PoW 挑战，触发 solve 事件
                                        ↓
                        POST token 到 captcha/callback.php（带一次性 CSRF）
                                        ↓
                 PHP 用 cURL 请求 CAP /api/validate 做服务端二次校验
                                        ↓
                         仅当 success === true 才写入 Session
                                        ↓
                    session_regenerate_id(true) 防会话固定，跳回原页面
```

设计要点：

- **只信任服务端结果**：前端任何"已通过"标识都不采信，只看 CAP 服务端返回的 JSON。
- **防开放重定向**：回调地址必须同源（scheme + host + **端口**全匹配），
  拒绝 `javascript:`、`data:`、`//evil.com`、`http://host@evil.com` 等，
  不合规一律回落到站内首页。
- **双级防刷**：会话级 5 分钟失败 5 次、IP 级 5 分钟 30 次，超限返回 `429` + `Retry-After`。
- **默认拒绝放行**：CAP 服务超时或返回异常时**不降级绕过**，返回 `503`。
  这是有意为之——代理服务一旦被刷，压力会转移到上游目标站点。

关闭验证（临时）：注释掉 `miniproxy_captcha.php` 里 `mp_captcha_gate([...]);` 一行即可，
无需删文件。

---

## 七、已验证事项

| 项目 | 结果 |
|---|---|
| 原文件改动 | `miniproxy.php` 零改动，与仓库历史一致 |
| 语法检查 | 全部 PHP 文件通过 `php -l` |
| 闸门单元测试 | `captcha/test_gate.php` 51 项通过 |
| 现代网页单元测试 | `test_modern.php` 52 项通过 |
| CAP 真实联调 | PoW 50/50 → `redeem` 成功 → 服务端 `validate` 返回 `success:true` |
| 端到端 | 验证通过后成功代理 `httpbin.org/get`，客户端 IP 已被匿名化 |
| 原版 500 修复 | `wikipedia.org` 由 500 恢复为 200（149KB），无 PHP 错误污染，CSP 头已剥离 |
| 无回归 | Landing Page、JS / 字体 / SVG 资源、表单 POST 回写功能均正常 |

## 八、许可

本项目是 [miniProxy](https://github.com/joshdick/miniProxy)（作者 Joshua Dick）的衍生作品，
沿用其 **GNU General Public License v3**，完整条款见仓库根目录的 [`LICENSE`](LICENSE)。

这意味着：

- 你可以自由使用、修改和再分发本项目的代码；
- 分发时必须同时提供 GPLv3 许可证文本并保留版权声明；
- 基于本项目的衍生作品必须以相同许可证开源；
- 本项目**不提供任何担保**，使用风险由使用者自行承担。

上游 miniProxy 自 2020-04-26 起已停止维护，本项目同样"按现状提供"。
