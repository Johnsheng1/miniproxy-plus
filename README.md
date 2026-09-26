# miniProxy-plus

一个轻量级 PHP Web 代理，在 [miniProxy](https://github.com/joshdick/miniProxy) 基础上
增加了 **CAP 人机验证闸门**，用于防止代理被匿名滥用。

本项目分成两个分支，按需选择：

| 分支 | 内容 | 适合谁 |
|---|---|---|
| [`main`](../../tree/main) | 原版 miniProxy，单文件，无任何验证 | 内网自用、已通过其他方式限流、需要最简部署 |
| [`feat/captcha-gate`](../../tree/feat/captcha-gate) | 接入 CAP 人机验证，未通过验证一律跳验证页 | 公网部署、需要防刷和防扫描 |

> 上游 miniProxy 自 2020-04-26 起已停止维护，本项目同样"按现状提供"，自行承担使用风险。

---

## 一、两个分支的差异

两个分支的代理核心完全一致，`feat/captcha-gate` 只在原有逻辑**之外**新增验证体系，
并且**没有修改原文件 `miniproxy.php` 的任何一个字节**——它被完整保留作为回退依据。

```
main（1 个文件）                      feat/captcha-gate（8 个文件）
├─ miniproxy.php                      ├─ miniproxy.php            ← 原样保留，未改动
                                       ├─ miniproxy_captcha.php    ← 带闸门的入口副本
                                       └─ captcha/
                                          ├─ gate.php              闸门核心库
                                          ├─ config.php            集中配置
                                          ├─ verify.php            独立验证页
                                          ├─ callback.php          token 服务端校验接口
                                          ├─ test_gate.php         安全逻辑单元测试
                                          └─ README.md             详细部署说明
```

副本 `miniproxy_captcha.php` 与原文件的差异**仅有两处**，其余逐字节一致：

1. 文件开头插入 17 行闸门调用；
2. 编码调用改为 PHP 8.2+ 兼容写法（消除 `mb_convert_encoding()` 的 `HTML-ENTITIES` 废弃警告）。

---

## 二、环境要求

| 项目 | 要求 |
|---|---|
| PHP | `main` 分支 ≥ 5.4.7；`feat/captcha-gate` 分支 ≥ 5.6（用到 `hash_equals`） |
| 扩展 | `curl`、`mbstring`、`xml` 三者必装 |
| Session | 服务端 PHP Session 可写（`captcha` 分支需要） |
| 网络 | 出站可访问 `captcha.api.968111.xyz`（`captcha` 分支需要） |

检查命令：

```bash
php -v
php -m | grep -Ei 'curl|mbstring|xml'
php -i | grep session.save_path    # 该路径需可写
```

---

## 三、部署 `main` 分支（原版，三步）

```bash
git clone https://github.com/Johnsheng1/miniproxy-plus.git
cd miniproxy-plus && git checkout main
```

1. 上传 `miniproxy.php` 到站点目录；
2. 浏览器访问 `https://你的域名/miniproxy.php`，看到代理首页即成功；
3. 按需修改文件顶部 `/*** START CONFIGURATION ***/` 区域的配置项。

### 原版配置项

| 变量 | 默认 | 说明 |
|---|---|---|
| `$whitelistPatterns` | `[]` | 允许代理的 URL 正则白名单，空数组 = 允许任意 URL |
| `$blacklistPatterns` | `[]` | 禁止代理的 URL 正则黑名单 |
| `$forceCORS` | `true` | 给被代理站点输出 CORS 头 |
| `$disallowLocal` | `true` | 禁止代理内网地址（防 SSRF，**别关**） |
| `$anonymize` | `true` | 不透传客户端 IP 给上游（`X-Forwarded-For`） |
| `$startURL` | `""` | 直接访问时的默认代理目标，留空则显示首页 |
| `$landingExampleURL` | `"https://google.com"` | 首页表单里的示例 URL |

用法：在 URL 后拼上要代理的地址：

```
https://你的域名/miniproxy.php?https://example.com
```

---

## 四、部署 `feat/captcha-gate` 分支（带人机验证）

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
for f in miniproxy_captcha.php captcha/config.php captcha/gate.php captcha/verify.php captcha/callback.php; do
  php -l $f
done

# 安全逻辑单元测试：期望"通过 51 项，失败 0 项"
php captcha/test_gate.php

# 未验证访问应返回 302 跳验证页
curl -sI "https://你的域名/miniproxy_captcha.php?https://example.com" | grep -i location
# 期望：Location: https://你的域名/captcha/verify.php?redirect=...
```

然后浏览器打开同一地址，应看到验证页 → 完成验证 → 自动回到代理内容；
**0.5 小时内**再访问其他代理目标不再要求验证。

---

## 五、验证流程与安全设计（`feat/captcha-gate`）

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

## 六、已验证事项

| 项目 | 结果 |
|---|---|
| 原文件改动 | `miniproxy.php` 零改动，与仓库历史完全一致 |
| 语法检查 | 7 个 PHP 文件全部通过 `php -l` |
| 单元测试 | `captcha/test_gate.php` 51 项全部通过 |
| 真实 CAP 联调 | PoW 50/50 挑战求解 → `redeem` 成功 → 服务端 `validate` 返回 `success:true` |
| 端到端 | 验证后成功代理 `httpbin.org/get`，客户端 IP 已被匿名化 |
| 防重定向 | 外域 / `javascript:` / `data:` / 协议相对 / 用户信息混淆等用例全部拦截 |
| 有效期 | 300 秒过期后正确要求重新验证 |

## 七、许可

沿用上游 [miniProxy](https://github.com/joshdick/miniProxy) 的 GNU GPL v3。
