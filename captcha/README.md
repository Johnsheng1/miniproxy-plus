# miniProxy-plus — CAP 人机验证接入说明

为 miniProxy 单文件代理接入 CAP（类 Cloudflare Turnstile 体验）的完整交付说明。
**原始 `miniproxy.php` 未做任何修改**，所有改造都在新增文件和副本上完成。

---

## 一、文件清单与职责

| 文件 | 类型 | 职责 |
|---|---|---|
| `miniproxy.php` | 原文件（**未改动**） | 原始代理逻辑，作为回退依据 |
| `miniproxy_captcha.php` | 新增副本 | 带验证闸门的代理入口：CAP 闸门 + 现代网页适配版代理逻辑。
自 `START CONFIGURATION` 起与 `main` 分支 `miniproxy-plus.php` 逐字节一致 |
| `captcha/config.php` | 新增 | 集中配置：CAP 地址、有效期、失败限制、超时、路径 |
| `captcha/gate.php` | 新增 | 闸门核心库：Session 加固、验证状态判断、跳转、服务端校验、防开放重定向、防刷 |
| `captcha/verify.php` | 新增 | 独立验证页：渲染 `<cap-widget>`，监听 `solve`/`error`，提交本地校验，成功后回源 |
| `captcha/callback.php` | 新增 | Token 服务端二次校验接口：只信任 CAP 服务端 `/api/validate` 返回结果 |

### 副本与原文件的差异范围

副本 `miniproxy_captcha.php` 由两部分拼成：

1. 文件开头 31 行 CAP 闸门调用（`require captcha/gate.php` + `mp_captcha_gate()`）；
2. 从 `START CONFIGURATION` 起的全部代理逻辑，与 `main` 分支的 `miniproxy-plus.php`
   **逐字节一致**（MD5 同为 `b5ff664f06af264a76ae4a59871f9378`）。

也就是说：本分支入口 = **CAP 闸门 + 现代网页适配版代理**，既有人机验证，
也包含下述现代网页修复（详见 `test_modern.php` 与提交记录）：

- `proxifySrcset()` 致命错误（无描述符的 srcset 导致 500）
- CSP / HSTS / COOP / COEP / Alt-Svc 等响应头透传
- `data-src`、`data-srcset`、`imagesrcset`、`integrity`、`nonce`、`<base href>`
- `fetch` / `sendBeacon` / `window.open` 的客户端改写
- PHP 8.2 `mb_convert_encoding()` 废弃警告、`display_errors` 污染、cURL 超时

原始文件 `miniproxy.php` 在两个分支上均**未做任何修改**，可作为回退依据。

---

## 二、接入代码（3 处关键片段）

### 1. 入口闸门（`miniproxy_captcha.php` 开头）

```php
require_once __DIR__ . '/captcha/gate.php';

//未通过人机验证则 302 到验证页并 exit；通过则继续执行下方原代理逻辑
mp_captcha_gate([
  'protect_all' => true,   //全站保护
]);
```

闸门位于任何输出与代理逻辑之前，所以未验证请求**不会触达** cURL 转发。

### 2. 验证页（`captcha/verify.php` 核心）

```html
<script src="https://captcha.api.968111.xyz/cap.min.js"></script>
<cap-widget id="cap"
            data-cap-api-endpoint="https://captcha.api.968111.xyz/api/"></cap-widget>
```

```js
widget.addEventListener('solve', async (e) => {
  const token = e.detail.token;              //只作为"待校验材料"
  const r = await fetch('captcha/callback.php', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'same-origin',
    body: JSON.stringify({token, csrf: CSRF, redirect: REDIRECT})
  });
  const data = await r.json();               //以服务端结果为准
  if (data.success) location.replace(data.redirect);
});
```

### 3. 服务端校验（`captcha/gate.php` → `mp_captcha_validate_token()`）

```php
curl_setopt($ch, CURLOPT_URL, 'https://captcha.api.968111.xyz/api/validate');
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
  'token'     => $token,
  'keepToken' => false,
]));
...
//只信任 success === true
if (!isset($decoded['success']) || $decoded['success'] !== true) {
  return ['ok' => false, ...];   //拒绝放行
}
```

---

## 三、安全设计要点

1. **只信任服务端结果**
   `callback.php` 完全不采信前端任何"已通过"字段，只依据 CAP `/api/validate` 的 HTTP 200 + `{"success":true}` 写入 Session。CAP 返回错误页 / 非 JSON / 超时一律视为失败。

2. **防开放重定向（防钓鱼）**
   `mp_captcha_safe_redirect()` 规则：
   - 拒绝 `javascript:`、`data:`、外域地址；
   - 拒绝 `//evil.com` 协议相对地址；
   - scheme / host / **端口**必须与当前请求完全一致（HTTPS 站点不接受 http 回调）；
   - 拒绝反斜杠开头与控制字符，长度限制 2000 字节。
   任意不合规都回落到 `miniproxy_captcha.php` 首页。

3. **会话加固**
   - `HttpOnly` + `SameSite=Lax` + 可选 `Secure`；
   - CSRF token 一次性消费（`hash_equals` 比对后立即失效）；
   - 校验通过后 `session_regenerate_id(true)` 并删除旧 Cookie，防会话固定；
   - Session 名独立为 `MPCAPSESSID`，不与业务会话冲突。

4. **防刷**
   - 会话级：5 分钟内失败 5 次 → `429` + `Retry-After`；
   - IP 级：每 IP 每 5 分钟最多 30 次提交请求（`sys_get_temp_dir()` 计数）；
   - CAP 网络异常**不计**为用户失败次数，避免服务端抖动把正常用户锁死。

5. **降级策略 = 默认拒绝**
   CAP 服务不可用时 `callback.php` 返回 `503 captcha_unavailable`，不放行；验证页显示"验证服务暂时不可用，请稍后重试"并提供重试按钮。这是有意为之——代理服务一旦被刷会对上游造成压力。

---

## 四、部署注意事项

### 1. Session 目录必须可写

闸门依赖 PHP Session。若 FCGI/FPM 以 `open_basedir` 或多用户运行时，注意：

- FPM：确认 `php_value[session.save_path]` 指向各池可写目录；
- 宝塔/虚拟主机：通常已默认可用；
- 排查：`phpinfo()` 看 `session.save_path`，手动 `touch` 测试。

### 2. 强烈建议 HTTPS

CAP token 与会话标识在 HTTP 下可被抓包劫持。上 HTTPS 后请修改 `captcha/config.php`：

```php
define('CAPTCHA_FORCE_HTTPS', true);
```

这会让 Session Cookie 自动带 `Secure` 标记，并强制回调必须是 https。

### 3. 入口地址

未改造的 `miniproxy.php` **不受闸门保护**。请把对外入口指向新文件：

```text
https://你的域名/miniproxy_captcha.php
```

如需对外仍显示 `/miniproxy.php`，用 Web Server 重写（任选其一，**不要**去改原文件）：

Nginx：

```nginx
location = /miniproxy.php {
    rewrite ^ /miniproxy_captcha.php last;
}
```

Apache（`.htaccess`）：

```apache
RewriteEngine On
RewriteRule ^miniproxy\.php$ /miniproxy_captcha.php [L]
```

### 4. 目录结构保持

`miniproxy_captcha.php` 通过 `__DIR__ . '/captcha/gate.php'` 定位，
所以 `captcha/` 必须与入口副本位于同级：

```text
站点根/
├─ miniproxy.php            # 原文件，未保护（回退用）
├─ miniproxy_captcha.php    # 带闸门入口
└─ captcha/
   ├─ config.php
   ├─ gate.php
   ├─ verify.php
   └─ callback.php
```

若整个项目部署在子目录（如 `/proxy/`），无需改代码，`mp_captcha_base_path()`
会自动从 `SCRIPT_NAME` 推导站点根；若被反向代理改写导致推导失败，可在
`config.php` 中显式指定：

```php
define('CAPTCHA_BASE_PATH', '/proxy');   //不要以 / 结尾
```

### 5. 依赖扩展

沿用 miniProxy 原有要求：`curl`、`mbstring`、`xml`。
验证体系额外用到 `json`（PHP 5.2+ 内置）、随机源 `random_bytes()` 与
`hash_equals()`（PHP 5.6+ / 7+）。

因此**实际最低 PHP 版本为 5.6**（而不是 miniProxy 标注的 5.4.7）；
用 PHP 7.1+ 可启用 `session_set_cookie_params()` 数组形式的 `SameSite` 支持，
低于该版本时 SameSite 会被自动省略（功能仍可用，只是 Cookie 兼容性稍弱）。

### 6. 临时关闭验证

注释掉 `miniproxy_captcha.php` 中的一行即可，恢复无门槛代理：

```php
//mp_captcha_gate(['protect_all' => true]);
```

---

## 五、已确认的部署参数

| 项目 | 取值 |
|---|---|
| 保护范围 | 全站（`miniproxy_captcha.php` 的所有请求） |
| 入口文件 | `miniproxy_captcha.php` |
| 验证页形式 | 独立文件 `captcha/verify.php` |
| 验证有效期 | 1800 秒（0.5 小时） |

可调项集中在 `captcha/config.php`：

| 配置项 | 默认值 |
|---|---|
| `CAP_API_ENDPOINT` | `https://captcha.api.968111.xyz/api/` |
| `CAP_JS_URL` | `https://captcha.api.968111.xyz/cap.min.js` |
| `CAPTCHA_VERIFIED_TTL` | `1800` |
| `CAPTCHA_FAILURE_LIMIT` | `5` 次 |
| `CAPTCHA_FAILURE_WINDOW` | `300` 秒 |
| `CAPTCHA_IP_REQUEST_LIMIT` | `30` 次 |
| `CAPTCHA_TIMEOUT` | `8` 秒 |
| `CAPTCHA_CONNECT_TIMEOUT` | `5` 秒 |
| `CAPTCHA_FORCE_HTTPS` | `false`（上 HTTPS 后改 `true`） |

---

## 六、已验证事项

| 项目 | 结果 |
|---|---|
| 原文件改动 | `miniproxy.php` 零改动，与仓库历史一致 |
| 语法检查 | 全部 PHP 文件通过 `php -l` |
| 闸门单元测试 | `captcha/test_gate.php` 51 项通过 |
| 现代网页单元测试 | `test_modern.php` 52 项通过 |
| CAP 真实联调 | PoW 50/50 → `redeem` 成功 → 服务端 `validate` 返回 `success:true` |
| 闸门 + 现代改造协同 | 验证通过后成功代理 `wikipedia.org`（原版 500），200 / 149KB，无 PHP 错误污染，CSP 已剥离 |
| 代理逻辑一致性 | 入口副本自 `START CONFIGURATION` 起与 `main` 分支 `miniproxy-plus.php` MD5 一致 |

---

## 七、联调测试建议

1. 直接访问 `miniproxy_captcha.php?https://example.com`
   → 应 302 到 `captcha/verify.php?redirect=...`
2. 完成验证 → 应自动回到受保护页面并看到代理内容
3. 已通过状态下再访问其他代理 URL → 不应再次验证（30 分钟内）
4. 手动访问 `captcha/verify.php?redirect=https://evil.com`
   → 应被回落到站内首页，不会跳外域
5. 连续用错误 token 打 `captcha/callback.php` 6 次 → 第 6 次起返回 `429`
6. 30 分钟后再次访问 → 应重新要求验证

> 注：本机无 PHP 运行时，语法需在服务器上用 `php -l` 校验；
> CAP API 的 `/api/challenge`、`/api/validate` 已在交付前实测连通
> （`challenge` 返回 200；`validate` 缺 token 返回 400 `{"success":false,"error":"Missing token"}`）。
