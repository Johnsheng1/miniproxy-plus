<?php
/*
 * CAP 人机验证 —— 配置文件
 * 本文件由 miniProxy-plus 接入 CAP（类 Cloudflare Turnstile 体验）时新增。
 * 原始 miniproxy.php 不做任何修改，本配置仅作用于新增的验证体系。
 */

// ---------------------------------------------------------------------------
// CAP 服务设置
// ---------------------------------------------------------------------------

//CAP 验证服务的 API 根地址（结尾的斜杠必须保留）
if (!defined('CAP_API_ENDPOINT')) {
  define('CAP_API_ENDPOINT', 'https://captcha.api.968111.xyz/api/');
}

//前端组件地址（cap-widget 官方 CDN）
//统一使用 npm 官方源，与 CAP 服务端解耦；组件本身与 API 端点分离，
//API 地址由上面的 CAP_API_ENDPOINT 单独控制。
if (!defined('CAP_JS_URL')) {
  define('CAP_JS_URL', 'https://cdn.jsdelivr.net/npm/cap-widget@latest/cap.min.js');
}

//服务端二次校验接口（相对 CAP_API_ENDPOINT）
if (!defined('CAP_VALIDATE_PATH')) {
  define('CAP_VALIDATE_PATH', 'validate');
}

//项目仓库地址，显示在验证页页脚
if (!defined('PROXY_GITHUB_URL')) {
  define('PROXY_GITHUB_URL', 'https://github.com/Johnsheng1/miniproxy-plus');
}

//是否保留 CAP token 以便后续复用（默认 false：校验即消费）
if (!defined('CAP_KEEP_TOKEN')) {
  define('CAP_KEEP_TOKEN', false);
}

// ---------------------------------------------------------------------------
// 会话与有效期
// ---------------------------------------------------------------------------

//验证通过后的有效期（秒）。0.5 小时 = 1800 秒。
if (!defined('CAPTCHA_VERIFIED_TTL')) {
  define('CAPTCHA_VERIFIED_TTL', 1800);
}

//Session Cookie 名称
if (!defined('CAPTCHA_SESSION_NAME')) {
  define('CAPTCHA_SESSION_NAME', 'MPCAPSESSID');
}

//是否强制使用 HTTPS 访问（部署到 HTTPS 站点时改为 true，会自动给 Cookie 加 Secure 标记）
if (!defined('CAPTCHA_FORCE_HTTPS')) {
  define('CAPTCHA_FORCE_HTTPS', false);
}

// ---------------------------------------------------------------------------
// 路径
// ---------------------------------------------------------------------------

//验证页（独立文件，相对站点根目录）
if (!defined('CAPTCHA_VERIFY_PAGE')) {
  define('CAPTCHA_VERIFY_PAGE', 'captcha/verify.php');
}

//本地校验接口（前端把 token POST 到这里）
if (!defined('CAPTCHA_CALLBACK_PAGE')) {
  define('CAPTCHA_CALLBACK_PAGE', 'captcha/callback.php');
}

//闸门库自身，避免重复引用
if (!defined('CAPTCHA_GATE_FILE')) {
  define('CAPTCHA_GATE_FILE', __FILE__);
}

// ---------------------------------------------------------------------------
// 防刷限制
// ---------------------------------------------------------------------------

//时间窗口内允许的最大失败次数（仅统计"服务端判定失败/参数错误"，网络异常不计入）
if (!defined('CAPTCHA_FAILURE_LIMIT')) {
  define('CAPTCHA_FAILURE_LIMIT', 5);
}

//失败计数的时间窗口（秒）
if (!defined('CAPTCHA_FAILURE_WINDOW')) {
  define('CAPTCHA_FAILURE_WINDOW', 300);
}

//单个 IP 在时间窗口内允许请求本地校验接口的最大次数（含成功）
if (!defined('CAPTCHA_IP_REQUEST_LIMIT')) {
  define('CAPTCHA_IP_REQUEST_LIMIT', 30);
}

// ---------------------------------------------------------------------------
// 网络请求
// ---------------------------------------------------------------------------

//请求 CAP API 的连接超时（秒）
if (!defined('CAPTCHA_CONNECT_TIMEOUT')) {
  define('CAPTCHA_CONNECT_TIMEOUT', 5);
}

//请求 CAP API 的总超时（秒）
if (!defined('CAPTCHA_TIMEOUT')) {
  define('CAPTCHA_TIMEOUT', 8);
}

//失败计数存在 Session 中（无 Cookie 的客户端退化为"仅本次请求受限"）
if (!defined('CAPTCHA_USE_SESSION_RATE_LIMIT')) {
  define('CAPTCHA_USE_SESSION_RATE_LIMIT', true);
}
