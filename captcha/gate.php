<?php
/*
 * CAP 人机验证 —— 闸门核心库（cap_gate.php）
 *
 * 职责：
 *   1. 启动并加固 Session；
 *   2. 判断当前访问者是否已在 Session 有效期内通过人机验证；
 *   3. 未通过时跳转到独立验证页，并携带"安全回源地址"；
 *   4. 提供服务端二次校验（只信任 CAP 服务端返回结果）；
 *   5. 提供回调地址白名单校验，防止开放重定向；
 *   6. 提供失败次数 / IP 频率限制，防止被刷。
 *
 * 使用方式：在 miniProxy 入口副本的"最前面"引入即可：
 *   require_once __DIR__ . '/captcha/gate.php';
 *   mp_captcha_gate();          // 未通过验证则 302 到验证页并 exit
 *
 * 注意：本库只做"闸门"，不代理业务逻辑；代理逻辑仍由 miniproxy.php 原样执行。
 */

if (defined('MP_CAPTCHA_GATE_LOADED')) {
  return;
}
define('MP_CAPTCHA_GATE_LOADED', true);

if (!defined('CAP_API_ENDPOINT')) {
  require_once __DIR__ . '/config.php';
}

// ---------------------------------------------------------------------------
// 一、Session 启动与加固
// ---------------------------------------------------------------------------

/**
 * 启动 Session（带明文 Cookie 名前缀与 SameSite 防护）。
 * 同一请求内重复调用是安全的。
 */
function mp_captcha_start_session() {
  if (session_status() === PHP_SESSION_ACTIVE) {
    return;
  }

  //Cookie 作用范围覆盖整个站点根，保证入口页与验证页共享同一会话
  $cookiePath = function_exists('mp_captcha_base_path') ? mp_captcha_base_path() : '/';

  $cookieParams = [
    'lifetime' => 0,
    'path'     => $cookiePath,
    'domain'   => '',
    'secure'   => defined('CAPTCHA_FORCE_HTTPS') ? (bool) CAPTCHA_FORCE_HTTPS : false,
    'httponly' => true,
    'samesite' => 'Lax',
  ];
  if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params($cookieParams);
  } elseif (PHP_VERSION_ID >= 50500) {
    session_set_cookie_params(
      $cookieParams['lifetime'],
      $cookieParams['path'],
      $cookieParams['domain'],
      $cookieParams['secure'],
      $cookieParams['httponly']
    );
  }

  session_name(defined('CAPTCHA_SESSION_NAME') ? CAPTCHA_SESSION_NAME : 'MPCAPSESSID');
  session_start();
}

/**
 * 取得当前客户端的真实 IP（用于 IP 频率限制）。
 * 只作为"简单防刷"用途，不作为可信身份。
 */
function mp_captcha_client_ip() {
  return isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

/**
 * 统一输出 JSON 响应并退出（校验接口用）。
 */
function mp_captcha_json_response($payload, $status = 200) {
  if (!headers_sent()) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    header('X-Robots-Tag: noindex, nofollow');
  }
  echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  exit;
}

// ---------------------------------------------------------------------------
// 二、回调地址校验（防开放重定向）
// ---------------------------------------------------------------------------

/**
 * 从 redirect 参数中解析出"站内、安全"的回调地址。
 *
 * 规则（满足全部才放行，否则默认回落到新入口首页）：
 *   - 非空，且不是 //evil.com 这类协议相对地址；
 *   - scheme 只能是 http/https，且与当前请求一致（HTTPS 站点不接受 http 回调）；
 *   - host（含端口）必须与当前请求完全一致；
 *   - path 不以 \\ 开头，不含控制字符；
 *   - 只保留 php 入口路径或站内相对路径，避免跳到第三方域名。
 *
 * @return string 安全处理后的站点相对地址
 */
function mp_captcha_safe_redirect($redirect) {
  $fallback = mp_captcha_entry_url();

  $redirect = is_string($redirect) ? trim($redirect) : '';
  if ($redirect === '') {
    return $fallback;
  }

  //禁止协议相对地址与异常协议
  if (preg_match('~^[a-z][a-z0-9+.\-]*:~i', $redirect)) {
    $parts = parse_url($redirect);
    if (empty($parts['scheme']) || empty($parts['host'])) {
      return $fallback;
    }
    if (strtolower($parts['scheme']) === 'javascript' || strtolower($parts['scheme']) === 'data') {
      return $fallback;
    }
    //外部域名一律拒绝
    if (!mp_captcha_same_host(trim($redirect))) {
      return $fallback;
    }
    $redirect = ($parts['path'] ?? '/')
      . (isset($parts['query']) ? '?' . $parts['query'] : '')
      . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
  } else {
    //相对地址：必须是本站内的普通路径，不能以 // 或 /\\ 开头
    if (strpos($redirect, '//') === 0 || strpos($redirect, '\\\\') === 0) {
      return $fallback;
    }
  }

  //禁止反斜杠开头与控制字符
  if ($redirect === '' || strpos($redirect, '\\') === 0 || preg_match('/[\x00-\x1F\x7F]/', $redirect)) {
    return $fallback;
  }

  //limit 长度，避免超长参数
  if (strlen($redirect) > 2000) {
    return $fallback;
  }

  return $redirect;
}

/**
 * 判断给定 URL 是否与当前请求同源（scheme + host + port）。
 * 端口比较以"非标准端口"为准，标准端口与未指定视为等价。
 */
function mp_captcha_same_host($url) {
  $isHttps       = mp_captcha_is_https();
  $currentScheme = $isHttps ? 'https' : 'http';

  if (strpos($url, '//') === 0) {
    $url = $currentScheme . ':' . $url;
  }
  if (!preg_match('~^https?://~i', $url)) {
    return false;
  }

  $parts = parse_url($url);
  if (empty($parts['scheme']) || empty($parts['host'])) {
    return false;
  }
  if (strtolower($parts['scheme']) !== $currentScheme) {
    return false;
  }

  //HTTP_HOST 可能自带端口（如 proxy.example.com:8080），按方案的标准端口剥离
  $currentHost = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
  if (strpos($currentHost, ':') !== false && strpos($currentHost, ']') === false) {
    $currentHost = explode(':', $currentHost)[0];
  }
  if (strtolower($parts['host']) !== $currentHost) {
    return false;
  }

  //端口比较：只看非标准端口
  if (mp_captcha_url_port($parts) !== mp_captcha_current_port()) {
    return false;
  }
  return true;
}

/**
 * 当前请求是否为 HTTPS。
 */
function mp_captcha_is_https() {
  if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
    return true;
  }
  if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
    return strtolower((string) $_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https';
  }
  if (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && strtolower((string) $_SERVER['HTTP_X_FORWARDED_SSL']) === 'on') {
    return true;
  }
  if (defined('CAPTCHA_FORCE_HTTPS') && CAPTCHA_FORCE_HTTPS) {
    return true;
  }
  return false;
}

/**
 * 当前请求端口：显式非标准端口返回其值，标准端口（80/443）与未指定一律返回 null。
 */
function mp_captcha_current_port() {
  if (empty($_SERVER['SERVER_PORT'])) {
    return null;
  }
  $port = (int) $_SERVER['SERVER_PORT'];
  $default = mp_captcha_is_https() ? 443 : 80;
  return ($port === $default) ? null : $port;
}

/**
 * 从 URL 中取出端口，标准端口与未指定一律返回 null。
 */
function mp_captcha_url_port($parts) {
  if (!isset($parts['port'])) {
    return null;
  }
  $port = (int) $parts['port'];
  $scheme = strtolower($parts['scheme'] ?? 'http');
  $default = ($scheme === 'https') ? 443 : 80;
  return ($port === $default) ? null : $port;
}

/**
 * 站点根路径（形如 / 或 /subdir/），始终以 / 结尾。
 *
 * 说明：gate.php 位于 captcha/ 子目录，而受保护入口 miniproxy_captcha.php
 * 位于站点根目录，因此不能直接用 dirname(SCRIPT_NAME)。这里按
 * CAPTCHA_VERIFY_PAGE 所在子目录回退一级，得到真正的站点根。
 * 注意：Windows 下 dirname() 会返回反斜杠，每层都要归一化成 /。
 */
function mp_captcha_base_path() {
  //允许部署时显式指定站点根（例如放在反向代理子路径下），优先级最高
  if (defined('CAPTCHA_BASE_PATH') && CAPTCHA_BASE_PATH) {
    return '/' . trim((string) CAPTCHA_BASE_PATH, '/') . '/';
  }

  $normalize = function ($p) { return rtrim(str_replace('\\', '/', (string) $p), '/'); };

  //当前脚本所在目录，例如 /captcha 或 /proxy/captcha
  $dir = $normalize(dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/')));

  //验证页所在子目录名（默认 captcha），命中则回退一级到站点根
  $subDir = defined('CAPTCHA_VERIFY_PAGE') ? trim((string) dirname(CAPTCHA_VERIFY_PAGE), '.') : 'captcha';
  $subDir = trim(str_replace('\\', '/', $subDir), '/');

  if ($subDir !== '' && basename($dir) === $subDir) {
    $dir = $normalize(dirname($dir === '' ? '/' : $dir));
  }

  return $dir === '' ? '/' : $dir . '/';
}

/**
 * 站点根基础 URL（形如 https://host/ 或 https://host/subdir/），始终以 / 结尾。
 */
function mp_captcha_base_url() {
  $scheme = mp_captcha_is_https() ? 'https' : 'http';
  $host   = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
  return $scheme . '://' . $host . mp_captcha_base_path();
}

/**
 * 受保护入口本身（miniproxy_captcha.php）的绝对 URL。
 */
function mp_captcha_entry_url() {
  return mp_captcha_base_url() . 'miniproxy_captcha.php';
}

/**
 * 验证页的绝对 URL。
 */
function mp_captcha_verify_url() {
  return mp_captcha_base_url() . (defined('CAPTCHA_VERIFY_PAGE') ? CAPTCHA_VERIFY_PAGE : 'captcha/verify.php');
}

/**
 * 本地校验接口的绝对 URL。
 */
function mp_captcha_callback_url() {
  return mp_captcha_base_url() . (defined('CAPTCHA_CALLBACK_PAGE') ? CAPTCHA_CALLBACK_PAGE : 'captcha/callback.php');
}

/**
 * 当前被请求的完整 URL（含查询串），用于回调参数。
 */
function mp_captcha_current_request_url() {
  $scheme = mp_captcha_is_https() ? 'https' : 'http';
  $host   = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
  $uri    = (string) ($_SERVER['REQUEST_URI'] ?? '/');
  return $scheme . '://' . $host . $uri;
}

// ---------------------------------------------------------------------------
// 三、闸门
// ---------------------------------------------------------------------------

/**
 * 检查当前访问者是否已通过 CAP 人机验证（尚未过期）。
 */
function mp_captcha_is_verified() {
  if (empty($_SESSION['mp_captcha_verified'])) {
    return false;
  }
  $verifiedAt = isset($_SESSION['mp_captcha_verified_at']) ? (int) $_SESSION['mp_captcha_verified_at'] : 0;
  if ($verifiedAt <= 0) {
    return false;
  }
  $ttl = defined('CAPTCHA_VERIFIED_TTL') ? (int) CAPTCHA_VERIFIED_TTL : 1800;
  if ($ttl <= 0) {
    return true; //配置为 0 表示永不过期
  }
  if (time() - $verifiedAt > $ttl) {
    //过期：清理标记，触发重新验证
    unset($_SESSION['mp_captcha_verified'], $_SESSION['mp_captcha_verified_at']);
    return false;
  }
  return true;
}

/**
 * 标记为已验证（由本地校验接口回调，服务端校验通过后调用）。
 */
function mp_captcha_mark_verified() {
  $_SESSION['mp_captcha_verified']    = true;
  $_SESSION['mp_captcha_verified_at'] = time();
}

/**
 * 主闸门：未验证则 302 跳转到验证页并结束请求。
 *
 * @param array $options 可选：
 *                       - protect_all      是否保护所有路径（默认 true）
 *                       - protected_prefixes 额外保护的路由前缀（数组）
 *                       - exclude_prefixes   放行的路径前缀（数组）
 */
function mp_captcha_gate(array $options = []) {
  mp_captcha_start_session();

  $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
  $uri  = (string) ($_SERVER['REQUEST_URI'] ?? '/');

  //先处理放行项（例如首页说明页无需验证），避免无谓地跳转
  $exclude = isset($options['exclude_prefixes']) ? (array) $options['exclude_prefixes'] : [];
  foreach ($exclude as $prefix) {
    if (is_string($prefix) && $prefix !== '' && strpos($uri, $prefix) === 0) {
      return;
    }
  }

  //已通过且在有效期内 → 直接放行
  if (mp_captcha_is_verified()) {
    return;
  }

  //回调地址：只保留同源的、指向本受保护入口的 URL，非法则回落到入口首页
  $protocol  = mp_captcha_is_https() ? 'https' : 'http';
  $currentUrl = $protocol . '://' . $host . $uri;
  $redirect  = mp_captcha_safe_redirect($currentUrl);

  $verifyUrl = mp_captcha_verify_url()
    . (strpos(mp_captcha_verify_url(), '?') === false ? '?' : '&')
    . 'redirect=' . rawurlencode($redirect);

  if (!headers_sent()) {
    header('Cache-Control: no-store');
    header('Location: ' . $verifyUrl, true, 302);
  } else {
    //极端情况：输出已经开始，退化为 meta 刷新 + JS 跳转
    echo '<meta http-equiv="refresh" content="0;url=' . htmlspecialchars($verifyUrl, ENT_QUOTES, 'UTF-8') . '">';
    echo '<script>location.replace(' . json_encode($verifyUrl) . ');</script>';
  }
  exit;
}

// ---------------------------------------------------------------------------
// 四、本地校验接口辅助（callback.php 使用）
// ---------------------------------------------------------------------------

/**
 * 向 CAP 服务端发起二次校验，只信任服务端返回的 JSON。
 *
 * @return array{ok:bool, http:int, body:string, error:string}
 */
function mp_captcha_validate_token($token) {
  $endpoint = rtrim(CAP_API_ENDPOINT, '/') . '/' . ltrim(CAP_VALIDATE_PATH, '/');
  $payload  = json_encode([
    'token'     => (string) $token,
    'keepToken' => defined('CAP_KEEP_TOKEN') ? (bool) CAP_KEEP_TOKEN : false,
  ], JSON_UNESCAPED_SLASHES);

  if (!function_exists('curl_init')) {
    return ['ok' => false, 'http' => 0, 'body' => '', 'error' => 'curl extension not available'];
  }

  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $endpoint);
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
  curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'Accept: application/json',
    'Content-Length: ' . strlen($payload),
  ]);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HEADER, false);
  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, defined('CAPTCHA_CONNECT_TIMEOUT') ? (int) CAPTCHA_CONNECT_TIMEOUT : 5);
  curl_setopt($ch, CURLOPT_TIMEOUT, defined('CAPTCHA_TIMEOUT') ? (int) CAPTCHA_TIMEOUT : 8);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
  curl_setopt($ch, CURLOPT_USERAGENT, 'miniProxy-CAP-Gate/1.0');

  $body = curl_exec($ch);
  $http = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
  $err  = curl_error($ch);
  curl_close($ch);

  if ($body === false) {
    return ['ok' => false, 'http' => 0, 'body' => '', 'error' => $err ?: 'curl request failed'];
  }

  $decoded = json_decode($body, true);
  if (!is_array($decoded)) {
    //CAP 服务端异常（例如 Worker 返回错误页），一律视为校验失败
    return ['ok' => false, 'http' => $http, 'body' => '', 'error' => 'invalid json response'];
  }

  if ($http !== 200) {
    return ['ok' => false, 'http' => $http, 'body' => '', 'error' => 'captcha api http ' . $http];
  }

  //只信任 success === true
  if (!isset($decoded['success']) || $decoded['success'] !== true) {
    return ['ok' => false, 'http' => $http, 'body' => '', 'error' => 'captcha rejected'];
  }

  return ['ok' => true, 'http' => $http, 'body' => $body, 'error' => ''];
}

/**
 * 失败次数限制：同一会话在时间窗口内失败过多则拒绝。
 * @return array{limited:bool, remaining:int}
 */
function mp_captcha_failure_state() {
  $now    = time();
  $timeWindow = defined('CAPTCHA_FAILURE_WINDOW') ? (int) CAPTCHA_FAILURE_WINDOW : 300;
  $limit     = defined('CAPTCHA_FAILURE_LIMIT') ? (int) CAPTCHA_FAILURE_LIMIT : 5;

  $failures = isset($_SESSION['mp_captcha_failures']) ? (array) $_SESSION['mp_captcha_failures'] : [];
  $failures = array_values(array_filter($failures, function ($ts) use ($now, $timeWindow) {
    return is_int($ts) && ($now - $ts) <= $timeWindow;
  }));

  $_SESSION['mp_captcha_failures'] = $failures;
  $remaining = max(0, $limit - count($failures));
  return ['limited' => count($failures) >= $limit, 'remaining' => $remaining];
}

/**
 * 记录一次失败（服务端判定失败 / 参数错误时调用；网络异常不计入）。
 */
function mp_captcha_record_failure() {
  $now = time();
  if (!isset($_SESSION['mp_captcha_failures']) || !is_array($_SESSION['mp_captcha_failures'])) {
    $_SESSION['mp_captcha_failures'] = [];
  }
  $_SESSION['mp_captcha_failures'][] = $now;
}

/**
 * IP 级简单频率限制（无数据库环境下的最小防刷）。
 * @return array{limited:bool, remaining:int}
 */
function mp_captcha_ip_rate_state() {
  $now  = time();
  $dir  = sys_get_temp_dir() . '/mp_captcha_rate';
  $key  = 'ip_' . hash('sha256', mp_captcha_client_ip());
  $file = $dir . '/' . $key . '.json';
  $ttl  = defined('CAPTCHA_FAILURE_WINDOW') ? (int) CAPTCHA_FAILURE_WINDOW : 300;
  $limit = defined('CAPTCHA_IP_REQUEST_LIMIT') ? (int) CAPTCHA_IP_REQUEST_LIMIT : 30;

  $hits = [];
  if (is_file($file)) {
    $raw = @file_get_contents($file);
    if ($raw !== false) {
      $data = json_decode($raw, true);
      if (is_array($data)) {
        $hits = array_values(array_filter($data, function ($ts) use ($now, $ttl) {
          return is_int($ts) && ($now - $ts) <= $ttl;
        }));
      }
    }
  }

  if (!is_dir($dir)) {
    @mkdir($dir, 0700, true);
  }

  $hits[] = $now;
  @file_put_contents($file, json_encode($hits), LOCK_EX);

  //清理过期文件（简单桶）
  foreach (glob($dir . '/ip_*.json') ?: [] as $old) {
    if (filemtime($old) < $now - $ttl) {
      @unlink($old);
    }
  }

  $remaining = max(0, $limit - count($hits));
  return ['limited' => count($hits) > $limit, 'remaining' => $remaining];
}

/**
 * 生成本次回调使用的 CSRF token（一次性），前端需要带回。
 */
function mp_captcha_csrf_token() {
  if (empty($_SESSION['mp_captcha_csrf'])) {
    $_SESSION['mp_captcha_csrf'] = bin2hex(random_bytes(32));
  }
  return $_SESSION['mp_captcha_csrf'];
}

/**
 * 校验 CSRF token 并立即失效（防止重放）。
 */
function mp_captcha_check_csrf($token) {
  if (!is_string($token) || $token === '' || empty($_SESSION['mp_captcha_csrf'])) {
    return false;
  }
  $valid = hash_equals((string) $_SESSION['mp_captcha_csrf'], $token);
  unset($_SESSION['mp_captcha_csrf']); //一次性消费
  return $valid;
}

/**
 * 验证成功后清理计数与 CSRF，并按需重生成 Session ID。
 */
function mp_captcha_cleanup_after_success() {
  unset($_SESSION['mp_captcha_failures'], $_SESSION['mp_captcha_csrf']);

  if (session_status() === PHP_SESSION_ACTIVE) {
    //删除旧 cookie，防止会话固定
    if (ini_get('session.use_cookies') && !headers_sent()) {
      $params = session_get_cookie_params();
      setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        (bool) $params['secure'],
        (bool) $params['httponly']
      );
    }
    session_regenerate_id(true);
  }

  mp_captcha_mark_verified();
}
