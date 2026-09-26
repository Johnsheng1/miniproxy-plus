<?php
/*
 * CAP 人机验证 —— token 服务端校验接口（captcha/callback.php）
 *
 * 前端在 cap-widget 触发 solve 事件后，把 token POST 到本接口。
 * 本接口"只信任" CAP 服务端 /api/validate 的返回结果，绝不相信前端任何"已通过"标识。
 *
 * 响应 JSON：
 *   {"success":true,  "redirect":"https://host/原始页面"}
 *   {"success":false, "error":"failed|captcha_unavailable|limited|bad_request|expired"}
 */

require_once __DIR__ . '/gate.php';

//只接受 POST；其他方法一律拒绝
if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
  mp_captcha_json_response(['success' => false, 'error' => 'bad_request'], 405);
}

//读取 JSON 请求体（同时兼容 application/x-www-form-urlencoded）
$contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
$raw = file_get_contents('php://input') ?: '';
$input = [];
if (strpos($contentType, 'application/json') !== false) {
  $decoded = json_decode($raw, true);
  $input = is_array($decoded) ? $decoded : [];
} else {
  parse_str($raw, $input);
  if (empty($input) && !empty($_POST)) {
    $input = $_POST;
  }
}

$token    = isset($input['token']) && is_string($input['token']) ? trim($input['token']) : '';
$csrf     = isset($input['csrf']) && is_string($input['csrf']) ? $input['csrf'] : '';
$redirect = isset($input['redirect']) && is_string($input['redirect']) ? $input['redirect'] : '';

mp_captcha_start_session();

//Session 过期（例如关闭浏览器太久）→ 让前端回验证页重新开始
if (empty($_SESSION['mp_captcha_csrf'])) {
  mp_captcha_json_response(['success' => false, 'error' => 'expired'], 401);
}

//CSRF 一次性校验
if (!mp_captcha_check_csrf($csrf)) {
  mp_captcha_json_response(['success' => false, 'error' => 'bad_request'], 400);
}

//IP 级简单频率限制（超出即拒绝，不作为用户失败次数）
$ipState = mp_captcha_ip_rate_state();
if ($ipState['limited']) {
  header('Retry-After: ' . (defined('CAPTCHA_FAILURE_WINDOW') ? (int) CAPTCHA_FAILURE_WINDOW : 300));
  mp_captcha_json_response(['success' => false, 'error' => 'limited'], 429);
}

//会话级失败次数限制
$failState = mp_captcha_failure_state();
if ($failState['limited']) {
  header('Retry-After: ' . (defined('CAPTCHA_FAILURE_WINDOW') ? (int) CAPTCHA_FAILURE_WINDOW : 300));
  mp_captcha_json_response(['success' => false, 'error' => 'limited'], 429);
}

//参数合法性
if ($token === '' || strlen($token) > 4096) {
  mp_captcha_record_failure();
  mp_captcha_json_response(['success' => false, 'error' => 'bad_request'], 400);
}

//服务端二次校验（只信任 CAP 服务端返回结果）
$verify = mp_captcha_validate_token($token);

if (!$verify['ok']) {
  //CAP 服务异常/超时：默认拒绝放行（降级策略 = 拒绝），不计为用户失败次数
  if (in_array($verify['error'], ['curl extension not available'], true) || $verify['http'] === 0) {
    mp_captcha_json_response(['success' => false, 'error' => 'captcha_unavailable'], 503);
  }
  //服务端明确拒绝（http 400/401/500 或 success=false）→ 记为一次失败
  mp_captcha_record_failure();
  mp_captcha_json_response(['success' => false, 'error' => 'failed'], 403);
}

//校验通过：清理计数、重生成 Session ID、写入验证标记
mp_captcha_cleanup_after_success();

mp_captcha_json_response([
  'success'  => true,
  'redirect' => mp_captcha_safe_redirect($redirect),
]);
