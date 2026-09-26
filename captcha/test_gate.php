<?php
/*
 * CAP 闸门逻辑单元测试（无需 curl/mbstring，纯 PHP 安全逻辑）
 * 运行：php captcha/test_gate.php
 */

error_reporting(E_ALL & ~E_DEPRECATED);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SCRIPT_NAME']    = '/miniproxy_captcha.php';
$_SERVER['HTTP_HOST']      = 'proxy.example.com';
$_SERVER['REQUEST_URI']    = '/miniproxy_captcha.php?https://example.com';
$_SERVER['SERVER_PORT']    = '80';
unset($_SERVER['HTTPS'], $_SERVER['HTTP_X_FORWARDED_PROTO']);

require_once __DIR__ . '/gate.php';

$pass = 0; $fail = 0;
function check($label, $got, $expect) {
  global $pass, $fail;
  if ($got === $expect) { $pass++; echo "  [OK]   $label\n"; }
  else { $fail++; echo "  [FAIL] $label\n         expect: " . var_export($expect, true) . "\n         got:    " . var_export($got, true) . "\n"; }
}

echo "== 1. 基础 URL 推导 ==\n";
check('base_url',            mp_captcha_base_url(),       'http://proxy.example.com/');
check('base_path',           mp_captcha_base_path(),      '/');
check('entry_url',           mp_captcha_entry_url(),      'http://proxy.example.com/miniproxy_captcha.php');
check('verify_url',          mp_captcha_verify_url(),     'http://proxy.example.com/captcha/verify.php');
check('callback_url',        mp_captcha_callback_url(),   'http://proxy.example.com/captcha/callback.php');
check('current_request_url', mp_captcha_current_request_url(), 'http://proxy.example.com/miniproxy_captcha.php?https://example.com');

echo "\n== 2. 防开放重定向 ==\n";
$fb = 'http://proxy.example.com/miniproxy_captcha.php';
//同源地址会被归一化为相对路径（不泄漏 scheme/host，反代场景下更稳）
check('同源完整 URL 归一化',  mp_captcha_safe_redirect('http://proxy.example.com/miniproxy_captcha.php?https://a.com'),
      '/miniproxy_captcha.php?https://a.com');
check('同源相对路径放行',     mp_captcha_safe_redirect('/miniproxy_captcha.php?x=1'),
      '/miniproxy_captcha.php?x=1');
check('空参数回落',           mp_captcha_safe_redirect(''), $fb);
check('外域 https 拒绝',      mp_captcha_safe_redirect('https://evil.com/phish'),
      $fb);
check('外域带同后缀名拒绝',    mp_captcha_safe_redirect('http://proxy.example.com.evil.com/'),
      $fb);
check('协议相对 //evil 拒绝', mp_captcha_safe_redirect('//evil.com/steal'),
      $fb);
check('javascript: 拒绝',     mp_captcha_safe_redirect('javascript:alert(1)'),
      $fb);
check('data: 拒绝',           mp_captcha_safe_redirect('data:text/html,<script>alert(1)</script>'),
      $fb);
check('反斜杠开头拒绝',       mp_captcha_safe_redirect('\\\\evil.com'),
      $fb);
check('控制字符拒绝',         mp_captcha_safe_redirect("/x\nLocation: evil"),
      $fb);
check('超长参数回落',         mp_captcha_safe_redirect('/' . str_repeat('a', 3000)),
      $fb);
check('file: 协议拒绝',       mp_captcha_safe_redirect('file:///etc/passwd'),
      $fb);
check('仅 host 无 scheme 拒绝', mp_captcha_safe_redirect('http://'), $fb);
check('非字符串回落',         mp_captcha_safe_redirect(null), $fb);
check('用户信息混淆拒绝',     mp_captcha_safe_redirect('http://proxy.example.com@evil.com/'),
      $fb);

echo "\n== 3. HTTPS 场景下不接受 http 回调 ==\n";
$_SERVER['HTTPS'] = 'on';
$_SERVER['SERVER_PORT'] = '443';
$fbHttps = 'https://proxy.example.com/miniproxy_captcha.php';
check('https 站点回落为 https',   mp_captcha_safe_redirect(''), $fbHttps);
check('https 站点拒绝 http 回调',  mp_captcha_safe_redirect('http://proxy.example.com/miniproxy_captcha.php?x'),
      $fbHttps);
//同源 https 地址被归一化为相对路径（更安全，不泄漏 scheme/host）
check('https 站点接受 https 回调', mp_captcha_safe_redirect('https://proxy.example.com/miniproxy_captcha.php?x'),
      '/miniproxy_captcha.php?x');
check('https 站点端口不一致拒绝',  mp_captcha_safe_redirect('https://proxy.example.com:8443/x'), $fbHttps);
check('https 站点同源 + 同端口放行', mp_captcha_safe_redirect('https://proxy.example.com:443/x'), '/x');
unset($_SERVER['HTTPS']);
$_SERVER['SERVER_PORT'] = '80';
check('恢复 http 后回落正确',       mp_captcha_safe_redirect(''), $fb);

echo "\n== 4. 同源判定 ==\n";
check('same_host 同源',     mp_captcha_same_host('http://proxy.example.com/a'), true);
check('same_host 外域',     mp_captcha_same_host('http://evil.com/a'), false);
check('same_host 端口不同', mp_captcha_same_host('http://proxy.example.com:8080/a'), false);
check('same_host 协议相对', mp_captcha_same_host('//proxy.example.com/a'), true);
check('same_host 相对路径', mp_captcha_same_host('/just/a/path'), false);

echo "\n== 5. 验证状态与 TTL ==\n";
check('未验证初始态',       mp_captcha_is_verified(), false);
mp_captcha_mark_verified();
check('标记后已验证',       mp_captcha_is_verified(), true);
$_SESSION['mp_captcha_verified_at'] = time() - 1801; //超过 0.5 小时
check('1801 秒后过期',      mp_captcha_is_verified(), false);
check('过期后标记被清理',   isset($_SESSION['mp_captcha_verified']), false);

echo "\n== 6. CSRF 一次性消费 ==\n";
$t = mp_captcha_csrf_token();
check('CSRF token 非空',    strlen($t), 64);
check('CSRF 首次校验通过',  mp_captcha_check_csrf($t), true);
check('CSRF 重放被拒',      mp_captcha_check_csrf($t), false);
check('CSRF 空值被拒',      mp_captcha_check_csrf(''), false);
check('CSRF 错值被拒',      mp_captcha_check_csrf('nope'), false);

echo "\n== 7. 失败次数限制 ==\n";
unset($_SESSION['mp_captcha_failures']);
$s = mp_captcha_failure_state();
check('初始未受限',        $s['limited'], false);
check('初始剩余 5 次',      $s['remaining'], 5);
for ($i = 0; $i < 5; $i++) mp_captcha_record_failure();
$s = mp_captcha_failure_state();
check('5 次失败后受限',     $s['limited'], true);
check('受限后剩余 0',       $s['remaining'], 0);
$_SESSION['mp_captcha_failures'] = [time() - 9999]; //超出时间窗口的旧记录
$s = mp_captcha_failure_state();
check('窗口外旧记录被清理',  $s['limited'], false);

echo "\n== 8. 成功后的清理 ==\n";
$_SESSION['mp_captcha_failures'] = [time()];
$_SESSION['mp_captcha_csrf'] = bin2hex(random_bytes(8));
mp_captcha_cleanup_after_success();
check('成功后已验证',       mp_captcha_is_verified(), true);
check('失败计数被清空',     isset($_SESSION['mp_captcha_failures']), false);
check('CSRF 被清空',        isset($_SESSION['mp_captcha_csrf']), false);

echo "\n== 9. 校验接口的判定逻辑（不发起真实网络请求） ==\n";
//用反射确认 validate_token 会信任 success===true（此处仅验证可调用性与返回结构）
$ref = new ReflectionFunction('mp_captcha_validate_token');
check('validate_token 参数数', $ref->getNumberOfParameters(), 1);
check('validate_token 为函数', $ref->isInternal(), false);

echo "\n========================================\n";
echo "通过 $pass 项，失败 $fail 项\n";
exit($fail === 0 ? 0 : 1);
