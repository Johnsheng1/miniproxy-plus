<?php
/*
 * CAP 人机验证 —— 独立验证页（captcha/verify.php）
 *
 * 用户未通过人机验证时，由闸门（gate.php）302 跳转到本页。
 * 通过验证后自动跳回原本想访问的页面（redirect 参数已由服务端白名单校验）。
 */

require_once __DIR__ . '/gate.php';
mp_captcha_start_session();

//若已经通过验证，直接回源（避免重复验证）
if (mp_captcha_is_verified()) {
  $target = mp_captcha_safe_redirect(isset($_GET['redirect']) ? $_GET['redirect'] : '');
  header('Location: ' . $target, true, 302);
  exit;
}

//redirect 参数一律经过白名单校验，只放行同源地址
$redirect = mp_captcha_safe_redirect(isset($_GET['redirect']) ? $_GET['redirect'] : '');
$csrf     = mp_captcha_csrf_token();
$callbackUrl = mp_captcha_callback_url();

//验证失败的提示信息（来自 callback.php 的重定向回来）
$info = isset($_GET['e']) ? (string) $_GET['e'] : '';
$messages = [
  'failed'  => '验证未通过，请重新完成人机验证。',
  'network' => '验证服务连接超时或异常，请稍后重试。',
  'limit'   => '失败次数过多，请稍后再试。',
  'expired' => '验证会话已过期，请重新验证。',
];
$message = isset($messages[$info]) ? $messages[$info] : '';

$verifyUrl = htmlspecialchars(mp_captcha_verify_url() . '?redirect=' . rawurlencode($redirect), ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>正在验证 - miniProxy</title>
<style>
  :root{--bg1:#f6f8fa;--bg2:#e9eef6;--card:#ffffff;--accent:#2563eb;--muted:#6b7280;--err:#b91c1c;--ok:#047857;--line:#e5e7eb}
  html,body{height:100%;margin:0}
  body{font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif;
       background:linear-gradient(135deg,var(--bg1),var(--bg2));display:flex;align-items:center;justify-content:center;padding:24px;color:#111827}
  .card{background:var(--card);max-width:520px;width:100%;border-radius:14px;box-shadow:0 10px 30px rgba(15,23,42,.08);padding:28px 26px;text-align:center}
  h1{margin:0 0 6px;font-size:20px;letter-spacing:-.01em}
  .lead{margin:0 0 20px;color:var(--muted);font-size:14px;line-height:1.6}
  #cap{display:flex;justify-content:center;margin:6px 0 4px}
  .status{margin-top:16px;min-height:22px;font-size:14px;color:var(--muted)}
  .status.error{color:var(--err)}
  .status.ok{color:var(--ok)}
  .retry{margin-top:14px;display:none}
  .retry button{background:var(--accent);color:#fff;border:none;padding:9px 16px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600}
  .retry button:hover{filter:brightness(1.05)}
  .hint{margin-top:18px;font-size:12px;color:#9ca3af;line-height:1.6}
  .footer{margin-top:14px;padding-top:12px;border-top:1px solid var(--line);font-size:12px;color:#9ca3af;text-align:center}
  a{color:var(--accent);text-decoration:none;word-break:break-all}
  .err{background:#fef2f2;border:1px solid #fecaca;color:var(--err);border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:16px;text-align:left}
</style>
<script src="<?php echo htmlspecialchars(CAP_JS_URL, ENT_QUOTES, 'UTF-8'); ?>"></script>
</head>
<body>
<div class="card" role="main">
  <h1>请完成人机验证</h1>
  <p class="lead">为了保护代理服务的稳定与安全，首次访问需要完成一次验证；验证通过后在 <?php echo (int) (defined('CAPTCHA_VERIFIED_TTL') ? CAPTCHA_VERIFIED_TTL : 1800) / 60; ?> 分钟内无需重复验证。</p>

  <?php if ($message !== ''): ?>
    <div class="err" role="alert"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></div>
  <?php endif; ?>

  <cap-widget
      id="cap"
      data-cap-api-endpoint="<?php echo htmlspecialchars(CAP_API_ENDPOINT, ENT_QUOTES, 'UTF-8'); ?>"
      data-cap-i18n-initial-state="请点击此处完成验证"
      data-cap-i18n-verifying-label="正在计算验证凭证..."></cap-widget>

  <div id="status" class="status" role="status" aria-live="polite">请在上方完成验证。</div>

  <div class="retry" id="retry">
    <button type="button" id="retryBtn">重新加载验证组件</button>
  </div>

  <p class="hint">验证通过后将自动返回原页面。若长时间无响应，请检查网络后重试。<br>
  来源页面：<a href="<?php echo $verifyUrl; ?>"><?php echo htmlspecialchars($redirect, ENT_QUOTES, 'UTF-8'); ?></a></p>

  <p class="footer"><a href="<?php echo htmlspecialchars(PROXY_GITHUB_URL, ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener noreferrer">miniProxy-plus on GitHub</a></p>
</div>

<script>
(function () {
  var widget   = document.getElementById('cap');
  var statusEl = document.getElementById('status');
  var retryEl  = document.getElementById('retry');
  var retryBtn = document.getElementById('retryBtn');
  var CALLBACK = <?php echo json_encode($callbackUrl, JSON_UNESCAPED_SLASHES); ?>;
  var CSRF     = <?php echo json_encode($csrf, JSON_UNESCAPED_SLASHES); ?>;
  var REDIRECT = <?php echo json_encode($redirect, JSON_UNESCAPED_SLASHES); ?>;
  var submitting = false;

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = 'status' + (cls ? ' ' + cls : '');
  }

  function showRetry(show) {
    retryEl.style.display = show ? 'block' : 'none';
  }

  //cap-widget 未注册（脚本被拦截/加载失败）时给出友好提示
  if (!window.customElements || !window.customElements.get('cap-widget')) {
    setStatus('验证组件加载失败，请检查网络后重试。', 'error');
    showRetry(true);
  }

  if (!widget) {
    setStatus('页面初始化失败，请刷新重试。', 'error');
    showRetry(true);
    return;
  }

  widget.addEventListener('solve', function (e) {
    if (submitting) return;
    submitting = true;
    var token = (e && e.detail && e.detail.token) ? e.detail.token : '';
    setStatus('正在提交服务端校验…');
    showRetry(false);

    fetch(CALLBACK, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({token: token, csrf: CSRF, redirect: REDIRECT})
    }).then(function (res) {
      return res.json().catch(function () { return {success: false, error: 'bad_response'}; });
    }).then(function (data) {
      if (data && data.success) {
        setStatus('验证通过，正在跳转…', 'ok');
        window.location.replace(data.redirect || REDIRECT || '/');
      } else {
        submitting = false;
        var code = (data && data.error) || 'failed';
        if (code === 'limited') {
          setStatus('失败次数过多，请稍后再试。', 'error');
          showRetry(false);
        } else if (code === 'captcha_unavailable') {
          setStatus('验证服务暂时不可用，请稍后重试。', 'error');
          showRetry(true);
        } else {
          setStatus('验证未通过，请重新完成。', 'error');
          showRetry(true);
        }
        try { widget.reset(); } catch (err) {}
      }
    }).catch(function () {
      submitting = false;
      setStatus('网络异常，校验未完成，请重试。', 'error');
      showRetry(true);
      try { widget.reset(); } catch (err) {}
    });
  });

  widget.addEventListener('error', function (e) {
    setStatus('验证组件加载出错：' + ((e && e.detail && e.detail.message) || '未知错误'), 'error');
    showRetry(true);
  });

  //部分浏览器 cap-widget 升级失败时 progress 事件可作为加载信号
  widget.addEventListener('progress', function (e) {
    if (e && e.detail && typeof e.detail.progress === 'number') {
      setStatus('正在计算验证凭证… ' + e.detail.progress + '%');
    }
  });

  retryBtn.addEventListener('click', function () {
    window.location.reload();
  });

  //组件脚本整体加载失败的兜底检测（未升级 + 组件无尺寸）
  setTimeout(function () {
    var upgraded = false;
    try { upgraded = !!(widget.shadowRoot && widget.shadowRoot.childNodes.length); } catch (e) {}
    if (!upgraded && (!widget.offsetWidth || widget.offsetWidth === 0)) {
      showRetry(true);
      setStatus('验证组件未能加载，请点击下方按钮重试。', 'error');
    }
  }, 4000);
})();
</script>
</body>
</html>
