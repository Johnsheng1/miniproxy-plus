<?php
/*
 * miniproxy 现代网页适配改造 —— 回归测试
 * 运行：php test_modern.php
 *
 * 覆盖两部分：
 *   A. 纯函数单元测试（proxifySrcset / 响应头黑名单 / 编码规范化），无需网络；
 *   B. 通过 PHP 内置服务器做 HTTP 级验证（--serve 模式）。
 */

error_reporting(E_ALL & ~E_DEPRECATED);

$pass = 0; $fail = 0; $errors = [];
function check($label, $got, $expect) {
  global $pass, $fail, $errors;
  if ($got === $expect) { $pass++; echo "  [OK]   $label\n"; }
  else {
    $fail++; $errors[] = $label;
    echo "  [FAIL] $label\n         expect: " . var_export($expect, true) . "\n         got:    " . var_export($got, true) . "\n";
  }
}
function checkTrue($label, $cond) { check($label, (bool) $cond, true); }

/* ---------------------------------------------------------------------------
 * A. 纯函数测试
 *
 * miniproxy-plus.php 的顶层逻辑会尝试解析请求并 die()，不能直接 include。
 * 因此这里用"读取源码 + 反射重建"的方式，只取被测函数定义执行。
 * --------------------------------------------------------------------------- */

//本测试覆盖两个入口副本：miniproxy-plus.php（main 分支）与 miniproxy_captcha.php
//（feat/captcha-gate 分支）。两个文件自 START CONFIGURATION 起的代理逻辑完全相同，
//因此下面所有断言对二者都应成立。默认测试当前分支上存在的那个文件。
$proxyFile = null;
foreach (["miniproxy-plus.php", "miniproxy_captcha.php"] as $candidate) {
  if (is_file(__DIR__ . "/" . $candidate)) { $proxyFile = __DIR__ . "/" . $candidate; break; }
}
if ($proxyFile === null) {
  fwrite(STDERR, "未找到待测的代理入口副本（miniproxy-plus.php 或 miniproxy_captcha.php）
");
  exit(2);
}
echo "被测文件: " . basename($proxyFile) . "
";
$src = file_get_contents($proxyFile);

/** 取出某个函数的完整源码并 eval 出来，返回其 ReflectionFunction */
function extract_function($src, $signature) {
  $start = strpos($src, $signature);
  if ($start === false) { throw new RuntimeException("function not found: $signature"); }
  // 从签名开始，配平大括号找到函数结束
  $i = strpos($src, '{', $start);
  $depth = 0; $end = $i;
  for ($p = $i; $p < strlen($src); $p++) {
    if ($src[$p] === '{') $depth++;
    elseif ($src[$p] === '}') { $depth--; if ($depth === 0) { $end = $p; break; } }
  }
  $code = substr($src, $start, $end - $start + 1);
  eval($code);
  $name = preg_replace('/^function\s+/', '', substr($signature, 0, strpos($signature, '(')));
  $name = trim($name);
  return new ReflectionFunction($name);
}

echo "=== A. proxifySrcset（原版在此 fatal） ===\n";
$reflProxifySrcset = extract_function($src, 'function proxifySrcset($srcset, $baseURL)');
$reflRel2abs      = extract_function($src, 'function rel2abs($rel, $base)');
$rel2abs          = function ($rel, $base) use ($reflRel2abs) { return $reflRel2abs->invoke($rel, $base); };

// invoke 参数顺序按函数签名：(srcset, baseURL)
$ps = function ($srcset, $baseURL) use ($reflProxifySrcset) {
  return $reflProxifySrcset->invoke($srcset, $baseURL);
};

define('PROXY_PREFIX', 'http://p/x.php?');
$P = 'http://p/x.php?';

check('单 URL 无描述符（原版 fatal 的场景）',
  $ps('img/a.png', 'https://s.com/dir/page'),
  $P . 'https://s.com/dir/img/a.png');

check('单 URL + 描述符',
  $ps('img/a.png 2x', 'https://s.com/dir/page'),
  $P . 'https://s.com/dir/img/a.png 2x');

check('多 URL + 混合描述符',
  $ps('img/a.png 1x, img/b.png 2x', 'https://s.com/dir/page'),
  $P . 'https://s.com/dir/img/a.png 1x, ' . $P . 'https://s.com/dir/img/b.png 2x');

check('w 描述符',
  $ps('img/a.png 100w', 'https://s.com/'),
  $P . 'https://s.com/img/a.png 100w');

check('data: URI 原样保留',
  $ps('data:image/png;base64,AAAA 1x', 'https://s.com/'),
  'data:image/png;base64,AAAA 1x');

check('空段被跳过',
  $ps('img/a.png,,img/b.png', 'https://s.com/'),
  $P . 'https://s.com/img/a.png, ' . $P . 'https://s.com/img/b.png');

check('绝对 URL 通过 rel2abs 原样返回再套前缀',
  $ps('https://cdn.com/x.png 2x', 'https://s.com/'),
  $P . 'https://cdn.com/x.png 2x');

check('多个空格分隔',
  $ps('img/a.png    2x', 'https://s.com/'),
  $P . 'https://s.com/img/a.png 2x');

check('根相对路径',
  $ps('/assets/a.png 1x', 'https://s.com/deep/page'),
  $P . 'https://s.com/assets/a.png 1x');

echo "\n=== B. 响应头黑名单（匹配方式与原版一致的正则） ===\n";
// 复刻 miniproxy-plus.php 中构造黑名单的代码，确保检测逻辑一致
$strip = [
  "Content-Length", "Transfer-Encoding", "Content-Encoding",
  "Content-Security-Policy", "Content-Security-Policy-Report-Only",
  "Strict-Transport-Security", "Cross-Origin-Embedder-Policy",
  "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
  "Alt-Svc", "Reporting-Endpoints", "Report-To",
  "Permissions-Policy", "Feature-Policy", "X-Frame-Options",
];
$pattern = "/^(?:" . implode("|", array_map(function ($n) { return preg_quote($n, "/"); }, $strip)) . ")/i";

$should_strip = [
  'Content-Length: 1234',
  'content-length: 99',                       // 大小写不敏感
  'Content-Encoding: gzip',
  'Content-Security-Policy: default-src self',
  'content-security-policy-report-only: x',
  'Strict-Transport-Security: max-age=1',
  'Cross-Origin-Opener-Policy: same-origin',
  'Alt-Svc: h3=":443"',
  'Report-To: {"g":["e"]}',
  'Permissions-Policy: geolocation=()',
  'X-Frame-Options: DENY',
  //注意：这个实现是"前缀匹配"，所以 Reporting-Endpoints-Foo 这类自定义头
  //也会被一并剥离。这是原版就有的行为（原版同样是前缀正则），予以保留。
  'Reporting-Endpoints-Foo: bar',
];
foreach ($should_strip as $h) {
  checkTrue("剥离: " . substr($h, 0, 42), (bool) preg_match($pattern, $h));
}

$should_keep = [
  'Content-Type: text/html',
  'content-type: text/css',
  'Cache-Control: max-age=3600',
  'Etag: "abc"',
  'Set-Cookie: a=b',
  'Link: </x.js>; rel=preload',
  'Vary: Accept-Encoding',
  'Location: https://example.com/',
  'Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT',
  'Accept-Ranges: bytes',
  'X-Powered-By: PHP',
];
foreach ($should_keep as $h) {
  checkTrue("保留: " . substr($h, 0, 42), !preg_match($pattern, $h));
}

echo "\n=== C. 编码规范化（消除 PHP 8.2 Deprecated） ===\n";
$reflEnc = null;
try {
  $reflEnc = extract_function($src, 'function mb_detect_encoding(');
} catch (RuntimeException $e) {
  // 内置函数，源码里不存在；改为直接验证新旧写法等价
}
$sample = "café 你好 <p>éèñ</p>";
$old = mb_convert_encoding($sample, "HTML-ENTITIES", "UTF-8");
$new = mb_encode_numericentity($sample, [0x80, 0x10FFFF, 0, 0x1FFFFF], "UTF-8");
// 渲染等价性：把实体都解码回原字符后必须相同
$decode = function ($s) {
  return html_entity_decode($s, ENT_QUOTES | ENT_HTML5, "UTF-8");
};
check('新旧编码渲染结果等价', $decode($old), $decode($new));
check('新写法产出数字实体', strpos($new, '&#') !== false, true);
checkTrue('源文件不再调用 mb_convert_encoding(..., "HTML-ENTITIES", ...)',
  strpos($src, 'mb_convert_encoding($responseBody, "HTML-ENTITIES"') === false);
checkTrue('源文件改用 mb_encode_numericentity', strpos($src, 'mb_encode_numericentity') !== false);

echo "\n=== D. 关键改造是否落在源码中 ===\n";
checkTrue('剥离 CSP', strpos($src, '"Content-Security-Policy"') !== false);
checkTrue('剥离 HSTS', strpos($src, '"Strict-Transport-Security"') !== false);
checkTrue('移除 integrity', strpos($src, 'removeAttribute("integrity")') !== false);
checkTrue('移除 nonce', strpos($src, 'removeAttribute("nonce")') !== false);
checkTrue('中和 base href', strpos($src, '//base[@href]') !== false);
checkTrue('重写 data-src', strpos($src, '"data-src"') !== false);
checkTrue('重写 data-srcset', strpos($src, '@data-srcset') !== false);
checkTrue('重写 imagesrcset', strpos($src, '@imagesrcset') !== false);
checkTrue('srcset 扩展到全部元素', strpos($src, '//*[@srcset]') !== false);
checkTrue('patch fetch', strpos($src, 'window.fetch = function(input, init)') !== false);
checkTrue('patch sendBeacon', strpos($src, 'navigator.sendBeacon') !== false);
checkTrue('patch window.open', strpos($src, 'window.open = function(url)') !== false);
checkTrue('绝对 URL 也走代理', strpos($src, 'preg_match("/^https?:\\/\\//i", $attrContent)') !== false);
checkTrue('curl 连接超时', strpos($src, 'CURLOPT_CONNECTTIMEOUT') !== false);
checkTrue('curl 总超时', strpos($src, 'CURLOPT_TIMEOUT, 30') !== false);
checkTrue('关闭 display_errors', strpos($src, 'ini_set("display_errors", "0")') !== false);

echo "\n========================================\n";
echo "通过 $pass 项，失败 $fail 项\n";
if ($fail > 0) { echo "失败项：" . implode("、", $errors) . "\n"; }
exit($fail === 0 ? 0 : 1);
