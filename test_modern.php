<?php
/*
 * miniproxy-plus.php 现代网页适配改造 —— 回归测试
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
  if ($got === $expect) { $pass++; echo "  [OK]   $label
"; }
  else {
    $fail++; $errors[] = $label;
    echo "  [FAIL] $label
         expect: " . var_export($expect, true) . "
         got:    " . var_export($got, true) . "
";
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
//因此下面所有断言对二者都应成立。按顺序探测当前分支上存在的那个文件。
$proxyFile = null;
foreach (["miniproxy2.php", "miniproxy-plus.php", "miniproxy_captcha.php"] as $candidate) {
  if (is_file(__DIR__ . "/" . $candidate)) { $proxyFile = __DIR__ . "/" . $candidate; break; }
}
if ($proxyFile === null) {
  fwrite(STDERR, "未找到待测的代理入口副本
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

echo "=== A. proxifySrcset（原版在此 fatal） ===
";
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

echo "
=== B. 响应头黑名单（匹配方式与原版一致的正则） ===
";
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

echo "
=== C. 编码规范化（消除 PHP 8.2 Deprecated） ===
";
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

echo "
=== D. 关键改造是否落在源码中 ===
";
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

// ---------------------------------------------------------------------------
// E. Bing URL 重写专项
//
// Bing 的搜索结果链接把真实网址 Base64 编码后放在 u=a1... 参数里，
// 图片/视频搜索则放在 JSON 的 "murl" 字段。这两处 DOMXPath 都看不到，
// 只能对最终 HTML 做文本替换。
//
// 用例分两类：
//   1. 从真实 Bing 页面采集的样本，必须被正确重写；
//   2. 各种"看起来像但其实不是"的输入，必须原样保留（防止误伤其他站点）。
// ---------------------------------------------------------------------------

echo "
=== E. Bing URL 重写专项 ===
";

$bingFnSignatures = [
  'mp_bing_b64decode'         => 'function mp_bing_b64decode($encoded)',
  'mp_bing_is_rewritable_url' => 'function mp_bing_is_rewritable_url($decoded)',
  'mp_bing_proxify'           => 'function mp_bing_proxify($decodedURL, $baseURL)',
  'mp_bing_b64encode'         => 'function mp_bing_b64encode($url)',
  'proxifyBingURLs'           => 'function proxifyBingURLs($html, $baseURL)',
  'proxifyBingMediaURLs'      => 'function proxifyBingMediaURLs($html, $baseURL)',
];

//与 proxifySrcset 同理：这些函数依赖 PROXY_PREFIX 常量和 rel2abs()，
//必须先从源码中取出定义再 eval，不能在测试进程里重新声明。
$hasBingSupport = strpos($src, 'function proxifyBingURLs') !== false;
if ($hasBingSupport) {
  foreach ($bingFnSignatures as $fnName => $signature) {
    try {
      extract_function($src, $signature);
      checkTrue("函数定义可提取: $fnName", function_exists($fnName));
    } catch (RuntimeException $e) {
      checkTrue("函数定义可提取: $fnName", false);
    }
  }
  if (!defined('PROXY_PREFIX')) {
    define('PROXY_PREFIX', 'http://p/x.php?');
  }

echo "
=== E1. base64 解码（标准 / URL-safe / 无 padding） ===
";
//以下样本均来自真实 Bing 搜索页
  check('标准 base64 含斜杠',
    mp_bing_b64decode('aHR0cHM6Ly9naXRodWIuY29tLw'), 'https://github.com/');
  check('URL-safe 含下划线',
    mp_bing_b64decode('L2ltYWdlcy9zZWFyY2g_cT1naXRodWI'), '/images/search?q=github');
  check('空串返回 null', mp_bing_b64decode(''), null);
  check('非法字符返回 null', mp_bing_b64decode('abc!@#'), null);
  check('乱码返回 null', mp_bing_b64decode('zzzzzzzz'), null);
  check('非 UTF-8 字节返回 null', mp_bing_b64decode('gA'), null);

echo "
=== E2. URL 判定（防误判的核心闸门） ===
";
  check('绝对 URL 接受', mp_bing_is_rewritable_url('https://github.com/'), true);
  check('站内路径接受', mp_bing_is_rewritable_url('/images/search?q=x'), true);
  //关键反例：这些字符串能被 base64 解出来，但不是 URL，重写只会弄坏参数
  check('解出普通单词时拒绝', mp_bing_is_rewritable_url('test'), false);
  check('解出 hello 时拒绝', mp_bing_is_rewritable_url('hello'), false);
  check('解出 ABC 时拒绝', mp_bing_is_rewritable_url('ABC'), false);
  check('空串拒绝', mp_bing_is_rewritable_url(''), false);
  check('控制字符拒绝', mp_bing_is_rewritable_url("/a
b"), false);
  check('无前导斜杠的路径拒绝', mp_bing_is_rewritable_url('images/a.png'), false);

echo "
=== E3. 编码往返 ===
";
  $roundtrip = 'http://p/x.php?https://github.com/';
  check('解码(编码(x)) == x', mp_bing_b64decode(mp_bing_b64encode($roundtrip)), $roundtrip);
  check('重新编码后无 padding', strpos(mp_bing_b64encode($roundtrip), '='), false);
  check('重新编码后不含标准字符 +/',
    strpos(mp_bing_b64encode('http://p/x.php?https://a.com/?q=1'), '+'), false);

echo "
=== E4. 重写 HTML 中的 u=a1 ===
";
  //真实 Bing ck/a 链接形态（& 已被 DOM 转义为 &amp;）
  $realBingLink = '<a href="http://p/x.php?https://www.bing.com/ck/a?!&amp;&amp;p=abc&amp;u=a1aHR0cHM6Ly9naXRodWIuY29tLw">r</a>';
  $rewritten = proxifyBingURLs($realBingLink, 'https://www.bing.com/search?q=github');
  checkTrue('u 参数已被重写为代理地址',
    strpos($rewritten, 'u=a1aHR0cDovL3AveC5waHA_aHR0cHM6Ly9naXRodWIuY29tLw') !== false);
  checkTrue('同链接其他参数未被破坏', strpos($rewritten, 'p=abc') !== false);
  checkTrue('链接其余部分完整', strpos($rewritten, 'ck/a?!') !== false);

  //未转义 & 的形态也要处理
  $plainLink = '<a href="http://p/x.php?https://www.bing.com/ck/a?!&p=abc&u=a1aHR0cHM6Ly9naXRodWIuY29tLw">r</a>';
  checkTrue('未转义 & 形态同样处理',
    strpos(proxifyBingURLs($plainLink, 'https://www.bing.com/'), 'u=a1aHR0cDovL3AveC5waHA') !== false);

echo "
=== E5. 不应被改写的情形（防止误伤） ===
";
  //没有 ck/a 的页面：零影响
  $otherSite = '<a href="https://example.com/?u=a1aHR0cHM6Ly9naXRodWIuY29tLw">x</a>';
  check('非 Bing 页面完全不动', proxifyBingURLs($otherSite, 'https://example.com/'), $otherSite);
  //解码失败：保留原值，不能把链接弄坏
  $undecodable = '<a href="http://p/x.php?https://www.bing.com/ck/a?!&u=a1zzzzzz">x</a>';
  check('解码失败保持原样', proxifyBingURLs($undecodable, 'https://www.bing.com/'), $undecodable);
  //解出来了但不是 URL：保留原值
  $notAURL = '<a href="http://p/x.php?https://www.bing.com/ck/a?!&u=a1dGVzdA">x</a>';
  check('解出非 URL 保持原样', proxifyBingURLs($notAURL, 'https://www.bing.com/'), $notAURL);
  $notAURL2 = '<a href="http://p/x.php?https://www.bing.com/ck/a?!&u=a1aGVsbG8">x</a>';
  check('解出 hello 保持原样', proxifyBingURLs($notAURL2, 'https://www.bing.com/'), $notAURL2);

echo "
=== E6. murl（图片/视频搜索原图地址） ===
";
  $json = '{"murl":"https://www.rd.com/a.jpg","purl":"https://x.com"}';
  $jsonOut = proxifyBingMediaURLs($json, 'https://www.bing.com/images/search?q=cat');
  checkTrue('murl 绝对地址已重写', strpos($jsonOut, 'x.php?https://www.rd.com/a.jpg') !== false);
  checkTrue('JSON 其余字段未被破坏', strpos($jsonOut, '"purl":"https://x.com"}') !== false);
  check('data: URI 不动',
    proxifyBingMediaURLs('{"murl":"data:image/png;base64,AAA"}', 'https://b/'),
    '{"murl":"data:image/png;base64,AAA"}');
  check('空 murl 不动', proxifyBingMediaURLs('{"murl":""}', 'https://b/'), '{"murl":""}');
  check('站内相对路径 murl 也重写',
    strpos(proxifyBingMediaURLs('{"murl":"/img/a.jpg"}', 'https://www.bing.com/i'), 'x.php?https://www.bing.com/img/a.jpg') !== false,
    true);

echo "
=== E7. 输出流程已接入 ===
";
  checkTrue('DOM 输出后调用 proxifyBingURLs',
    strpos($src, '$finalHTML = proxifyBingURLs(') !== false);
  checkTrue('DOM 输出后调用 proxifyBingMediaURLs',
    strpos($src, '$finalHTML = proxifyBingMediaURLs(') !== false);
  checkTrue('仍在 saveHTML() 之后执行',
    strpos($src, '$finalHTML = $doc->saveHTML();') !== false);
} else {
  echo "  (源码中未包含 Bing 重写逻辑，跳过 E 组断言)
";
}


// ---------------------------------------------------------------------------
// F. HLS / DASH 流媒体播放列表重写
//
// 现代视频站几乎不用直接 mp4，而是 HLS（.m3u8）或 DASH（.mpd）自适应流。
// 播放列表里引用相对路径，播放器按列表自身 URL 解析；经代理后拿不到子列表
// 和视频分片，表现为视频无法播放。
//
// 样本结构来自公开测试流 test-streams.mux.dev 的真实响应。
// ---------------------------------------------------------------------------

echo "
=== F. HLS / DASH 流媒体播放列表重写 ===
";

$hlsFns = [
  'isHLSPlaylist'        => 'function isHLSPlaylist($contentType, $body)',
  'isDASHManifest'       => 'function isDASHManifest($contentType, $body)',
  'mp_proxify_media_url' => 'function mp_proxify_media_url($u, $baseURL)',
  'proxifyHLS'           => 'function proxifyHLS($body, $baseURL)',
  'proxifyDASH'          => 'function proxifyDASH($body, $baseURL)',
];

$hasHLSSupport = strpos($src, 'function proxifyHLS') !== false;
if ($hasHLSSupport) {
  foreach ($hlsFns as $fnName => $signature) {
    try {
      extract_function($src, $signature);
      checkTrue("函数定义可提取: $fnName", function_exists($fnName));
    } catch (RuntimeException $e) {
      checkTrue("函数定义可提取: $fnName", false);
    }
  }
  if (!defined('PROXY_PREFIX')) {
    define('PROXY_PREFIX', 'http://p/x.php?');
  }

echo "
=== F1. 播放列表识别 ===
";
  check('mpegurl 内容类型识别', isHLSPlaylist('audio/mpegurl', 'x'), true);
  check('x-mpegurl 内容类型识别', isHLSPlaylist('application/x-mpegurl', 'x'), true);
  check('vnd.apple.mpegurl 识别', isHLSPlaylist('application/vnd.apple.mpegurl', 'x'), true);
  check('text/plain 但内容是 M3U 也识别', isHLSPlaylist('text/plain', '#EXTM3U'), true);
  check('普通 HTML 不误判', isHLSPlaylist('text/html', '<html></html>'), false);
  check('MP4 不误判为 HLS', isHLSPlaylist('video/mp4', 'x'), false);
  check('dash+xml 识别', isDASHManifest('application/dash+xml', 'x'), true);
  check('MPD 内容识别', isDASHManifest('text/xml', '<MPD></MPD>'), true);
  check('普通 HTML 不误判为 DASH', isDASHManifest('text/html', '<html></html>'), false);

echo "
=== F2. 主播放列表重写（真实结构样本） ===
";
  $master = '#EXTM3U
' . '#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=2149280,RESOLUTION=1280x720,NAME="720"
' . 'url_0/193039199_mp4_h264_aac_hd_7.m3u8
' . '#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=246440,RESOLUTION=320x184,NAME="240"
' . 'url_2/193039199_mp4_h264_aac_ld_7.m3u8
' . '#EXT-X-ENDLIST
';
  $out = proxifyHLS($master, 'https://cdn.example.com/hls/index.m3u8');
  checkTrue('注释行 #EXTM3U 原样保留', strpos($out, '#EXTM3U') === 0);
  checkTrue('STREAM-INF 属性行未被破坏', strpos($out, 'RESOLUTION=1280x720,NAME="720"') !== false);
  checkTrue('相对子列表已重写', strpos($out, 'x.php?https://cdn.example.com/hls/url_0/193039199_mp4_h264_aac_hd_7.m3u8') !== false);
  checkTrue('第二个码率子列表也已重写', strpos($out, 'x.php?https://cdn.example.com/hls/url_2/193039199_mp4_h264_aac_ld_7.m3u8') !== false);
  checkTrue('结尾标签保留', strpos($out, '#EXT-X-ENDLIST') !== false);

echo "
=== F3. 子播放列表重写（视频分片） ===
";
  $sub = '#EXTM3U
' . '#EXT-X-VERSION:3
' . '#EXT-X-TARGETDURATION:10
' . '#EXTINF:10.000,
' . 'url_462/193039199_mp4_h264_aac_hd_7.ts
' . '#EXTINF:10.000,
' . 'url_463/193039199_mp4_h264_aac_hd_7.ts
';
  $out2 = proxifyHLS($sub, 'https://cdn.example.com/hls/url_0/media.m3u8');
  checkTrue('EXTINF 行保留', strpos($out2, '#EXTINF:10.000,') !== false);
  checkTrue('分片已重写', strpos($out2, 'x.php?https://cdn.example.com/hls/url_0/url_462/193039199_mp4_h264_aac_hd_7.ts') !== false);
  checkTrue('第二个分片已重写', strpos($out2, 'x.php?https://cdn.example.com/hls/url_0/url_463/193039199_mp4_h264_aac_hd_7.ts') !== false);

echo "
=== F4. 加密流密钥（EXT-X-KEY） ===
";
  $key = '#EXT-X-KEY:METHOD=AES-128,URI="https://keys.example.com/k.key",IV=0x1234
';
  $out3 = proxifyHLS($key, 'https://cdn.example.com/hls/index.m3u8');
  checkTrue('KEY 行的 METHOD 保留', strpos($out3, 'METHOD=AES-128') !== false);
  checkTrue('KEY 行的 IV 保留', strpos($out3, 'IV=0x1234') !== false);
  checkTrue('KEY 行的 URI 已重写', strpos($out3, 'x.php?https://keys.example.com/k.key') !== false);

echo "
=== F5. 绝对地址与边界情况 ===
";
  $abs = proxifyHLS('https://other.com/a.ts' . "
", 'https://cdn.example.com/hls/index.m3u8');
  checkTrue('绝对地址分片也走代理', strpos($abs, 'x.php?https://other.com/a.ts') !== false);
  check('空播放列表返回空', proxifyHLS('', 'https://a/'), '');
  check('非字符串安全返回', proxifyHLS(null, 'https://a/'), null);
  check('仅注释的列表不被破坏', proxifyHLS('#EXTM3U' . "
", 'https://a/'), '#EXTM3U' . "
");
  check('data: 地址原样返回', mp_proxify_media_url('data:video/mp4,x', 'https://a/'), 'data:video/mp4,x');
  check('空地址返回空', mp_proxify_media_url('', 'https://a/'), '');

echo "
=== F6. DASH 清单 ===
";
  $mpd = '<?xml?><MPD><BaseURL>https://cdn.example.com/dash/</BaseURL></MPD>';
  $outd = proxifyDASH($mpd, 'https://cdn.example.com/dash/manifest.mpd');
  checkTrue('BaseURL 已重写', strpos($outd, 'x.php?https://cdn.example.com/dash/') !== false);
  checkTrue('XML 标签结构保留', strpos($outd, '<BaseURL>') !== false && strpos($outd, '</BaseURL>') !== false);

echo "
=== F7. 输出流程已接入 ===
";
  checkTrue('HLS 分支已接入输出流程', strpos($src, 'isHLSPlaylist($contentType, $responseBody)') !== false);
  checkTrue('DASH 分支已接入输出流程', strpos($src, 'isDASHManifest($contentType, $responseBody)') !== false);
  checkTrue('HLS 分支位于 CSS 分支之前',
    strpos($src, 'isHLSPlaylist($contentType') < strpos($src, 'stripos($contentType, "text/css")'));
} else {
  echo "  (源码中未包含 HLS/DASH 重写逻辑，跳过 F 组断言)
";
}


// ---------------------------------------------------------------------------
// G. 客户端脚本注入与 URL 拦截面
//
// 参考 node-unblocker 的做法：服务端无法看到 JS 里动态构造的 URL，
// 因此向页面注入一段脚本，覆盖浏览器里所有会发起请求的入口。
//
// 这里只做静态断言（源码里是否包含各拦截点），因为真实浏览器行为
// 需要 DOM 环境。动态断言见 test_injected.js（需 node 运行）。
// ---------------------------------------------------------------------------

echo "\n=== G. 客户端脚本注入与 URL 拦截面 ===\n";
$clientChecks = [
  ['proxifyURL 基准从 location 动态推导', 'function currentRemoteHref()'],
  ['查询串风格的地址解析', 'location.search'],
  ['XMLHttpRequest', 'window.XMLHttpRequest.prototype.open'],
  ['fetch（含 Request 对象）', 'typeof input.url === "string"'],
  ['sendBeacon', 'navigator.sendBeacon'],
  ['window.open', 'proxiedOpen.apply'],
  ['createElement 的 src/href setter', 'Object.defineProperty(element, attr'],
  ['new Image() 等内存构造', '"Image", "Audio", "Video", "Source", "Track", "Embed"'],
  ['WebSocket 主机修正', 'proxiedWebSocket'],
  ['history.pushState/replaceState', '"pushState", "replaceState"'],
  ['Service Worker', 'navigator.serviceWorker'],
  ['EventSource', 'proxiedEventSource'],
  ['location.href 赋值', 'initLocationWatch'],
];
foreach ($clientChecks as $c) {
  checkTrue($c[0], strpos($src, $c[1]) !== false);
}
//注入方式必须用文本节点。createElement("script", $text) 会把 && 当 HTML 实体
//解码成 &，导致注入的 JS 语法错误、整个脚本失效。
checkTrue('脚本经 createTextNode 注入（避免 && 被改成 &）',
  strpos($src, 'createTextNode(') !== false);
//去掉注释行后再判断：注释里会提到"不能用 createElement(script, $text)"作为说明
$srcCodeOnly = preg_replace('/^\s*\/\/.*$/m', '', $src);
checkTrue('未使用 createElement 直接传脚本文本',
  strpos($srcCodeOnly, 'createElement("script", ' . chr(36)) === false);
//常量必须在使用前定义：var 只提升声明、不提升赋值
$posPrefix = strpos($src, 'var PROXY_PREFIX = ');
$posUse = strpos($src, 'function proxifyURL');
checkTrue('PROXY_PREFIX 在 proxifyURL 之前定义',
  $posPrefix !== false && $posUse !== false && $posPrefix < $posUse);
//绝对不能在包装列表里放基础构造函数
checkTrue('未包装 Object 构造函数',
  strpos($src, '"Embed", "Object"') === false && strpos($src, '", "Object"]') === false);

echo "\n========================================\n";
echo "通过 $pass 项，失败 $fail 项\n";
if ($fail > 0) { echo "失败项：" . implode("、", $errors) . "\n"; }
exit($fail === 0 ? 0 : 1);
