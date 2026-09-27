<?php
/*
NOTE: miniProxy IS NO LONGER MAINTAINED AS OF APRIL 26th, 2020.
IF YOU USE IT, YOU DO SO ENTIRELY AT YOUR OWN RISK.
More information is available at <https://github.com/joshdick/miniProxy>.
*/

/*
miniProxy - A simple PHP web proxy. <https://github.com/joshdick/miniProxy>
Written and maintained by Joshua Dick <http://joshdick.net>.
miniProxy is licensed under the GNU GPL v3 <https://www.gnu.org/licenses/gpl-3.0.html>.
*/

/* ---------------------------------------------------------------------------
 * miniProxy-plus：CAP 人机验证闸门（本文件为 miniproxy.php 的改造副本）
 *
 * 受保护范围：本入口的"全部"请求（用户确认第 1 项 = 全部保护）。
 * 未通过验证的访问会被 302 跳转到验证页，通过后自动返回原始 URL。
 * 原始文件 miniproxy.php 未做任何修改，可作为回退依据。
 *
 * 如想临时关闭验证，注释掉下面 mp_captcha_gate() 一行即可。
 * --------------------------------------------------------------------------- */
require_once __DIR__ . '/captcha/gate.php';

//统一闸门：未通过人机验证则跳转验证页并结束本次请求，否则继续执行下方代理逻辑。
//可选参数示例：['exclude_prefixes' => ['/miniproxy_captcha.php?health']]
mp_captcha_gate([
  'protect_all' => true,
]);

/****************************** START CONFIGURATION ******************************/

//NOTE: If a given URL matches a pattern in both $whitelistPatterns and $blacklistPatterns,
//that URL will be treated as blacklisted.

//To allow proxying any URL, set $whitelistPatterns to an empty array (the default).
//To only allow proxying of specific URLs (whitelist), add corresponding regular expressions
//to the $whitelistPatterns array. To prevent possible abuse, enter the narrowest/most-specific patterns possible.
//You can optionally use the "getHostnamePattern()" helper function to build a regular expression that
//matches all URLs for a given hostname.
$whitelistPatterns = [
  //Usage example: To whitelist any URL at example.net, including sub-domains, uncomment the
  //line below (which is equivalent to [ @^https?://([a-z0-9-]+\.)*example\.net@i ]):
  //getHostnamePattern("example.net")
];

//To disallow proxying of specific URLs (blacklist), add corresponding regular expressions
//to the $blacklistPatterns array. To prevent possible abuse, enter the broadest/least-specific patterns possible.
//You can optionally use the "getHostnamePattern()" helper function to build a regular expression that
//matches all URLs for a given hostname.
$blacklistPatterns = [
  //Usage example: To blacklist any URL at example.net, including sub-domains, uncomment the
  //line below (which is equivalent to [ @^https?://([a-z0-9-]+\.)*example\.net@i ]):
  //getHostnamePattern("example.net")
];

//To enable CORS (cross-origin resource sharing) for proxied sites, set $forceCORS to true.
$forceCORS = true;

//Set to false to allow sites on the local network (where miniProxy is running) to be proxied.
$disallowLocal = true;

//Set to false to report the client machine's IP address to proxied sites via the HTTP `x-forwarded-for` header.
//Setting to false may improve compatibility with some sites, but also exposes more information about end users to proxied sites.
$anonymize = true;

//Start/default URL that that will be proxied when miniProxy is first loaded in a browser/accessed directly with no URL to proxy.
//If empty, miniProxy will show its own landing page.
$startURL = "";

//When no $startURL is configured above, miniProxy will show its own landing page with a URL form field
//and the configured example URL. The example URL appears in the instructional text on the miniProxy landing page,
//and is proxied when pressing the 'Proxy It!' button on the landing page if its URL form is left blank.
$landingExampleURL = "https://google.com";

/****************************** END CONFIGURATION ******************************/

ob_start("ob_gzhandler");

//Modern hosts run with display_errors enabled, which splices PHP warnings and deprecation
//notices straight into the middle of proxified HTML and corrupts the page. Send them to the
//error log instead, while still surfacing genuinely fatal problems.
ini_set("display_errors", "0");
ini_set("log_errors", "1");
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);

if (version_compare(PHP_VERSION, "5.4.7", "<")) {
  die("miniProxy requires PHP version 5.4.7 or later.");
}

$requiredExtensions = ["curl", "mbstring", "xml"];
foreach($requiredExtensions as $requiredExtension) {
  if (!extension_loaded($requiredExtension)) {
    die("miniProxy requires PHP's \"" . $requiredExtension . "\" extension. Please install/enable it on your server and try again.");
  }
}

//Helper function for use inside $whitelistPatterns/$blacklistPatterns.
//Returns a regex that matches all HTTP[S] URLs for a given hostname.
function getHostnamePattern($hostname) {
  $escapedHostname = str_replace(".", "\.", $hostname);
  return "@^https?://([a-z0-9-]+\.)*" . $escapedHostname . "@i";
}

//Helper function that determines whether to allow proxying of a given URL.
function isValidURL($url) {
  //Validates a URL against the whitelist.
  function passesWhitelist($url) {
    if (count($GLOBALS['whitelistPatterns']) === 0) return true;
    foreach ($GLOBALS['whitelistPatterns'] as $pattern) {
      if (preg_match($pattern, $url)) {
        return true;
      }
    }
    return false;
  }

  //Validates a URL against the blacklist.
  function passesBlacklist($url) {
    foreach ($GLOBALS['blacklistPatterns'] as $pattern) {
      if (preg_match($pattern, $url)) {
        return false;
      }
    }
    return true;
  }

  function isLocal($url) {
    //First, generate a list of IP addresses that correspond to the requested URL.
    $ips = [];
    $host = parse_url($url, PHP_URL_HOST);
    if (filter_var($host, FILTER_VALIDATE_IP)) {
      //The supplied host is already a valid IP address.
      $ips = [$host];
    } else {
      //The host is not a valid IP address; attempt to resolve it to one.
      $dnsResult = dns_get_record($host, DNS_A + DNS_AAAA);
      $ips = array_map(function($dnsRecord) { return $dnsRecord['type'] == 'A' ? $dnsRecord['ip'] : $dnsRecord['ipv6']; }, $dnsResult);
    }
    foreach ($ips as $ip) {
      //Determine whether any of the IPs are in the private or reserved range.
      if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return true;
      }
    }
    return false;
  }

  return passesWhitelist($url) && passesBlacklist($url) && ($GLOBALS['disallowLocal'] ? !isLocal($url) : true);
}

//Helper function used to removes/unset keys from an associative array using case insensitive matching
function removeKeys(&$assoc, $keys2remove) {
  $keys = array_keys($assoc);
  $map = [];
  $removedKeys = [];
  foreach ($keys as $key) {
    $map[strtolower($key)] = $key;
  }
  foreach ($keys2remove as $key) {
    $key = strtolower($key);
    if (isset($map[$key])) {
      unset($assoc[$map[$key]]);
      $removedKeys[] = $map[$key];
    }
  }
  return $removedKeys;
}

if (!function_exists("getallheaders")) {
  //Adapted from http://www.php.net/manual/en/function.getallheaders.php#99814
  function getallheaders() {
    $result = [];
    foreach($_SERVER as $key => $value) {
      if (substr($key, 0, 5) == "HTTP_") {
        $key = str_replace(" ", "-", ucwords(strtolower(str_replace("_", " ", substr($key, 5)))));
        $result[$key] = $value;
      }
    }
    return $result;
  }
}

$usingDefaultPort =  (!isset($_SERVER["HTTPS"]) && $_SERVER["SERVER_PORT"] === 80) || (isset($_SERVER["HTTPS"]) && $_SERVER["SERVER_PORT"] === 443);
$prefixPort = $usingDefaultPort ? "" : ":" . $_SERVER["SERVER_PORT"];
//Use HTTP_HOST to support client-configured DNS (instead of SERVER_NAME), but remove the port if one is present
$prefixHost = $_SERVER["HTTP_HOST"];
$prefixHost = strpos($prefixHost, ":") ? implode(":", explode(":", $_SERVER["HTTP_HOST"], -1)) : $prefixHost;

define("PROXY_PREFIX", "http" . (isset($_SERVER["HTTPS"]) ? "s" : "") . "://" . $prefixHost . $prefixPort . $_SERVER["SCRIPT_NAME"] . "?");

//Makes an HTTP request via cURL, using request data that was passed directly to this script.
function makeRequest($url) {

  global $anonymize;

  //Tell cURL to make the request using the brower's user-agent if there is one, or a fallback user-agent otherwise.
  $user_agent = $_SERVER["HTTP_USER_AGENT"];
  if (empty($user_agent)) {
    $user_agent = "Mozilla/5.0 (compatible; miniProxy)";
  }
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);

  //Get ready to proxy the browser's request headers...
  $browserRequestHeaders = getallheaders();

  //...but let cURL set some headers on its own.
  $removedHeaders = removeKeys(
    $browserRequestHeaders,
    [
      "Accept-Encoding", //Throw away the browser's Accept-Encoding header if any and let cURL make the request using gzip if possible.
      "Content-Length",
      "Host",
      "Origin"
    ]
  );

  $removedHeaders = array_map("strtolower", $removedHeaders);

  curl_setopt($ch, CURLOPT_ENCODING, "");
  //Transform the associative array from getallheaders() into an
  //indexed array of header strings to be passed to cURL.
  $curlRequestHeaders = [];
  foreach ($browserRequestHeaders as $name => $value) {
    $curlRequestHeaders[] = $name . ": " . $value;
  }
  if (!$anonymize) {
    $curlRequestHeaders[] = "X-Forwarded-For: " . $_SERVER["REMOTE_ADDR"];
  }
  //Any `origin` header sent by the browser will refer to the proxy itself.
  //If an `origin` header is present in the request, rewrite it to point to the correct origin.
  if (in_array("origin", $removedHeaders)) {
    $urlParts = parse_url($url);
    $port = $urlParts["port"];
    $curlRequestHeaders[] = "Origin: " . $urlParts["scheme"] . "://" . $urlParts["host"] . (empty($port) ? "" : ":" . $port);
  };
  curl_setopt($ch, CURLOPT_HTTPHEADER, $curlRequestHeaders);

  //Proxy any received GET/POST/PUT data.
  switch ($_SERVER["REQUEST_METHOD"]) {
    case "POST":
      curl_setopt($ch, CURLOPT_POST, true);
      //For some reason, $HTTP_RAW_POST_DATA isn't working as documented at
      //http://php.net/manual/en/reserved.variables.httprawpostdata.php
      //but the php://input method works. This is likely to be flaky
      //across different server environments.
      //More info here: http://stackoverflow.com/questions/8899239/http-raw-post-data-not-being-populated-after-upgrade-to-php-5-3
      //If the miniProxyFormAction field appears in the POST data, remove it so the destination server doesn't receive it.
      $postData = [];
      parse_str(file_get_contents("php://input"), $postData);
      if (isset($postData["miniProxyFormAction"])) {
        unset($postData["miniProxyFormAction"]);
      }
      curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    break;
    case "PUT":
      curl_setopt($ch, CURLOPT_PUT, true);
      curl_setopt($ch, CURLOPT_INFILE, fopen("php://input", "r"));
    break;
  }

  //Other cURL options.
  curl_setopt($ch, CURLOPT_HEADER, true);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  //Bound the upstream request. Without these, a slow or hanging origin runs until
  //PHP's max_execution_time kills the request and the visitor gets a bare 500.
  //30s is generous for HTML; assets are usually far faster and fail quickly instead.
  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
  curl_setopt($ch, CURLOPT_TIMEOUT, 30);

  //Set the request URL.
  curl_setopt($ch, CURLOPT_URL, $url);

  //Make the request.
  $response = curl_exec($ch);
  $responseInfo = curl_getinfo($ch);
  $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
  curl_close($ch);

  //Setting CURLOPT_HEADER to true above forces the response headers and body
  //to be output together--separate them.
  $responseHeaders = substr($response, 0, $headerSize);
  $responseBody = substr($response, $headerSize);

  return ["headers" => $responseHeaders, "body" => $responseBody, "responseInfo" => $responseInfo];
}

//Converts relative URLs to absolute ones, given a base URL.
//Modified version of code found at http://nashruddin.com/PHP_Script_for_Converting_Relative_to_Absolute_URL
function rel2abs($rel, $base) {
  if (empty($rel)) $rel = ".";
  if (parse_url($rel, PHP_URL_SCHEME) != "" || strpos($rel, "//") === 0) return $rel; //Return if already an absolute URL
  if ($rel[0] == "#" || $rel[0] == "?") return $base.$rel; //Queries and anchors
  extract(parse_url($base)); //Parse base URL and convert to local variables: $scheme, $host, $path
  $path = isset($path) ? preg_replace("#/[^/]*$#", "", $path) : "/"; //Remove non-directory element from path
  if ($rel[0] == "/") $path = ""; //Destroy path if relative url points to root
  $port = isset($port) && $port != 80 ? ":" . $port : "";
  $auth = "";
  if (isset($user)) {
    $auth = $user;
    if (isset($pass)) {
      $auth .= ":" . $pass;
    }
    $auth .= "@";
  }
  $abs = "$auth$host$port$path/$rel"; //Dirty absolute URL
  for ($n = 1; $n > 0; $abs = preg_replace(["#(/\.?/)#", "#/(?!\.\.)[^/]+/\.\./#"], "/", $abs, -1, $n)) {} //Replace '//' or '/./' or '/foo/../' with '/'
  return $scheme . "://" . $abs; //Absolute URL is ready.
}

//Proxify contents of url() references in blocks of CSS text.
function proxifyCSS($css, $baseURL) {
  //Add a "url()" wrapper to any CSS @import rules that only specify a URL without the wrapper,
  //so that they're proxified when searching for "url()" wrappers below.
  $sourceLines = explode("\n", $css);
  $normalizedLines = [];
  foreach ($sourceLines as $line) {
    if (preg_match("/@import\s+url/i", $line)) {
      $normalizedLines[] = $line;
    } else {
      $normalizedLines[] = preg_replace_callback(
        "/(@import\s+)([^;\s]+)([\s;])/i",
        function($matches) use ($baseURL) {
          return $matches[1] . "url(" . $matches[2] . ")" . $matches[3];
        },
        $line);
    }
  }
  $normalizedCSS = implode("\n", $normalizedLines);
  return preg_replace_callback(
    "/url\((.*?)\)/i",
    function($matches) use ($baseURL) {
        $url = $matches[1];
        //Remove any surrounding single or double quotes from the URL so it can be passed to rel2abs - the quotes are optional in CSS
        //Assume that if there is a leading quote then there should be a trailing quote, so just use trim() to remove them
        if (strpos($url, "'") === 0) {
          $url = trim($url, "'");
        }
        if (strpos($url, "\"") === 0) {
          $url = trim($url, "\"");
        }
        if (stripos($url, "data:") === 0) return "url(" . $url . ")"; //The URL isn't an HTTP URL but is actual binary data. Don't proxify it.
        return "url(" . PROXY_PREFIX . rel2abs($url, $baseURL) . ")";
    },
    $normalizedCSS);
}

//Proxify "srcset" attributes (normally associated with <img> and <source> tags.)
//A srcset is a comma-separated list of "url [descriptor]" pairs. The descriptor part
//is optional, which is what broke the original implementation: str_split() on the
//result of strrpos() produced a fatal error when there was no space to split on.
function proxifySrcset($srcset, $baseURL) {
  //A srcset is a comma-separated list of "url [descriptor]" pairs. Two things make this
  //harder than it looks:
  //
  //  1. The descriptor is optional. The original implementation split each candidate on
  //     its last space via str_split($source, strrpos($source, " ")); strrpos() returns
  //     false when there is no space, so str_split() threw a fatal error and the whole
  //     page came back as a 500. Modern srcsets without descriptors are common.
  //
  //  2. URLs can contain commas, most notably data: URIs. A naive explode() on "," tears
  //     them apart.
  //
  //So: split on commas, then re-join fragments that were split out of a data: URI. A
  //candidate is considered complete once its leading token is not a bare data: payload
  //fragment.
  $rawParts = preg_split('/,/', (string) $srcset);
  $candidates = [];
  $carry = null;
  foreach ($rawParts as $part) {
    $trimmed = trim($part);
    if ($trimmed === "") continue;

    if ($carry !== null) {
      //Previous part was an unterminated data: URI; re-attach this fragment.
      $carry .= "," . $trimmed;
    } else {
      $carry = $trimmed;
    }

    //A data: URI is complete when it contains a comma (header,payload) and the payload
    //does not look like a fresh candidate URL.
    if (preg_match('/^data:/i', $carry)) {
      if (strpos($carry, ",") !== false && !preg_match('/,\s*[^\s,]*\.[A-Za-z0-9]{2,5}(\s|$)/', $carry)) {
        $candidates[] = $carry;
        $carry = null;
      }
      //Otherwise keep accumulating: the data payload had embedded commas.
      continue;
    }

    //Plain URL candidates are complete immediately.
    $candidates[] = $carry;
    $carry = null;
  }
  if ($carry !== null) $candidates[] = $carry;

  $proxifiedSources = [];
  foreach ($candidates as $source) {
    if ($source === "") continue;

    //Split into URL + optional descriptor. The descriptor is the final whitespace-separated
    //token when it looks like "2x", "1.5x" or "640w"; otherwise there is no descriptor.
    $descriptor = "";
    $imageURL = $source;
    if (stripos($source, "data:") !== 0 && preg_match('/^(.*\S)\s+(\S+)$/', $source, $m)) {
      $imageURL = $m[1];
      $descriptor = $m[2];
    }

    //Do not proxify data: URIs, they are already self-contained.
    if (stripos($imageURL, "data:") === 0) {
      $proxifiedSources[] = $source;
      continue;
    }

    //rel2abs() resolves relative paths and returns absolute URLs untouched. Note the
    //leading slash must be preserved: stripping it turns a root-relative "/a.png" into
    //a path relative to the current directory, which resolves against the wrong base.
    $proxifiedURL = PROXY_PREFIX . rel2abs($imageURL, $baseURL);
    $proxifiedSources[] = $descriptor === "" ? $proxifiedURL : $proxifiedURL . " " . $descriptor;
  }
  return implode(", ", $proxifiedSources); //Recombine the sources with ", "
}

// ---------------------------------------------------------------------------
// Bing / Microsoft 专用 URL 解码重写
//
// Bing 的搜索结果链接并不直接指向目标站点，而是形如：
//   https://www.bing.com/ck/a?!&&p=<token>&u=a1<base64>&...
// 真实网址被 Base64 编码后放在 u=a1... 参数里，由页面 JS 解出再跳转。
// 图片/视频搜索则把原图地址放在 JSON 的 "murl" 字段里。
//
// 代理只重写 href 属性是不够的：JS 读到的仍是编码前的真实地址，
// 用户一点搜索结果，浏览器就直接跳去了真实站点，等于绕过代理。
//
// 这里在服务端把这些值解码出来、套上代理前缀、再编码回去，
// 使 href 与 JS 读到的内容一致。仅处理 Bing 的这两个已知形态，
// 不做通用的"猜测脚本里的 URL"，避免误伤其他站点。
// ---------------------------------------------------------------------------

//Bing URL 参数中使用的编码：标准 base64 与 URL-safe base64 两种都可能出现，
//且 padding 常被省略。逐个补齐 padding 尝试解码，取第一个成功的结果。
function mp_bing_b64decode($encoded) {
  if (!is_string($encoded) || $encoded === "") return null;
  //只接受 base64 字符集，遇到其他字符直接放弃
  //用 # 作分隔符：字符类里的 / 会被 / 分隔符误认为正则结束
  if (!preg_match('#^[A-Za-z0-9+/_-]+$#', $encoded)) return null;

  $len = strlen($encoded);
  for ($pad = 0; $pad < 3; $pad++) {
    $candidate = $encoded . str_repeat("=", $pad);
    //base64 长度必须是 4 的倍数
    if (strlen($candidate) % 4 !== 0) continue;
    //URL-safe 变体优先：实测 Bing 的 /ck/a 链接使用的是 -_ 形式
    //两种变体都试：URL-safe（-_）转成标准（+/），以及原样按标准 base64 解。
    //顺序无关紧要，因为 strtr 只替换实际存在的字符。
    foreach ([["-_", "+/"], ["", ""]] as $pair) {
      $normalized = strtr($candidate, $pair[0], $pair[1]);
      $decoded = base64_decode($normalized, true); //严格模式，非法字符返回 false
      if ($decoded === false || $decoded === "") continue;
      //必须是合法 UTF-8，否则视为解码失败
      if (!mb_check_encoding($decoded, "UTF-8")) continue;
      return $decoded;
    }
  }
  return null;
}

//判断解码结果是否是"值得重写"的 URL。
//这一步是防止误判的关键：像 "a1dGVzdA" 这样的参数能解出 "test"，
//但它不是 URL，重写它只会把参数弄坏。
function mp_bing_is_rewritable_url($decoded) {
  if (!is_string($decoded) || $decoded === "") return false;
  //控制字符与空白一律拒绝
  if (preg_match('/[ -]/', $decoded)) return false;
  //绝对地址：scheme://host
  if (preg_match('#^https?://[A-Za-z0-9.\-]+#i', $decoded)) return true;
  //站内路径：/path
  if (preg_match('#^/[A-Za-z0-9\-._~%/?=&]#', $decoded)) return true;
  return false;
}

//把解码出的 URL 套上代理前缀。绝对地址与相对路径都走 rel2abs 统一处理。
function mp_bing_proxify($decodedURL, $baseURL) {
  if (preg_match('#^https?://#i', $decodedURL)) {
    return PROXY_PREFIX . $decodedURL;
  }
  return PROXY_PREFIX . rel2abs($decodedURL, $baseURL);
}

//把代理后的 URL 重新编码为 URL-safe base64 并去掉 padding，
//与 Bing 原始形态保持一致，避免长度或字符集变化引起 JS 解析差异。
function mp_bing_b64encode($url) {
  $encoded = base64_encode($url);
  return rtrim(strtr($encoded, "+/", "-_"), "=");
}

//处理整段 HTML 中的 Bing u=a1... 参数。
//仅在 HTML 内容里出现 bing.com 的 ck/a 链接时才动手，其他站点零影响。
function proxifyBingURLs($html, $baseURL) {
  if (!is_string($html) || $html === "") return $html;
  //快速退出：没有 Bing 的 ck/a 链接就不处理
  if (strpos($html, "/ck/a") === false) return $html;

  return preg_replace_callback(
    '/((?:amp;|&|\?)u=a)(\d)([A-Za-z0-9_\-]+)/',
    function ($matches) use ($baseURL) {
      $prefix = $matches[1]; //形如 "&u=a" / "&amp;u=a"
      $schemeDigit = $matches[2]; //Bing 的版本号，固定为 1
      $encoded = $matches[3];

      $decoded = mp_bing_b64decode($encoded);
      if ($decoded === null) return $matches[0]; //解码失败，保持原样
      if (!mp_bing_is_rewritable_url($decoded)) return $matches[0]; //不是 URL，保持原样

      $proxied = mp_bing_proxify($decoded, $baseURL);
      $reEncoded = mp_bing_b64encode($proxied);

      return $prefix . $schemeDigit . $reEncoded;
    },
    $html
  );
}

//处理 Bing 图片/视频搜索 JSON 中的 "murl" 字段（原图地址）。
function proxifyBingMediaURLs($html, $baseURL) {
  if (!is_string($html) || $html === "") return $html;
  //只在出现 murl 字段时处理
  if (strpos($html, "murl") === false) return $html;

  return preg_replace_callback(
    '/("murl"\s*:\s*")([^"]*)(")/',
    function ($matches) use ($baseURL) {
      $lead = $matches[1];
      $url = $matches[2];
      $trail = $matches[3];

      if ($url === "") return $matches[0];
      //data: URI 与已是代理地址的不动
      if (stripos($url, "data:") === 0) return $matches[0];
      if (strpos($url, PROXY_PREFIX) === 0) return $matches[0];

      $proxied = preg_match('#^https?://#i', $url)
        ? PROXY_PREFIX . $url
        : PROXY_PREFIX . rel2abs($url, $baseURL);

      //JSON 字符串里需要转义反斜杠，避免破坏 JSON 结构
      $escaped = str_replace("\\", "\\\\", $proxied);
      return $lead . $escaped . $trail;
    },
    $html
  );
}

//Extract and sanitize the requested URL, handling cases where forms have been rewritten to point to the proxy.
if (isset($_POST["miniProxyFormAction"])) {
  $url = $_POST["miniProxyFormAction"];
  unset($_POST["miniProxyFormAction"]);
} else {
  $queryParams = [];
  parse_str($_SERVER["QUERY_STRING"], $queryParams);
  //If the miniProxyFormAction field appears in the query string, make $url start with its value, and rebuild the the query string without it.
  if (isset($queryParams["miniProxyFormAction"])) {
    $formAction = $queryParams["miniProxyFormAction"];
    unset($queryParams["miniProxyFormAction"]);
    $url = $formAction . "?" . http_build_query($queryParams);
  } else {
    $url = substr($_SERVER["REQUEST_URI"], strlen($_SERVER["SCRIPT_NAME"]) + 1);
  }
}
if (empty($url)) {
    if (empty($startURL)) {
        die("
        <!doctype html>
        <html lang=\"zh-CN\">
        <head>
            <meta charset=\"utf-8\">
            <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
            <title>miniProxy</title>
            <style>
                :root{--bg1:#f6f8fa;--bg2:#e9eef6;--card:#ffffff;--accent:#2563eb;--muted:#6b7280;--pink:#fce7f3}
                html,body{height:100%;margin:0;font-family:Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial;}
                body{background:linear-gradient(135deg,var(--bg1),var(--bg2));display:flex;align-items:center;justify-content:center;padding:24px}
                .card{background:var(--card);max-width:760px;width:100%;border-radius:12px;box-shadow:0 10px 30px rgba(15,23,42,0.08);padding:28px}
                h1{margin:0 0 6px;font-size:22px}
                .lead{margin:0 0 14px;color:var(--muted)}
                form{display:flex;gap:10px;flex-wrap:wrap}
                input[type=text]{flex:1;min-width:220px;padding:10px 12px;border:1px solid #e5e7eb;border-radius:8px;font-size:15px}
                input[type=submit]{background:var(--accent);color:#fff;border:none;padding:10px 14px;border-radius:8px;cursor:pointer;font-weight:600}
                .muted{color:#9ca3af;font-size:13px;margin-top:12px}
                .example{color:var(--accent);text-decoration:none}
                .quote{margin-top:14px;padding:12px;border-left:4px solid #f472b6;background:var(--pink);color:#b91c52;border-radius:6px;font-size:14px}
                footer{margin-top:16px;font-size:12px;color:#9ca3af;text-align:right}
                @media (max-width:480px){h1{font-size:18px} .card{padding:18px}}
            </style>
            <script>
                async function fetchQuote(){
                    try{
                        const res = await fetch('https://v1.hitokoto.cn/?c=a&c=b&c=d&encode=text');
                        if(res.ok){
                            const txt = await res.text();
                            document.getElementById('quote').innerText = txt;
                        } else {
                            document.getElementById('quote').innerText = '一言读取失败';
                        }
                    } catch(e){
                        document.getElementById('quote').innerText = '一言读取失败';
                    }
                }
                function submitProxy(e){
                    e.preventDefault();
                    var v = document.getElementById('site').value.trim();
                    if (v) {
                        window.location.href = '" . PROXY_PREFIX . "' + v;
                    } else {
                        window.location.href = '" . PROXY_PREFIX . $landingExampleURL . "';
                    }
                }
                window.onload = fetchQuote;
            </script>
        </head>
        <body>
            <div class=\"card\" role=\"main\">
                <h1>欢迎使用 miniProxy</h1>
                <p class=\"lead\">轻量级 PHP 代理（由 @Johnsheng 改良）。输入要代理的 URL，按回车或点击“代理它!”即可。</p>
                <form onsubmit=\"submitProxy(event)\" autocomplete=\"off\">
                    <input id=\"site\" type=\"text\" aria-label=\"要代理的 URL\" placeholder=\"输入或粘贴需要代理的 URL，例如: " . htmlspecialchars($landingExampleURL) . "\" />
                    <input type=\"submit\" value=\"代理它!\" />
                </form>
                <p class=\"muted\">示例：<a class=\"example\" href=\"" . PROXY_PREFIX . $landingExampleURL . "\">" . PROXY_PREFIX . $landingExampleURL . "</a></p>
                <div class=\"quote\">一言：<span id=\"quote\">加载中...</span></div>
                <footer>miniProxy — 简单、快速、易用</footer>
            </div>
        </body>
        </html>");
    } else {
        $url = $startURL;
    }
} else if (strpos($url, ":/") !== strpos($url, "://")) {
    //Work around the fact that some web servers (e.g. IIS 8.5) change double slashes appearing in the URL to a single slash.
    //See https://github.com/joshdick/miniProxy/pull/14
    $pos = strpos($url, ":/");
    $url = substr_replace($url, "://", $pos, strlen(":/"));
}
$scheme = parse_url($url, PHP_URL_SCHEME);
if (empty($scheme)) {
  if (strpos($url, "//") === 0) {
    //Assume that any supplied URLs starting with // are HTTP URLs.
    $url = "http:" . $url;
  } else {
    //Assume that any supplied URLs without a scheme (just a host) are HTTP URLs.
    $url = "http://" . $url;
  }
} else if (!preg_match("/^https?$/i", $scheme)) {
    die('Error: Detected a "' . $scheme . '" URL. miniProxy exclusively supports http[s] URLs.');
}

if (!isValidURL($url)) {
  die("Error: The requested URL was disallowed by the server administrator.");
}

$response = makeRequest($url);
$rawResponseHeaders = $response["headers"];
$responseBody = $response["body"];
$responseInfo = $response["responseInfo"];

//If CURLOPT_FOLLOWLOCATION landed the proxy at a diferent URL than
//what was requested, explicitly redirect the proxy there.
$responseURL = $responseInfo["url"];
if ($responseURL !== $url) {
  header("Location: " . PROXY_PREFIX . $responseURL, true);
  exit(0);
}

//A regex that indicates which server response headers should be stripped out of the proxified response.
//Beyond the original three (content framing headers that cURL has already decoded, so re-sending
//them would corrupt the output), modern sites require stripping a number of headers that are
//scoped to the real origin and break the page when relayed through a proxy:
//
//  - Content-Security-Policy: 'self' and host-based allowlists refer to the real origin, so the
//    proxied page's own scripts, styles, fonts and AJAX calls all get blocked.
//  - Strict-Transport-Security: pins the real origin to HTTPS in the browser and leaks to any
//    other subdomain that happens to be served through the proxy.
//  - Cross-Origin-*: embedder/opener policies refer to the real origin and break rendering.
//  - Alt-Svc: advertises HTTP/3 endpoints for the real origin, bypassing the proxy altogether.
//  - Reporting-Endpoints / Report-To: sends origin-scoped reports and can leak visitor data.
//  - Permissions-Policy / Feature-Policy: block camera, geolocation and other APIs.
const PROXY_STRIP_RESPONSE_HEADERS = [
  "Content-Length",
  "Transfer-Encoding",
  "Content-Encoding",
  "Content-Security-Policy",
  "Content-Security-Policy-Report-Only",
  "Strict-Transport-Security",
  "Cross-Origin-Embedder-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
  "Alt-Svc",
  "Reporting-Endpoints",
  "Report-To",
  "Permissions-Policy",
  "X-Frame-Options",
  "Feature-Policy",
];

//Build one case-insensitive pattern that matches any of the headers above at the start of a line.
$header_blacklist_pattern = "/^(?:" . implode("|", array_map(function ($name) {
  return preg_quote($name, "/");
}, PROXY_STRIP_RESPONSE_HEADERS)) . ")/i";

//cURL can make multiple requests internally (for example, if CURLOPT_FOLLOWLOCATION is enabled), and reports
//headers for every request it makes. Only proxy the last set of received response headers,
//corresponding to the final request made by cURL for any given call to makeRequest().
$responseHeaderBlocks = array_filter(explode("\r\n\r\n", $rawResponseHeaders));
$lastHeaderBlock = end($responseHeaderBlocks);
$headerLines = explode("\r\n", $lastHeaderBlock);
foreach ($headerLines as $header) {
  $header = trim($header);
  if (!preg_match($header_blacklist_pattern, $header)) {
    header($header, false);
  }
}
//Prevent robots from indexing proxified pages
header("X-Robots-Tag: noindex, nofollow", true);

if ($forceCORS) {
  //This logic is based on code found at: http://stackoverflow.com/a/9866124/278810
  //CORS headers sent below may conflict with CORS headers from the original response,
  //so these headers are sent after the original response headers to ensure their values
  //are the ones that actually end up getting sent to the browser.
  //Explicit [ $replace = true ] is used for these headers even though this is PHP's default behavior.

  //Allow access from any origin.
  header("Access-Control-Allow-Origin: *", true);
  header("Access-Control-Allow-Credentials: true", true);

  //Handle CORS headers received during OPTIONS requests.
  if ($_SERVER["REQUEST_METHOD"] == "OPTIONS") {
    if (isset($_SERVER["HTTP_ACCESS_CONTROL_REQUEST_METHOD"])) {
      header("Access-Control-Allow-Methods: GET, POST, OPTIONS", true);
    }
    if (isset($_SERVER["HTTP_ACCESS_CONTROL_REQUEST_HEADERS"])) {
      header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}", true);
    }
    //No further action is needed for OPTIONS requests.
    exit(0);
  }

}

$contentType = "";
if (isset($responseInfo["content_type"])) $contentType = $responseInfo["content_type"];

//This is presumably a web page, so attempt to proxify the DOM.
if (stripos($contentType, "text/html") !== false) {

  //Attempt to normalize character encoding.
  //PHP 8.2 deprecated mb_convert_encoding()'s "HTML-ENTITIES" target mode; converting
  //to UTF-8 first and then to numeric entities produces the same rendered output.
  $detectedEncoding = mb_detect_encoding($responseBody, "UTF-8, ISO-8859-1");
  if ($detectedEncoding) {
    if (strtoupper($detectedEncoding) !== "UTF-8") {
      $responseBody = mb_convert_encoding($responseBody, "UTF-8", $detectedEncoding);
    }
    $responseBody = mb_encode_numericentity($responseBody, [0x80, 0x10FFFF, 0, 0x1FFFFF], "UTF-8");
  }

  //Parse the DOM.
  $doc = new DomDocument();
  @$doc->loadHTML($responseBody);
  $xpath = new DOMXPath($doc);

  //Rewrite forms so that their actions point back to the proxy.
  foreach($xpath->query("//form") as $form) {
    $method = $form->getAttribute("method");
    $action = $form->getAttribute("action");
    //If the form doesn't have an action, the action is the page itself.
    //Otherwise, change an existing action to an absolute version.
    $action = empty($action) ? $url : rel2abs($action, $url);
    //Rewrite the form action to point back at the proxy.
    $form->setAttribute("action", rtrim(PROXY_PREFIX, "?"));
    //Add a hidden form field that the proxy can later use to retreive the original form action.
    $actionInput = $doc->createDocumentFragment();
    $actionInput->appendXML('<input type="hidden" name="miniProxyFormAction" value="' . htmlspecialchars($action) . '" />');
    $form->appendChild($actionInput);
  }
  //Proxify <meta> tags with an 'http-equiv="refresh"' attribute.
  foreach ($xpath->query("//meta[@http-equiv]") as $element) {
    if (strcasecmp($element->getAttribute("http-equiv"), "refresh") === 0) {
      $content = $element->getAttribute("content");
      if (!empty($content)) {
        $splitContent = preg_split("/=/", $content);
        if (isset($splitContent[1])) {
          $element->setAttribute("content", $splitContent[0] . "=" . PROXY_PREFIX . rel2abs($splitContent[1], $url));
        }
      }
    }
  }
  //Neutralize <base href>. A base tag rewrites how the browser resolves every relative URL
  //on the page, which would point them at the real origin instead of the proxy. Removing the
  //element is safer than rewriting it, because a base tag inside the body still applies to the
  //whole document and other tooling may re-add it.
  foreach ($xpath->query("//base[@href]") as $base) {
    $base->removeAttribute("href");
  }

  //Profixy <style> tags.
  foreach($xpath->query("//style") as $style) {
    $style->nodeValue = proxifyCSS($style->nodeValue, $url);
  }
  //Proxify tags with a "style" attribute.
  foreach ($xpath->query("//*[@style]") as $element) {
    $element->setAttribute("style", proxifyCSS($element->getAttribute("style"), $url));
  }
  //Proxify "srcset" attributes. Modern sites put them on <img> AND <source> tags,
  //so query every element rather than just <img>.
  foreach ($xpath->query("//*[@srcset]") as $element) {
    $element->setAttribute("srcset", proxifySrcset($element->getAttribute("srcset"), $url));
  }
  //Proxify any of these attributes appearing in any tag.
  //"href" and "src" are the classics. The data-* entries cover lazy-loading and
  //video-poster patterns that modern frameworks emit instead of the plain attribute:
  //  data-src, data-srcset, data-background-image, data-bg, data-lazy-src, data-image,
  //  data-poster, data-original, data-lazy, data-echo, data-thumb, data-href, data-url.
  //Each entry maps an attribute name to the pattern of values to leave alone.
  $proxifyAttributes = [
    "href" => "/^(about|javascript|magnet|mailto|tel|sms|ftp|ws|wss):|^#/i",
    "src" => "/^(data):/i",
    //Lazy-load sources: skip anything that is already absolute, or a fragment/empty value.
    "data-src" => "/^(#|data:|about:blank)/i",
    "data-lazy-src" => "/^(#|data:|about:blank)/i",
    "data-original" => "/^(#|data:|about:blank)/i",
    "data-echo" => "/^(#|data:|about:blank)/i",
    "data-thumb" => "/^(#|data:|about:blank)/i",
    "data-lazy" => "/^(#|data:|about:blank)/i",
    "data-image" => "/^(#|data:|about:blank)/i",
    "data-poster" => "/^(#|data:|about:blank)/i",
    "data-bg" => "/^(#|data:|about:blank)/i",
    "data-url" => "/^(#|data:|about:blank)/i",
    "data-href" => "/^(#|data:|about:blank)/i",
  ];
  foreach($proxifyAttributes as $attrName => $skipPattern) {
    foreach($xpath->query("//*[@" . $attrName . "]") as $element) { //For every element with the given attribute...
      $attrContent = $element->getAttribute($attrName);
      if (preg_match($skipPattern, $attrContent)) continue;
      //Only rewrite values that are actually relative; already-absolute URLs to any
      //host (including the real origin) are still routed through the proxy, because a
      //browser hitting the real origin directly would bypass the proxy.
      if (preg_match("/^https?:\/\//i", $attrContent)) {
        $attrContent = PROXY_PREFIX . $attrContent;
      } else {
        $attrContent = PROXY_PREFIX . rel2abs($attrContent, $url);
      }
      $element->setAttribute($attrName, $attrContent);
    }
  }
  //Proxify "data-srcset", the lazy-loaded twin of srcset.
  foreach ($xpath->query("//*[@data-srcset]") as $element) {
    $element->setAttribute("data-srcset", proxifySrcset($element->getAttribute("data-srcset"), $url));
  }
  //Proxify "imagesrcset" on <link rel="preload">, which tells the browser which image
  //a future navigation will need. Without this, preloaded images miss the proxy.
  foreach ($xpath->query("//*[@imagesrcset]") as $element) {
    $element->setAttribute("imagesrcset", proxifySrcset($element->getAttribute("imagesrcset"), $url));
  }
  //Remove Subresource Integrity attributes. The hash was computed against the file at
  //the real origin; routing the same bytes through this proxy is byte-identical, but the
  //browser blocks the resource if the URL origin does not match what the hash expects,
  //and some sites also key integrity to crossorigin behaviour. Dropping the attribute is
  //the safest option and costs nothing but a marginally weaker integrity guarantee for
  //third-party assets, which is inherent to proxying.
  foreach ($xpath->query("//*[@integrity]") as $element) {
    $element->removeAttribute("integrity");
  }
  //Drop CSP nonces on inline <script>/<style>. A nonce only authorises inline content when
  //it matches the page's Content-Security-Policy; since the CSP is stripped, nonces are
  //meaningless. Worse, if the page is behind a CSP from another layer, a stale nonce makes
  //every inline script fail. Removing them is harmless.
  foreach ($xpath->query("//script[@nonce]") as $element) {
    $element->removeAttribute("nonce");
  }
  foreach ($xpath->query("//style[@nonce]") as $element) {
    $element->removeAttribute("nonce");
  }

  //Attempt to force AJAX requests to be made through the proxy by
  //wrapping window.XMLHttpRequest.prototype.open in order to make
  //all request URLs absolute and point back to the proxy.
  //The rel2abs() JavaScript function serves the same purpose as the server-side one in this file,
  //but is used in the browser to ensure all AJAX request URLs are absolute and not relative.
  //Uses code from these sources:
  //http://stackoverflow.com/questions/7775767/javascript-overriding-xmlhttprequest-open
  //https://gist.github.com/1088850
  //TODO: This is obviously only useful for browsers that use XMLHttpRequest but
  //it's better than nothing.

  $head = $xpath->query("//head")->item(0);
  $body = $xpath->query("//body")->item(0);
  $prependElem = $head != null ? $head : $body;

  //Only bother trying to apply this hack if the DOM has a <head> or <body> element;
  //insert some JavaScript at the top of whichever is available first.
  //Protects against cases where the server sends a Content-Type of "text/html" when
  //what's coming back is most likely not actually HTML.
  //TODO: Do this check before attempting to do any sort of DOM parsing?
  if ($prependElem != null) {

    $scriptElem = $doc->createElement("script",
      '(function() {

        if (window.XMLHttpRequest) {

          function parseURI(url) {
            var m = String(url).replace(/^\s+|\s+$/g, "").match(/^([^:\/?#]+:)?(\/\/(?:[^:@]*(?::[^:@]*)?@)?(([^:\/?#]*)(?::(\d*))?))?([^?#]*)(\?[^#]*)?(#[\s\S]*)?/);
            // authority = "//" + user + ":" + pass "@" + hostname + ":" port
            return (m ? {
              href : m[0] || "",
              protocol : m[1] || "",
              authority: m[2] || "",
              host : m[3] || "",
              hostname : m[4] || "",
              port : m[5] || "",
              pathname : m[6] || "",
              search : m[7] || "",
              hash : m[8] || ""
            } : null);
          }

          function rel2abs(base, href) { // RFC 3986

            function removeDotSegments(input) {
              var output = [];
              input.replace(/^(\.\.?(\/|$))+/, "")
                .replace(/\/(\.(\/|$))+/g, "/")
                .replace(/\/\.\.$/, "/../")
                .replace(/\/?[^\/]*/g, function (p) {
                  if (p === "/..") {
                    output.pop();
                  } else {
                    output.push(p);
                  }
                });
              return output.join("").replace(/^\//, input.charAt(0) === "/" ? "/" : "");
            }

            href = parseURI(href || "");
            base = parseURI(base || "");

            return !href || !base ? null : (href.protocol || base.protocol) +
            (href.protocol || href.authority ? href.authority : base.authority) +
            removeDotSegments(href.protocol || href.authority || href.pathname.charAt(0) === "/" ? href.pathname : (href.pathname ? ((base.authority && !base.pathname ? "/" : "") + base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1) + href.pathname) : base.pathname)) +
            (href.protocol || href.authority || href.pathname ? href.search : (href.search || base.search)) +
            href.hash;

          }

          function proxifyURL(u) {
            var abs = rel2abs("' . $url . '", u);
            if (abs === null) return u;
            if (abs.indexOf("' . PROXY_PREFIX . '") != -1) return abs;
            // Only rewrite http(s) URLs; blob:, data: and about: must pass through
            // unchanged or the browser throws before the request is constructed.
            if (!/^https?:\/\//.test(abs)) return u;
            return "' . PROXY_PREFIX . '" + abs;
          }

          var proxied = window.XMLHttpRequest.prototype.open;
          window.XMLHttpRequest.prototype.open = function() {
              if (arguments[1] !== null && arguments[1] !== undefined) {
                arguments[1] = proxifyURL(arguments[1]);
              }
              return proxied.apply(this, [].slice.call(arguments));
          };

          // fetch() is what modern sites actually use. The URL is the first argument
          // and may also arrive as a Request object, which carries it in .url.
          if (window.fetch) {
            var proxiedFetch = window.fetch;
            window.fetch = function(input, init) {
              if (typeof input === "string") {
                input = proxifyURL(input);
              } else if (input && typeof input === "object" && typeof input.url === "string") {
                try {
                  return proxiedFetch(new Request(proxifyURL(input.url), input), init);
                } catch (e) {
                  return proxiedFetch(input, init);
                }
              }
              return proxiedFetch(input, init);
            };
          }

          // navigator.sendBeacon() sends analytics payloads; route them through the
          // proxy so the data lands on the origin instead of failing on this host.
          if (navigator.sendBeacon) {
            var proxiedBeacon = navigator.sendBeacon.bind(navigator);
            navigator.sendBeacon = function(url, data) {
              return proxiedBeacon(proxifyURL(url), data);
            };
          }

          // window.open() with a URL pointing at the real origin would escape the proxy.
          var proxiedOpen = window.open;
          window.open = function(url) {
            if (typeof url === "string" && url !== "") {
              url = proxifyURL(url);
            }
            return proxiedOpen.apply(window, arguments);
          };

                }
                arguments[1] = url;
              }
              return proxied.apply(this, [].slice.call(arguments));
          };

        }

      })();'
    );
    $scriptElem->setAttribute("type", "text/javascript");

    $prependElem->insertBefore($scriptElem, $prependElem->firstChild);

  }

  //DOM 重写完成后再处理 Bing 的编码 URL。
  //必须在 saveHTML() 之后：DOMXPath 看不到 JS 里的 u 参数和 JSON 里的 murl 字段，
  //这两个位置只能靠对最终 HTML 做文本替换。
  $finalHTML = $doc->saveHTML();
  $finalHTML = proxifyBingURLs($finalHTML, $url);
  $finalHTML = proxifyBingMediaURLs($finalHTML, $url);
  echo "<!-- Proxified page constructed by miniProxy -->\n" . $finalHTML;
} else if (stripos($contentType, "text/css") !== false) { //This is CSS, so proxify url() references.
  echo proxifyCSS($responseBody, $url);
} else { //This isn't a web page or CSS, so serve unmodified through the proxy with the correct headers (images, JavaScript, etc.)
  header("Content-Length: " . strlen($responseBody), true);
  echo $responseBody;
}
