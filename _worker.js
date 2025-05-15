/**
 * CF-Workers-SUB - A Cloudflare Workers based subscription aggregator
 *
 * This worker provides functionality to aggregate and convert subscription links
 * for various proxy clients. It supports authentication, KV storage, and
 * multiple subscription formats.
 */

// Configuration variables
const CONFIG = {
  // Authentication settings
  auth: {
    token: 'auto',                // Main access token
    guestToken: '',               // Guest token (can be generated with UUID)
    username: 'admin',            // Default admin username
    password: 'admin',            // Default admin password
    enabled: true                 // Whether authentication is enabled
  },

  // Telegram notification settings
  telegram: {
    botToken: '',                 // Telegram bot token (optional)
    chatId: '',                   // Telegram chat ID (optional)
    notifyAll: 0                  // 0: Only notify subscription access, 1: Notify all access
  },

  // Subscription settings
  subscription: {
    name: 'CF-Workers-SUB',       // Subscription name
    updateInterval: 6,            // Update interval in hours
    total: 99,                    // Total traffic in TB
    expireTimestamp: 4102329600000, // Expiration timestamp (2099-12-31)

    // Subscription converter settings
    converter: {
      api: "SUBAPI.cmliussss.net", // Subscription conversion backend
      config: "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini",
      protocol: 'https'           // Protocol for subscription converter
    }
  },

  // KV namespace settings
  kv: {
    namespace: 'KV'               // Default KV namespace name
  }
};

// Initial subscription data
let mainData = `
https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray
`;

// Initialize empty URLs array
let urls = [];

/**
 * Main worker handler
 */
export default {
  async fetch(request, env) {
    // Parse request information
    const userAgentHeader = request.headers.get('User-Agent');
    const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";
    const url = new URL(request.url);
    const token = url.searchParams.get('token');

    // Load environment variables or use defaults
    loadEnvironmentVariables(env);

    // Load authentication credentials
    const { username, password } = await loadCredentials(env, CONFIG.kv.namespace);
    CONFIG.auth.username = username || CONFIG.auth.username;
    CONFIG.auth.password = password || CONFIG.auth.password;

    // Generate tokens
    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    const timeTemp = Math.ceil(currentDate.getTime() / 1000);
    const fakeToken = await generateMD5Hash(`${CONFIG.auth.token}${timeTemp}`);

    if (!CONFIG.auth.guestToken) {
      CONFIG.auth.guestToken = await generateMD5Hash(CONFIG.auth.token);
    }

    // Calculate traffic data
    const usedData = Math.floor(((CONFIG.subscription.expireTimestamp - Date.now()) /
                      CONFIG.subscription.expireTimestamp * CONFIG.subscription.total * 1099511627776) / 2);
    const totalData = CONFIG.subscription.total * 1099511627776;
    const expireTime = Math.floor(CONFIG.subscription.expireTimestamp / 1000);

    // Check if token is valid
    const validTokens = [CONFIG.auth.token, fakeToken, CONFIG.auth.guestToken];
    const isValidToken = validTokens.includes(token) ||
                         url.pathname === `/${CONFIG.auth.token}` ||
                         url.pathname.includes(`/${CONFIG.auth.token}?`);

    // Handle request based on token validity
    if (!isValidToken) {
      return handleUnauthenticatedRequest(request, env, url, userAgent, userAgentHeader);
    } else {
      return handleAuthenticatedRequest(request, env, url, userAgent, userAgentHeader, fakeToken);
    }
  }
};

/**
 * Handles requests without valid token
 */
async function handleUnauthenticatedRequest(request, env, url, userAgent, userAgentHeader) {
  // Log abnormal access if enabled
  if (CONFIG.telegram.notifyAll === 1 && url.pathname !== "/" && url.pathname !== "/favicon.ico") {
    await sendTelegramMessage(
      `#异常访问 ${CONFIG.subscription.name}`,
      request.headers.get('CF-Connecting-IP'),
      `UA: ${userAgent}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`
    );
  }

  // Handle login page request
  if (url.pathname === '/login') {
    return handleLogin(request, env, CONFIG.kv.namespace, {
      username: CONFIG.auth.username,
      password: CONFIG.auth.password
    });
  }

  // Handle credential update request
  if (url.pathname === '/update-credentials') {
    // Check if user is authenticated
    const authResult = await checkAuth(request, {
      username: CONFIG.auth.username,
      password: CONFIG.auth.password
    });

    if (!authResult.authenticated) {
      return new Response(JSON.stringify({ error: '未授权访问' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return handleUpdateCredentials(request, env, CONFIG.kv.namespace);
  }

  // Handle authentication for protected routes
  if (CONFIG.auth.enabled) {
    // Redirect root path to login page
    if (url.pathname === '/') {
      return new Response(generateLoginHtml(url.origin), {
        headers: { 'Content-Type': 'text/html; charset=UTF-8' }
      });
    }

    if (url.pathname !== '/favicon.ico') {
      const authResult = await checkAuth(request, {
        username: CONFIG.auth.username,
        password: CONFIG.auth.password
      });

      if (!authResult.authenticated) {
        return new Response(generateLoginHtml(url.origin), {
          headers: {
            'Content-Type': 'text/html; charset=UTF-8',
            'WWW-Authenticate': 'Basic realm="Secure Area"'
          },
          status: 401
        });
      }
    }
  }

  // Handle URL redirects or proxying
  if (env.URL302) {
    return Response.redirect(env.URL302, 302);
  } else if (env.URL) {
    return await proxyURL(env.URL, url);
  } else if (url.pathname === '/') {
    // For root path, show different content based on authentication status
    if (CONFIG.auth.enabled) {
      return new Response(generateLoginHtml(url.origin), {
        headers: { 'Content-Type': 'text/html; charset=UTF-8' }
      });
    } else {
      // If authentication is disabled, show welcome page
      return new Response(await generateWelcomePage(), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
        },
      });
    }
  } else {
    return new Response(await generateWelcomePage(), {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=UTF-8',
      },
    });
  }
}

/**
 * Handles requests with valid token
 */
async function handleAuthenticatedRequest(request, env, url, userAgent, userAgentHeader, fakeToken) {
  // Use specified KV namespace
  const kvNamespace = env[CONFIG.kv.namespace];

  if (kvNamespace) {
    await migrateAddressList(env, 'LINK.txt', CONFIG.kv.namespace);

    // Handle browser requests for editing
    if (userAgent.includes('mozilla') && !url.search) {
      // Check authentication if enabled
      if (CONFIG.auth.enabled) {
        const authResult = await checkAuth(request, {
          username: CONFIG.auth.username,
          password: CONFIG.auth.password
        });

        if (!authResult.authenticated) {
          return new Response(generateLoginHtml(url.origin), {
            headers: {
              'Content-Type': 'text/html; charset=UTF-8',
              'WWW-Authenticate': 'Basic realm="Secure Area"'
            },
            status: 401
          });
        }
      }

      // Log subscription edit access
      await sendTelegramMessage(
        `#编辑订阅 ${CONFIG.subscription.name}`,
        request.headers.get('CF-Connecting-IP'),
        `UA: ${userAgentHeader}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`
      );

      return await handleKVEditor(request, env, 'LINK.txt', CONFIG.auth.guestToken, CONFIG.kv.namespace);
    } else {
      // Load subscription data from KV
      mainData = await kvNamespace.get('LINK.txt') || mainData;
    }
  } else {
    // Use environment variables if KV is not available
    mainData = env.LINK || mainData;
    if (env.LINKSUB) {
      urls = await parseLinesToArray(env.LINKSUB);
    }
  }

  // Process subscription data
  let allLinks = await parseLinesToArray(mainData + '\n' + urls.join('\n'));
  let nodeData = "";
  let subscriptionLinks = "";

  // Separate nodes and subscription links
  for (let link of allLinks) {
    if (link.toLowerCase().startsWith('http')) {
      subscriptionLinks += link + '\n';
    } else {
      nodeData += link + '\n';
    }
  }

  mainData = nodeData;
  urls = await parseLinesToArray(subscriptionLinks);

  // Log subscription access
  await sendTelegramMessage(
    `#获取订阅 ${CONFIG.subscription.name}`,
    request.headers.get('CF-Connecting-IP'),
    `UA: ${userAgentHeader}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`
  );

  // Determine subscription format based on user agent and query parameters
  let subscriptionFormat = determineSubscriptionFormat(userAgent, url);

  // Generate subscription conversion URL
  let conversionUrl = `${url.origin}/${await generateMD5Hash(fakeToken)}?token=${fakeToken}`;
  let requestData = mainData;

  // Determine additional user agent for subscription requests
  let additionalUA = determineAdditionalUserAgent(url);

  // Process subscription links
  const uniqueSubscriptionLinks = [...new Set(urls)].filter(item => item?.trim?.());
  if (uniqueSubscriptionLinks.length > 0) {
    const subscriptionResponse = await fetchSubscriptions(uniqueSubscriptionLinks, request, additionalUA, userAgentHeader);
    requestData += subscriptionResponse[0].join('\n');
    conversionUrl += "|" + subscriptionResponse[1];
  }

  // Add WARP links if available
  if (env.WARP) {
    conversionUrl += "|" + (await parseLinesToArray(env.WARP)).join("|");
  }

  // Fix encoding issues
  const encodedData = new TextEncoder().encode(requestData);
  const decodedText = new TextDecoder().decode(encodedData);

  // Remove duplicates
  const uniqueLines = [...new Set(decodedText.split('\n'))].join('\n');

  // Encode to base64
  let base64Data = encodeToBase64(uniqueLines);

  // Return response based on subscription format
  if (subscriptionFormat === 'base64' || token === fakeToken) {
    return new Response(base64Data, {
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "Profile-Update-Interval": `${CONFIG.subscription.updateInterval}`,
        // "Subscription-Userinfo": `upload=${usedData}; download=${usedData}; total=${totalData}; expire=${expireTime}`,
      }
    });
  } else {
    // Generate subscription converter URL based on format
    const subConverterUrl = generateConverterUrl(subscriptionFormat, conversionUrl);

    try {
      // Fetch converted subscription
      const subConverterResponse = await fetch(subConverterUrl);

      if (!subConverterResponse.ok) {
        return new Response(base64Data, {
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "Profile-Update-Interval": `${CONFIG.subscription.updateInterval}`,
            // "Subscription-Userinfo": `upload=${usedData}; download=${usedData}; total=${totalData}; expire=${expireTime}`,
          }
        });
      }

      let subConverterContent = await subConverterResponse.text();

      // Apply fixes for specific formats
      if (subscriptionFormat === 'clash') {
        subConverterContent = fixClashConfig(subConverterContent);
      }

      return new Response(subConverterContent, {
        headers: {
          "Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(CONFIG.subscription.name)}`,
          "content-type": "text/plain; charset=utf-8",
          "Profile-Update-Interval": `${CONFIG.subscription.updateInterval}`,
          // "Subscription-Userinfo": `upload=${usedData}; download=${usedData}; total=${totalData}; expire=${expireTime}`,
        },
      });
    } catch (error) {
      // Fallback to base64 response on error
      return new Response(base64Data, {
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "Profile-Update-Interval": `${CONFIG.subscription.updateInterval}`,
          // "Subscription-Userinfo": `upload=${usedData}; download=${usedData}; total=${totalData}; expire=${expireTime}`,
        }
      });
    }
  }
}

/**
 * Load environment variables into CONFIG
 */
function loadEnvironmentVariables(env) {
  CONFIG.auth.token = env.TOKEN || CONFIG.auth.token;
  CONFIG.auth.guestToken = env.GUESTTOKEN || env.GUEST || CONFIG.auth.guestToken;
  CONFIG.auth.username = env.USERNAME || CONFIG.auth.username;
  CONFIG.auth.password = env.PASSWORD || CONFIG.auth.password;
  CONFIG.auth.enabled = env.AUTH_ENABLED !== undefined ? env.AUTH_ENABLED : CONFIG.auth.enabled;

  CONFIG.telegram.botToken = env.TGTOKEN || CONFIG.telegram.botToken;
  CONFIG.telegram.chatId = env.TGID || CONFIG.telegram.chatId;
  CONFIG.telegram.notifyAll = env.TG || CONFIG.telegram.notifyAll;

  CONFIG.subscription.name = env.SUBNAME || CONFIG.subscription.name;
  CONFIG.subscription.updateInterval = env.SUBUPTIME || CONFIG.subscription.updateInterval;

  CONFIG.subscription.converter.api = env.SUBAPI || CONFIG.subscription.converter.api;
  CONFIG.subscription.converter.config = env.SUBCONFIG || CONFIG.subscription.converter.config;

  // Process subscription converter API URL
  if (CONFIG.subscription.converter.api.includes("http://")) {
    CONFIG.subscription.converter.api = CONFIG.subscription.converter.api.split("//")[1];
    CONFIG.subscription.converter.protocol = 'http';
  } else {
    CONFIG.subscription.converter.api = CONFIG.subscription.converter.api.split("//")[1] || CONFIG.subscription.converter.api;
  }

  CONFIG.kv.namespace = env.KV_NAMESPACE || CONFIG.kv.namespace;
}

/**
 * Parse multi-line text into an array of lines
 */
async function parseLinesToArray(text) {
  const cleanedText = text.replace(/[	"'|\r\n]+/g, '\n').replace(/\n+/g, '\n');
  let result = cleanedText;

  if (result.charAt(0) === '\n') {
    result = result.slice(1);
  }

  if (result.charAt(result.length - 1) === '\n') {
    result = result.slice(0, result.length - 1);
  }

  return result.split('\n');
}

/**
 * Generate welcome page HTML
 */
async function generateWelcomePage() {
  return `
    <!DOCTYPE html>
    <html>
    <head>
    <title>${CONFIG.subscription.name} - 欢迎页面</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body {
        width: 100%;
        max-width: 800px;
        margin: 0 auto;
        padding: 30px 20px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        line-height: 1.6;
        color: #333;
      }
      h1 {
        color: #2c3e50;
        margin-top: 0;
        text-align: center;
      }
      .card {
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        padding: 30px;
        margin-top: 20px;
      }
      .login-button {
        display: inline-block;
        background-color: #2196F3;
        color: white;
        padding: 10px 25px;
        text-align: center;
        text-decoration: none;
        font-size: 16px;
        margin: 20px 0;
        border-radius: 4px;
        cursor: pointer;
        transition: background-color 0.3s;
      }
      .login-button:hover {
        background-color: #0b7dda;
      }
      p {
        margin-bottom: 15px;
      }
      .center {
        text-align: center;
      }
    </style>
    </head>
    <body>
    <div class="card">
      <h1>${CONFIG.subscription.name}</h1>
      <p>欢迎使用 CF-Workers-SUB 订阅聚合工具，这是一个基于 Cloudflare Workers 的工具，可以帮助您管理和聚合多个订阅源。</p>
      <p>要访问管理面板或使用更多功能，请登录系统。</p>
      <div class="center">
        <a href="/login" class="login-button">登录管理面板</a>
      </div>
      <p>如果您是订阅用户，请使用提供给您的订阅链接。</p>
      <p>未登录用户可以访问的公共路径:</p>
      <ul>
        <li>首页: <code>/</code></li>
        <li>登录页面: <code>/login</code></li>
        <li>订阅地址: <code>/?token=访问令牌</code></li>
      </ul>
    </div>
    </body>
    </html>
  `;
}

/**
 * Send notification message to Telegram
 */
async function sendTelegramMessage(type, ip, additionalData = "") {
  if (CONFIG.telegram.botToken === '' || CONFIG.telegram.chatId === '') {
    return;
  }

  let message = "";
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
    if (response.status === 200) {
      const ipInfo = await response.json();
      message = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${additionalData}`;
    } else {
      message = `${type}\nIP: ${ip}\n<tg-spoiler>${additionalData}`;
    }

    const url = "https://api.telegram.org/bot" + CONFIG.telegram.botToken +
                "/sendMessage?chat_id=" + CONFIG.telegram.chatId +
                "&parse_mode=HTML&text=" + encodeURIComponent(message);

    return fetch(url, {
      method: 'get',
      headers: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;',
        'Accept-Encoding': 'gzip, deflate, br',
        'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
      }
    });
  } catch (error) {
    console.error('Failed to send Telegram message:', error);
  }
}

/**
 * Generate MD5 hash
 */
async function generateMD5Hash(text) {
  const encoder = new TextEncoder();

  const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstPassArray = Array.from(new Uint8Array(firstPass));
  const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

  const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  const secondPassArray = Array.from(new Uint8Array(secondPass));
  const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return secondHex.toLowerCase();
}

/**
 * Determine subscription format based on user agent and URL parameters
 */
function determineSubscriptionFormat(userAgent, url) {
  let format = 'base64';

  // Check user agent
  if (userAgent.includes('null') ||
      userAgent.includes('subconverter') ||
      userAgent.includes('nekobox') ||
      userAgent.includes((CONFIG.subscription.name).toLowerCase())) {
    format = 'base64';
  } else if (userAgent.includes('clash') ||
            (url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
    format = 'clash';
  } else if (userAgent.includes('sing-box') ||
            userAgent.includes('singbox') ||
            ((url.searchParams.has('sb') || url.searchParams.has('singbox')) &&
            !userAgent.includes('subconverter'))) {
    format = 'singbox';
  } else if (userAgent.includes('surge') ||
            (url.searchParams.has('surge') && !userAgent.includes('subconverter'))) {
    format = 'surge';
  } else if (userAgent.includes('quantumult%20x') ||
            (url.searchParams.has('quanx') && !userAgent.includes('subconverter'))) {
    format = 'quanx';
  } else if (userAgent.includes('loon') ||
            (url.searchParams.has('loon') && !userAgent.includes('subconverter'))) {
    format = 'loon';
  }

  // Check URL parameters (override user agent detection)
  if (url.searchParams.has('b64') || url.searchParams.has('base64')) {
    format = 'base64';
  }

  return format;
}

/**
 * Determine additional user agent for subscription requests
 */
function determineAdditionalUserAgent(url) {
  let additionalUA = 'v2rayn';

  if (url.searchParams.has('clash')) {
    additionalUA = 'clash';
  } else if (url.searchParams.has('singbox')) {
    additionalUA = 'singbox';
  } else if (url.searchParams.has('surge')) {
    additionalUA = 'surge';
  } else if (url.searchParams.has('quanx')) {
    additionalUA = 'Quantumult%20X';
  } else if (url.searchParams.has('loon')) {
    additionalUA = 'Loon';
  }

  return additionalUA;
}

/**
 * Generate converter URL based on subscription format
 */
function generateConverterUrl(format, conversionUrl) {
  const baseUrl = `${CONFIG.subscription.converter.protocol}://${CONFIG.subscription.converter.api}/sub`;
  const encodedConversionUrl = encodeURIComponent(conversionUrl);
  const encodedConfig = encodeURIComponent(CONFIG.subscription.converter.config);
  const commonParams = `&url=${encodedConversionUrl}&insert=false&config=${encodedConfig}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`;

  switch (format) {
    case 'clash':
      return `${baseUrl}?target=clash${commonParams}&new_name=true`;
    case 'singbox':
      return `${baseUrl}?target=singbox${commonParams}&new_name=true`;
    case 'surge':
      return `${baseUrl}?target=surge&ver=4${commonParams}&new_name=true`;
    case 'quanx':
      return `${baseUrl}?target=quanx${commonParams}&udp=true`;
    case 'loon':
      return `${baseUrl}?target=loon${commonParams}`;
    default:
      return `${baseUrl}?target=clash${commonParams}&new_name=true`;
  }
}

/**
 * Fix Clash configuration
 */
function fixClashConfig(content) {
  if (content.includes('wireguard') && !content.includes('remote-dns-resolve')) {
    const lines = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
    let result = "";

    for (let line of lines) {
      if (line.includes('type: wireguard')) {
        const oldContent = `, mtu: 1280, udp: true`;
        const newContent = `, mtu: 1280, remote-dns-resolve: true, udp: true`;
        result += line.replace(new RegExp(oldContent, 'g'), newContent) + '\n';
      } else {
        result += line + '\n';
      }
    }

    return result;
  }

  return content;
}

/**
 * Encode text to base64
 */
function encodeToBase64(text) {
  try {
    return btoa(text);
  } catch (e) {
    // Fallback implementation for handling non-ASCII characters
    function customBase64Encode(data) {
      const binary = new TextEncoder().encode(data);
      let base64 = '';
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

      for (let i = 0; i < binary.length; i += 3) {
        const byte1 = binary[i];
        const byte2 = binary[i + 1] || 0;
        const byte3 = binary[i + 2] || 0;

        base64 += chars[byte1 >> 2];
        base64 += chars[((byte1 & 3) << 4) | (byte2 >> 4)];
        base64 += chars[((byte2 & 15) << 2) | (byte3 >> 6)];
        base64 += chars[byte3 & 63];
      }

      const padding = 3 - (binary.length % 3 || 3);
      return base64.slice(0, base64.length - padding) + '=='.slice(0, padding);
    }

    return customBase64Encode(text);
  }
}

/**
 * Migrate address list from old path to new path
 */
async function migrateAddressList(env, txt = 'LINK.txt', kvNamespace) {
  const oldData = await env[kvNamespace].get(`/${txt}`);
  const newData = await env[kvNamespace].get(txt);

  if (oldData && !newData) {
    // Write to new location
    await env[kvNamespace].put(txt, oldData);
    // Delete old data
    await env[kvNamespace].delete(`/${txt}`);
    return true;
  }
  return false;
}

/**
 * Proxy URL request
 */
async function proxyURL(proxyURL, url) {
  const URLs = await parseLinesToArray(proxyURL);
  const fullURL = URLs[Math.floor(Math.random() * URLs.length)];

  // Parse target URL
  let parsedURL = new URL(fullURL);

  // Extract and possibly modify URL components
  let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
  let URLHostname = parsedURL.hostname;
  let URLPathname = parsedURL.pathname;
  let URLSearch = parsedURL.search;

  // Handle pathname
  if (URLPathname.charAt(URLPathname.length - 1) == '/') {
    URLPathname = URLPathname.slice(0, -1);
  }
  URLPathname += url.pathname;

  // Build new URL
  let newURL = `${URLProtocol}://${URLHostname}${URLPathname}${URLSearch}`;

  // Proxy request
  let response = await fetch(newURL);

  // Create new response
  let newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  });

  // Add custom header with URL information
  newResponse.headers.set('X-New-URL', newURL);

  return newResponse;
}

/**
 * Fetch subscriptions from URLs
 */
async function fetchSubscriptions(apiUrls, request, additionalUA, userAgentHeader) {
  if (!apiUrls || apiUrls.length === 0) {
    return [[], ""];
  }

  // Remove duplicates
  apiUrls = [...new Set(apiUrls)];

  let newContent = "";
  let conversionUrls = "";
  let errorSubscriptions = "";

  // Create abort controller for timeout
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort(); // Cancel all requests after 2 seconds
  }, 2000);

  try {
    // Wait for all API requests to complete
    const responses = await Promise.allSettled(
      apiUrls.map(apiUrl =>
        fetchUrl(request, apiUrl, additionalUA, userAgentHeader)
          .then(response => response.ok ? response.text() : Promise.reject(response))
      )
    );

    // Process all responses
    const processedResponses = responses.map((response, index) => {
      if (response.status === 'rejected') {
        const reason = response.reason;
        if (reason && reason.name === 'AbortError') {
          return {
            status: '超时',
            value: null,
            apiUrl: apiUrls[index]
          };
        }
        console.error(`请求失败: ${apiUrls[index]}, 错误信息: ${reason.status} ${reason.statusText}`);
        return {
          status: '请求失败',
          value: null,
          apiUrl: apiUrls[index]
        };
      }
      return {
        status: response.status,
        value: response.value,
        apiUrl: apiUrls[index]
      };
    });

    // Process each response
    for (const response of processedResponses) {
      if (response.status === 'fulfilled') {
        const content = await response.value || 'null';

        if (content.includes('proxies:')) {
          // Clash configuration
          conversionUrls += "|" + response.apiUrl;
        } else if (content.includes('outbounds"') && content.includes('inbounds"')) {
          // Singbox configuration
          conversionUrls += "|" + response.apiUrl;
        } else if (content.includes('://')) {
          // Plain text subscription
          newContent += content + '\n';
        } else if (isValidBase64(content)) {
          // Base64 encoded subscription
          newContent += decodeBase64(content) + '\n';
        } else {
          // Invalid subscription
          const errorLink = `trojan://CMLiussss@127.0.0.1:8888?security=tls&allowInsecure=1&type=tcp&headerType=none#%E5%BC%82%E5%B8%B8%E8%AE%A2%E9%98%85%20${response.apiUrl.split('://')[1].split('/')[0]}`;
          console.log('异常订阅: ' + errorLink);
          errorSubscriptions += `${errorLink}\n`;
        }
      }
    }
  } catch (error) {
    console.error(error);
  } finally {
    clearTimeout(timeout);
  }

  // Convert processed content to array
  const subscriptionContent = await parseLinesToArray(newContent + errorSubscriptions);

  // Return processed results
  return [subscriptionContent, conversionUrls];
}

/**
 * Fetch URL with custom headers
 */
async function fetchUrl(request, targetUrl, additionalUA, userAgentHeader) {
  // Set custom User-Agent
  const newHeaders = new Headers(request.headers);
  newHeaders.set("User-Agent", `${atob('djJyYXlOLzYuNDU=')} cmliu/CF-Workers-SUB ${additionalUA}(${userAgentHeader})`);

  // Build new request object
  const modifiedRequest = new Request(targetUrl, {
    method: request.method,
    headers: newHeaders,
    body: request.method === "GET" ? null : request.body,
    redirect: "follow",
    cf: {
      // Skip SSL certificate validation
      insecureSkipVerify: true,
      // Allow self-signed certificates
      allowUntrusted: true,
      // Disable certificate validation
      validateCertificate: false
    }
  });

  // Log request details
  console.log(`请求URL: ${targetUrl}`);
  console.log(`请求头: ${JSON.stringify([...newHeaders])}`);
  console.log(`请求方法: ${request.method}`);
  console.log(`请求体: ${request.method === "GET" ? null : request.body}`);

  // Send request and return response
  return fetch(modifiedRequest);
}

/**
 * Check if string is valid base64
 */
function isValidBase64(str) {
  // Remove all whitespace characters
  const cleanStr = str.replace(/\s/g, '');
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(cleanStr);
}

/**
 * Decode base64 string
 */
function decodeBase64(str) {
  const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
  const decoder = new TextDecoder('utf-8');
  return decoder.decode(bytes);
}

/**
 * Check authentication credentials
 */
async function checkAuth(request, credentials) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return { authenticated: false };
  }

  const base64Credentials = authHeader.split(' ')[1];
  const decodedCredentials = atob(base64Credentials);
  const [username, password] = decodedCredentials.split(':');

  if (username === credentials.username && password === credentials.password) {
    return {
      authenticated: true,
      user: { username }
    };
  }

  return { authenticated: false };
}

/**
 * Load credentials from KV storage
 */
async function loadCredentials(env, kvNamespace) {
  try {
    if (env[kvNamespace]) {
      const credentialsData = await env[kvNamespace].get('CREDENTIALS');
      if (credentialsData) {
        return JSON.parse(credentialsData);
      }
    }

    // If no saved credentials or KV not bound, return default values
    return {
      username: CONFIG.auth.username,
      password: CONFIG.auth.password
    };
  } catch (error) {
    console.error('Error loading credentials:', error);
    return {
      username: CONFIG.auth.username,
      password: CONFIG.auth.password
    };
  }
}

/**
 * Generate login page HTML
 */
function generateLoginHtml(originUrl = '', loginFailed = false) {
  const errorMessage = loginFailed ? '<div class="error-message">用户名或密码错误</div>' : '';
  const actionUrl = originUrl ? `${originUrl}/login` : '/login';

  return `<!DOCTYPE html>
<html>
<head>
  <title>${CONFIG.subscription.name} - 登录</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
      margin: 0;
      padding: 0;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .login-container {
      background-color: white;
      padding: 30px;
      border-radius: 5px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      width: 350px;
    }
    h1 {
      margin-top: 0;
      color: #333;
      text-align: center;
    }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 10px;
      margin: 10px 0;
      border: 1px solid #ddd;
      border-radius: 4px;
      box-sizing: border-box;
    }
    button {
      width: 100%;
      padding: 10px;
      background-color: #4CAF50;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
    }
    button:hover {
      background-color: #45a049;
    }
    .error-message {
      color: red;
      margin-bottom: 15px;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>${CONFIG.subscription.name} 管理登录</h1>
    ${errorMessage}
    <form method="post" action="${actionUrl}">
      <div>
        <input type="text" name="username" placeholder="用户名" required>
      </div>
      <div>
        <input type="password" name="password" placeholder="密码" required>
      </div>
      <div>
        <button type="submit">登录</button>
      </div>
    </form>
  </div>
</body>
</html>`;
}

/**
 * Handle login request
 */
async function handleLogin(request, env, kvNamespace, credentials) {
  if (request.method === 'POST') {
    try {
      const formData = await request.formData();
      const username = formData.get('username');
      const password = formData.get('password');

      if (username === credentials.username && password === credentials.password) {
        // Login successful, redirect to home page
        return new Response(null, {
          status: 302,
          headers: {
            'Location': '/',
            'Set-Cookie': `auth=${btoa(username + ':' + password)}; HttpOnly; Path=/; Max-Age=86400`
          }
        });
      } else {
        // Login failed
        return new Response(generateLoginHtml('', true), {
          headers: { 'Content-Type': 'text/html; charset=UTF-8' }
        });
      }
    } catch (error) {
      return new Response(`Login processing error: ${error.message}`, { status: 500 });
    }
  } else {
    // GET request, show login page
    return new Response(generateLoginHtml(), {
      headers: { 'Content-Type': 'text/html; charset=UTF-8' }
    });
  }
}

/**
 * Handle credential update request
 */
async function handleUpdateCredentials(request, env, kvNamespace) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: '方法不允许' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const data = await request.json();
    const { currentPassword, newUsername, newPassword } = data;

    // Verify current password
    if (currentPassword !== CONFIG.auth.password) {
      return new Response(JSON.stringify({ error: '当前密码不正确' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Update credentials
    const newCredentials = {
      username: newUsername || CONFIG.auth.username,
      password: newPassword || CONFIG.auth.password
    };

    // Save to KV
    if (env[kvNamespace]) {
      await env[kvNamespace].put('CREDENTIALS', JSON.stringify(newCredentials));
    }

    // Update global variables
    CONFIG.auth.username = newCredentials.username;
    CONFIG.auth.password = newCredentials.password;

    return new Response(JSON.stringify({
      success: true,
      message: '凭证已更新'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: `更新凭证失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * Handle KV editor interface
 */
async function handleKVEditor(request, env, txt = 'LINK.txt', guestToken, kvNamespace) {
  const url = new URL(request.url);
  try {
    // Handle POST request for saving content
    if (request.method === "POST") {
      if (!env[kvNamespace]) {
        return new Response("未绑定KV空间", { status: 400 });
      }

      try {
        const content = await request.text();
        await env[kvNamespace].put(txt, content);
        return new Response("保存成功");
      } catch (error) {
        console.error('保存KV时发生错误:', error);
        return new Response("保存失败: " + error.message, { status: 500 });
      }
    }

    // Handle GET request for editor interface
    let content = '';
    let hasKV = !!env[kvNamespace];

    if (hasKV) {
      try {
        content = await env[kvNamespace].get(txt) || '';
      } catch (error) {
        console.error('读取KV时发生错误:', error);
        content = '读取数据时发生错误: ' + error.message;
      }
    }

    // Generate editor HTML
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>${CONFIG.subscription.name} 订阅编辑</title>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            body {
              margin: 0;
              padding: 15px;
              box-sizing: border-box;
              font-size: 13px;
            }
            .editor-container {
              width: 100%;
              max-width: 100%;
              margin: 0 auto;
            }
            .editor {
              width: 100%;
              height: 300px;
              margin: 15px 0;
              padding: 10px;
              box-sizing: border-box;
              border: 1px solid #ccc;
              border-radius: 4px;
              font-size: 13px;
              line-height: 1.5;
              overflow-y: auto;
              resize: none;
            }
            .save-container {
              margin-top: 8px;
              display: flex;
              align-items: center;
              gap: 10px;
            }
            .save-btn, .back-btn {
              padding: 6px 15px;
              color: white;
              border: none;
              border-radius: 4px;
              cursor: pointer;
            }
            .save-btn {
              background: #4CAF50;
            }
            .save-btn:hover {
              background: #45a049;
            }
            .back-btn {
              background: #666;
            }
            .back-btn:hover {
              background: #555;
            }
            .save-status {
              color: #666;
            }
            .credentials-container {
              margin-top: 20px;
              padding: 15px;
              border: 1px solid #ddd;
              border-radius: 4px;
              background-color: #f9f9f9;
            }
            .credentials-title {
              margin-top: 0;
              margin-bottom: 15px;
              font-size: 16px;
              color: #333;
            }
            .form-field {
              margin-bottom: 10px;
            }
            .form-field label {
              display: block;
              margin-bottom: 5px;
              font-weight: bold;
            }
            .form-field input {
              width: 100%;
              padding: 8px;
              border: 1px solid #ddd;
              border-radius: 4px;
            }
            .credentials-btn {
              padding: 8px 15px;
              background-color: #2196F3;
              color: white;
              border: none;
              border-radius: 4px;
              cursor: pointer;
            }
            .credentials-btn:hover {
              background-color: #0b7dda;
            }
            .credentials-status {
              margin-top: 10px;
              font-size: 14px;
            }
          </style>
          <script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
        </head>
        <body>
          ################################################################<br>
          Subscribe / sub 订阅地址, 点击链接自动 <strong>复制订阅链接</strong> 并 <strong>生成订阅二维码</strong> <br>
          ---------------------------------------------------------------<br>
          自适应订阅地址:<br>
          <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${CONFIG.auth.token}?sub','qrcode_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${CONFIG.auth.token}</a><br>
          <div id="qrcode_0" style="margin: 10px 10px 10px 10px;"></div>
          Base64订阅地址:<br>
          <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${CONFIG.auth.token}?b64','qrcode_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${CONFIG.auth.token}?b64</a><br>
          <div id="qrcode_1" style="margin: 10px 10px 10px 10px;"></div>
          clash订阅地址:<br>
          <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${CONFIG.auth.token}?clash','qrcode_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${CONFIG.auth.token}?clash</a><br>
          <div id="qrcode_2" style="margin: 10px 10px 10px 10px;"></div>
          singbox订阅地址:<br>
          <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${CONFIG.auth.token}?sb','qrcode_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${CONFIG.auth.token}?sb</a><br>
          <div id="qrcode_3" style="margin: 10px 10px 10px 10px;"></div>
          surge订阅地址:<br>
          <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${CONFIG.auth.token}?surge','qrcode_4')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${CONFIG.auth.token}?surge</a><br>
          <div id="qrcode_4" style="margin: 10px 10px 10px 10px;"></div>
          loon订阅地址:<br>
          <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${CONFIG.auth.token}?loon','qrcode_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/${CONFIG.auth.token}?loon</a><br>
          <div id="qrcode_5" style="margin: 10px 10px 10px 10px;"></div>
          &nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">查看访客订阅∨</a></strong><br>
          <div id="noticeContent" class="notice-content" style="display: none;">
            ---------------------------------------------------------------<br>
            访客订阅只能使用订阅功能，无法查看配置页！<br>
            GUEST（访客订阅TOKEN）: <strong>${guestToken}</strong><br>
            ---------------------------------------------------------------<br>
            自适应订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guestToken}','guest_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guestToken}</a><br>
            <div id="guest_0" style="margin: 10px 10px 10px 10px;"></div>
            Base64订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guestToken}&b64','guest_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guestToken}&b64</a><br>
            <div id="guest_1" style="margin: 10px 10px 10px 10px;"></div>
            clash订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guestToken}&clash','guest_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guestToken}&clash</a><br>
            <div id="guest_2" style="margin: 10px 10px 10px 10px;"></div>
            singbox订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guestToken}&sb','guest_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guestToken}&sb</a><br>
            <div id="guest_3" style="margin: 10px 10px 10px 10px;"></div>
            surge订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guestToken}&surge','guest_4')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guestToken}&surge</a><br>
            <div id="guest_4" style="margin: 10px 10px 10px 10px;"></div>
            loon订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/sub?token=${guestToken}&loon','guest_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${url.hostname}/sub?token=${guestToken}&loon</a><br>
            <div id="guest_5" style="margin: 10px 10px 10px 10px;"></div>
          </div>
          ---------------------------------------------------------------<br>
          ################################################################<br>
          订阅转换配置<br>
          ---------------------------------------------------------------<br>
          SUBAPI（订阅转换后端）: <strong>${CONFIG.subscription.converter.protocol}://${CONFIG.subscription.converter.api}</strong><br>
          SUBCONFIG（订阅转换配置文件）: <strong>${CONFIG.subscription.converter.config}</strong><br>
          ---------------------------------------------------------------<br>
          ################################################################<br>
          ${CONFIG.subscription.name} 汇聚订阅编辑:
          <div class="editor-container">
            ${hasKV ? `
            <textarea class="editor"
              placeholder="${decodeURIComponent(atob('TElOSyVFNyVBNCVCQSVFNCVCRSU4QiVFRiVCQyU4OCVFNCVCOCU4MCVFOCVBMSU4QyVFNCVCOCU4MCVFNCVCOCVBQSVFOCU4QSU4MiVFNyU4MiVCOSVFOSU5MyVCRSVFNiU4RSVBNSVFNSU4RCVCMyVFNSU4RiVBRiVFRiVCQyU4OSVFRiVCQyU5QQp2bGVzcyUzQSUyRiUyRjI0NmFhNzk1LTA2MzctNGY0Yy04ZjY0LTJjOGZiMjRjMWJhZCU0MDEyNy4wLjAuMSUzQTEyMzQlM0ZlbmNyeXB0aW9uJTNEbm9uZSUyNnNlY3VyaXR5JTNEdGxzJTI2c25pJTNEVEcuQ01MaXVzc3NzLmxvc2V5b3VyaXAuY29tJTI2YWxsb3dJbnNlY3VyZSUzRDElMjZ0eXBlJTNEd3MlMjZob3N0JTNEVEcuQ01MaXVzc3NzLmxvc2V5b3VyaXAuY29tJTI2cGF0aCUzRCUyNTJGJTI1M0ZlZCUyNTNEMjU2MCUyM0NGbmF0CnRyb2phbiUzQSUyRiUyRmFhNmRkZDJmLWQxY2YtNGE1Mi1iYTFiLTI2NDBjNDFhNzg1NiU0MDIxOC4xOTAuMjMwLjIwNyUzQTQxMjg4JTNGc2VjdXJpdHklM0R0bHMlMjZzbmklM0RoazEyLmJpbGliaWxpLmNvbSUyNmFsbG93SW5zZWN1cmUlM0QxJTI2dHlwZSUzRHRjcCUyNmhlYWRlclR5cGUlM0Rub25lJTIzSEsKc3MlM0ElMkYlMkZZMmhoWTJoaE1qQXRhV1YwWmkxd2IyeDVNVE13TlRveVJYUlFjVzQyU0ZscVZVNWpTRzlvVEdaVmNFWlJkMjVtYWtORFVUVnRhREZ0U21SRlRVTkNkV04xVjFvNVVERjFaR3RTUzBodVZuaDFielUxYXpGTFdIb3lSbTgyYW5KbmRERTRWelkyYjNCMGVURmxOR0p0TVdwNlprTm1RbUklMjUzRCU0MDg0LjE5LjMxLjYzJTNBNTA4NDElMjNERQoKCiVFOCVBRSVBMiVFOSU5OCU4NSVFOSU5MyVCRSVFNiU4RSVBNSVFNyVBNCVCQSVFNCVCRSU4QiVFRiVCQyU4OCVFNCVCOCU4MCVFOCVBMSU4QyVFNCVCOCU4MCVFNiU5RCVBMSVFOCVBRSVBMiVFOSU5OCU4NSVFOSU5MyVCRSVFNiU4RSVBNSVFNSU4RCVCMyVFNSU4RiVBRiVFRiVCQyU4OSVFRiVCQyU5QQpodHRwcyUzQSUyRiUyRnN1Yi54Zi5mcmVlLmhyJTJGYXV0bw=='))}"
              id="content">${content}</textarea>
            <div class="save-container">
              <button class="save-btn" onclick="saveContent(this)">保存</button>
              <span class="save-status" id="saveStatus"></span>
            </div>

            <!-- 密码设置 -->
            <div class="credentials-container">
              <h3 class="credentials-title">管理员凭证设置</h3>
              <div class="form-field">
                <label for="currentPassword">当前密码</label>
                <input type="password" id="currentPassword" placeholder="输入当前密码">
              </div>
              <div class="form-field">
                <label for="newUsername">新用户名 (可选)</label>
                <input type="text" id="newUsername" placeholder="留空则不修改">
              </div>
              <div class="form-field">
                <label for="newPassword">新密码 (可选)</label>
                <input type="password" id="newPassword" placeholder="留空则不修改">
              </div>
              <button class="credentials-btn" onclick="updateCredentials()">更新凭证</button>
              <div class="credentials-status" id="credentialsStatus"></div>
            </div>
            ` : `<p>请绑定KV命名空间。在 Cloudflare Workers 设置中：</p>
<ol>
  <li>创建一个KV命名空间</li>
  <li>将该命名空间绑定到Worker，绑定变量名称为 <strong>${CONFIG.kv.namespace}</strong></li>
  <li>或者设置环境变量 <strong>KV_NAMESPACE</strong> 为您自定义的KV绑定名称</li>
</ol>`}
          </div>
          <br>
          ################################################################<br>
          参考项目：<a href="https://github.com/cmliu/CF-Workers-SUB" target="_blank">CF-Workers-SUB</a>
          <br><br>UA: <strong>${request.headers.get('User-Agent')}</strong>
          <script>
          function copyToClipboard(text, qrcode) {
            navigator.clipboard.writeText(text).then(() => {
              alert('已复制到剪贴板');
            }).catch(err => {
              console.error('复制失败:', err);
            });
            const qrcodeDiv = document.getElementById(qrcode);
            qrcodeDiv.innerHTML = '';
            new QRCode(qrcodeDiv, {
              text: text,
              width: 220,
              height: 220,
              colorDark: "#000000",
              colorLight: "#ffffff",
              correctLevel: QRCode.CorrectLevel.Q,
              scale: 1
            });
          }

          if (document.querySelector('.editor')) {
            let timer;
            const textarea = document.getElementById('content');
            const originalContent = textarea.value;

            function goBack() {
              const currentUrl = window.location.href;
              const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
              window.location.href = parentUrl;
            }

            function replaceFullwidthColon() {
              const text = textarea.value;
              textarea.value = text.replace(/：/g, ':');
            }

            function saveContent(button) {
              try {
                const updateButtonText = (step) => {
                  button.textContent = \`保存中: \${step}\`;
                };
                // 检测是否为iOS设备
                const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);

                // 仅在非iOS设备上执行replaceFullwidthColon
                if (!isIOS) {
                  replaceFullwidthColon();
                }
                updateButtonText('开始保存');
                button.disabled = true;

                // 获取textarea内容和原始内容
                const textarea = document.getElementById('content');
                if (!textarea) {
                  throw new Error('找不到文本编辑区域');
                }

                updateButtonText('获取内容');
                let newContent;
                let originalContent;
                try {
                  newContent = textarea.value || '';
                  originalContent = textarea.defaultValue || '';
                } catch (e) {
                  console.error('获取内容错误:', e);
                  throw new Error('无法获取编辑内容');
                }

                updateButtonText('准备状态更新函数');
                const updateStatus = (message, isError = false) => {
                  const statusElem = document.getElementById('saveStatus');
                  if (statusElem) {
                    statusElem.textContent = message;
                    statusElem.style.color = isError ? 'red' : '#666';
                  }
                };

                updateButtonText('准备按钮重置函数');
                const resetButton = () => {
                  button.textContent = '保存';
                  button.disabled = false;
                };

                if (newContent !== originalContent) {
                  updateButtonText('发送保存请求');
                  fetch(window.location.href, {
                    method: 'POST',
                    body: newContent,
                    headers: {
                      'Content-Type': 'text/plain;charset=UTF-8'
                    },
                    cache: 'no-cache'
                  })
                  .then(response => {
                    updateButtonText('检查响应状态');
                    if (!response.ok) {
                      throw new Error(\`HTTP error! status: \${response.status}\`);
                    }
                    updateButtonText('更新保存状态');
                    const now = new Date().toLocaleString();
                    document.title = \`编辑已保存 \${now}\`;
                    updateStatus(\`已保存 \${now}\`);
                  })
                  .catch(error => {
                    updateButtonText('处理错误');
                    console.error('Save error:', error);
                    updateStatus(\`保存失败: \${error.message}\`, true);
                  })
                  .finally(() => {
                    resetButton();
                  });
                } else {
                  updateButtonText('检查内容变化');
                  updateStatus('内容未变化');
                  resetButton();
                }
              } catch (error) {
                console.error('保存过程出错:', error);
                button.textContent = '保存';
                button.disabled = false;
                const statusElem = document.getElementById('saveStatus');
                if (statusElem) {
                  statusElem.textContent = \`错误: \${error.message}\`;
                  statusElem.style.color = 'red';
                }
              }
            }

            // 更新凭证函数
            function updateCredentials() {
              const currentPassword = document.getElementById('currentPassword').value;
              const newUsername = document.getElementById('newUsername').value;
              const newPassword = document.getElementById('newPassword').value;

              if (!currentPassword) {
                document.getElementById('credentialsStatus').textContent = '请输入当前密码';
                document.getElementById('credentialsStatus').style.color = 'red';
                return;
              }

              fetch('/update-credentials', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                  currentPassword,
                  newUsername,
                  newPassword
                })
              })
              .then(response => response.json())
              .then(data => {
                if (data.error) {
                  document.getElementById('credentialsStatus').textContent = data.error;
                  document.getElementById('credentialsStatus').style.color = 'red';
                } else {
                  document.getElementById('credentialsStatus').textContent = data.message;
                  document.getElementById('credentialsStatus').style.color = 'green';
                  // 清空输入框
                  document.getElementById('currentPassword').value = '';
                  document.getElementById('newUsername').value = '';
                  document.getElementById('newPassword').value = '';
                }
              })
              .catch(error => {
                document.getElementById('credentialsStatus').textContent = '更新失败: ' + error.message;
                document.getElementById('credentialsStatus').style.color = 'red';
              });
            }

            textarea.addEventListener('blur', saveContent);
            textarea.addEventListener('input', () => {
              clearTimeout(timer);
              timer = setTimeout(saveContent, 5000);
            });
          }

          function toggleNotice() {
            const noticeContent = document.getElementById('noticeContent');
            const noticeToggle = document.getElementById('noticeToggle');
            if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
              noticeContent.style.display = 'block';
              noticeToggle.textContent = '隐藏访客订阅∧';
            } else {
              noticeContent.style.display = 'none';
              noticeToggle.textContent = '查看访客订阅∨';
            }
          }

          // 初始化 noticeContent 的 display 属性
          document.addEventListener('DOMContentLoaded', () => {
            document.getElementById('noticeContent').style.display = 'none';
          });
          </script>
        </body>
      </html>
    `;

    return new Response(html, {
      headers: { "Content-Type": "text/html;charset=utf-8" }
    });
  } catch (error) {
    console.error('处理请求时发生错误:', error);
    return new Response("服务器错误: " + error.message, {
      status: 500,
      headers: { "Content-Type": "text/plain;charset=utf-8" }
    });
  }
}
