// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function getSubStore(env) {
  if (!env?.SUB_STORE || typeof env.SUB_STORE.get !== 'function' || typeof env.SUB_STORE.put !== 'function') {
    throw new Error(
      '未绑定 KV Namespace：SUB_STORE。请在 Cloudflare Worker 的 Settings -> Bindings 中添加 KV namespace，变量名必须为 SUB_STORE，然后重新部署。',
    );
  }
  return env.SUB_STORE;
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

function parsePreferredEndpoints(input) {
  return String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [raw, remark = ''] = line.split('#');
      const value = raw.trim();
      const hashRemark = remark.trim();
      const match = value.match(/^(.*?)(?::(\d+))?$/);
      return {
        server: match?.[1] || value,
        port: match?.[2] ? Number(match[2]) : undefined,
        remark: hashRemark,
      };
    });
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? decodeURIComponent(u.username) : undefined,
    uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined,
    network: u.searchParams.get('type') || 'tcp',
    tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls',
    host: u.searchParams.get('host') || u.searchParams.get('sni') || '',
    path: u.searchParams.get('path') || '/',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || '',
    fp: u.searchParams.get('fp') || '',
    alpn: u.searchParams.get('alpn') || '',
    flow: u.searchParams.get('flow') || '',
  };
}

function parseHysteria2(link) {
  const schemeEnd = link.indexOf('://');
  const body = link.slice(schemeEnd + 3).trim();
  const hashIndex = body.indexOf('#');
  const bodyWithoutHash = hashIndex >= 0 ? body.slice(0, hashIndex) : body;
  const hash = hashIndex >= 0 ? body.slice(hashIndex + 1) : '';
  const queryIndex = bodyWithoutHash.indexOf('?');
  const authorityAndPath = queryIndex >= 0 ? bodyWithoutHash.slice(0, queryIndex) : bodyWithoutHash;
  const queryText = queryIndex >= 0 ? bodyWithoutHash.slice(queryIndex + 1) : '';
  const authority = authorityAndPath.split('/')[0];
  const atIndex = authority.lastIndexOf('@');
  const params = Object.fromEntries(new URLSearchParams(queryText).entries());

  const rawPassword =
    atIndex >= 0
      ? authority.slice(0, atIndex)
      : firstNonEmpty(params.auth, params.password, params.pass);
  const serverPart = atIndex >= 0 ? authority.slice(atIndex + 1) : authority;
  const password = decodeComponentSafe(rawPassword).trim();
  const { host: server, portText } = splitHysteria2HostAndPort(serverPart);
  const { port, ports } = normalizeHysteria2Port(portText);
  const paramsPorts = firstNonEmpty(params.ports, params.mport, params.portHop);

  if (!server || !password) {
    throw new Error('Hysteria2 链接缺少主机或认证密码');
  }

  return {
    type: 'hysteria2',
    name: decodeComponentSafe(hash) || 'hysteria2',
    server,
    port,
    ports: paramsPorts || ports,
    password,
    network: 'udp',
    tls: true,
    host: '',
    path: '',
    sni: firstNonEmpty(params.sni, params.peer, params.serverName),
    alpn: params.alpn || '',
    obfs: firstNonEmpty(params.obfs),
    obfsPassword: firstNonEmpty(params['obfs-password'], params.obfsPassword, params.obfs_password),
    pinSHA256: params.pinSHA256 || '',
    fingerprint: firstNonEmpty(params.fingerprint),
    fp: firstNonEmpty(params.fp, params['client-fingerprint'], params.clientFingerprint),
    allowInsecure: parseBool(
      firstNonEmpty(params.insecure, params.allowInsecure, params['skip-cert-verify'], params.skipCertVerify),
    ),
    up: firstNonEmpty(params.up, params.upmbps),
    down: firstNonEmpty(params.down, params.downmbps),
    hopInterval: firstNonEmpty(
      params['hop-interval'],
      params.hopInterval,
      params.hop_interval,
      params.mportHopInt,
    ),
  };
}

function splitHysteria2HostAndPort(input) {
  const value = String(input || '').trim();
  if (!value) {
    return { host: '', portText: '' };
  }

  if (value.startsWith('[')) {
    const match = value.match(/^\[([^\]]+)](?::(.+))?$/);
    if (!match) {
      throw new Error(`Hysteria2 IPv6 地址格式错误：${value}`);
    }
    return { host: match[1], portText: match[2] || '' };
  }

  const colonCount = (value.match(/:/g) || []).length;
  if (colonCount > 1) {
    return { host: value, portText: '' };
  }

  const separator = value.lastIndexOf(':');
  if (separator >= 0) {
    return {
      host: value.slice(0, separator),
      portText: value.slice(separator + 1),
    };
  }

  return { host: value, portText: '' };
}

function normalizeHysteria2Port(value) {
  const text = String(value || '').trim();
  if (!text) {
    return { port: 443, ports: '' };
  }
  if (/^\d+$/.test(text)) {
    return { port: normalizePortNumber(text), ports: '' };
  }

  const firstPort = text.match(/\d+/)?.[0];
  if (!firstPort) {
    throw new Error(`Hysteria2 端口无效：${value}`);
  }
  return { port: normalizePortNumber(firstPort), ports: text };
}

function normalizePortNumber(value) {
  const port = Number.parseInt(String(value || ''), 10);
  if (Number.isInteger(port) && port >= 1 && port <= 65535) {
    return port;
  }
  throw new Error(`Hysteria2 端口无效：${value}`);
}

function parseBool(value) {
  const text = String(value || '').trim().toLowerCase();
  return text === '1' || text === 'true' || text === 'yes';
}

function decodeComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function firstNonEmpty(...values) {
  for (const value of values) {
    const text = String(value || '').trim();
    if (text) {
      return text;
    }
  }
  return '';
}

function getCertificateFingerprint(node) {
  const pin = firstNonEmpty(node.pinSHA256);
  if (pin) {
    return pin;
  }

  const candidate = firstNonEmpty(node.fingerprint);
  return isCertificateFingerprint(candidate) ? candidate : '';
}

function getClientFingerprint(node) {
  const clientFingerprint = firstNonEmpty(node.fp, node.clientFingerprint);
  if (clientFingerprint) {
    return clientFingerprint;
  }

  const candidate = firstNonEmpty(node.fingerprint);
  return candidate && !isCertificateFingerprint(candidate) ? candidate : '';
}

function isCertificateFingerprint(value) {
  const text = String(value || '').trim();
  if (!text) {
    return false;
  }
  const compactHex = text.replace(/[:-]/g, '');
  if (/^[0-9a-f]{32,}$/i.test(compactHex)) {
    return true;
  }
  return /^[A-Za-z0-9+/=_-]{40,}$/.test(text);
}

function parseRawLinks(input) {
  const lines = String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const result = [];
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (lower.startsWith('vmess://')) {
      result.push(parseVmess(line));
      continue;
    }
    if (lower.startsWith('vless://')) {
      result.push(parseUrlLike(line, 'vless'));
      continue;
    }
    if (lower.startsWith('trojan://')) {
      result.push(parseUrlLike(line, 'trojan'));
      continue;
    }
    if (lower.startsWith('hysteria2://') || lower.startsWith('hy2://')) {
      result.push(parseHysteria2(line));
      continue;
    }
    try {
      const decoded = b64DecodeUtf8(line);
      if (/^(vmess|vless|trojan|hysteria2|hy2):\/\//m.test(decoded)) {
        result.push(...parseRawLinks(decoded));
      }
    } catch {}
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));
      const sni = node.sni || (node.type === 'hysteria2' ? node.server : '');
      output.push({
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
        host: options.keepOriginalHost ? node.host : '',
        sni: options.keepOriginalHost ? sni : '',
        ports: ep.port && node.type === 'hysteria2' ? '' : node.ports,
      });
    }
  }
  return output;
}

function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function encodeHysteria2(node) {
  const params = new URLSearchParams();
  if (node.sni) params.set('sni', node.sni);
  if (node.allowInsecure) params.set('insecure', '1');
  if (node.obfs) params.set('obfs', node.obfs);
  if (node.obfsPassword) params.set('obfs-password', node.obfsPassword);
  if (node.alpn) params.set('alpn', node.alpn);
  const certificateFingerprint = getCertificateFingerprint(node);
  const clientFingerprint = getClientFingerprint(node);
  if (certificateFingerprint) params.set('pinSHA256', certificateFingerprint);
  if (clientFingerprint) params.set('fp', clientFingerprint);
  if (node.up) params.set('up', node.up);
  if (node.down) params.set('down', node.down);
  if (node.hopInterval) params.set('hop-interval', node.hopInterval);

  const portPart = node.ports || node.port;
  const query = params.toString();
  const hash = node.name ? `#${encodeURIComponent(node.name)}` : '';
  return `hysteria2://${encodeURIComponent(node.password)}@${formatHostForUrl(node.server)}:${portPart}${query ? `?${query}` : ''}${hash}`;
}

function formatHostForUrl(host) {
  const value = String(host || '');
  return value.includes(':') && !value.startsWith('[') ? `[${value}]` : value;
}

function renderRaw(nodes) {
  const lines = nodes
    .map((node) => {
      if (node.type === 'vmess') return encodeVmess(node);
      if (node.type === 'vless') return encodeVless(node);
      if (node.type === 'trojan') return encodeTrojan(node);
      if (node.type === 'hysteria2') return encodeHysteria2(node);
      return '';
    })
    .filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}

function renderClash(nodes) {
  const proxies = nodes
    .map((node) => {
      if (node.type === 'vmess') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vmess`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    alterId: 0`,
          `    cipher: ${node.cipher || 'auto'}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'vless') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vless`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'trojan') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: trojan`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    password: "${escapeYaml(node.password || '')}"`,
          `    udp: true`,
        ];

        if (node.sni) {
          lines.push(`    sni: "${escapeYaml(node.sni)}"`);
        }

        if (node.tls !== false) {
          lines.push(`    tls: true`);
        }

        if (node.network) {
          lines.push(`    network: ${node.network}`);
        }

        if (node.network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'hysteria2') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: hysteria2`,
          `    server: "${escapeYaml(node.server)}"`,
          `    port: ${node.port}`,
          `    password: "${escapeYaml(node.password || '')}"`,
          `    udp: true`,
        ];

        if (node.ports) {
          lines.push(`    ports: "${escapeYaml(node.ports)}"`);
        }
        if (node.up) {
          lines.push(`    up: "${escapeYaml(node.up)}"`);
        }
        if (node.down) {
          lines.push(`    down: "${escapeYaml(node.down)}"`);
        }
        if (node.hopInterval) {
          lines.push(`    hop-interval: "${escapeYaml(node.hopInterval)}"`);
        }
        if (node.obfs) {
          lines.push(`    obfs: "${escapeYaml(node.obfs)}"`);
        }
        if (node.obfsPassword) {
          lines.push(`    obfs-password: "${escapeYaml(node.obfsPassword)}"`);
        }
        if (node.sni) {
          lines.push(`    sni: "${escapeYaml(node.sni)}"`);
        }
        if (node.alpn) {
          const alpn = String(node.alpn)
            .split(',')
            .map((item) => item.trim())
            .filter(Boolean);
          if (alpn.length) {
            lines.push(`    alpn: [${alpn.map((item) => `"${escapeYaml(item)}"`).join(', ')}]`);
          }
        }
        const certificateFingerprint = getCertificateFingerprint(node);
        const clientFingerprint = getClientFingerprint(node);
        if (certificateFingerprint) {
          lines.push(`    fingerprint: "${escapeYaml(certificateFingerprint)}"`);
        }
        if (clientFingerprint) {
          lines.push(`    client-fingerprint: "${escapeYaml(clientFingerprint)}"`);
        }
        lines.push(`    skip-cert-verify: ${node.allowInsecure ? 'true' : 'false'}`);

        return lines.join('\n');
      }

      return '';
    })
    .filter(Boolean);

  const proxyNames = nodes.map(
    (node) => `      - "${escapeYaml(node.name)}"`
  );

  const allGroupMembers = [
    `      - "自动选择"`,
    ...proxyNames,
    `      - DIRECT`,
  ];

  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...(proxies.length ? proxies : []),
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`,
  ].join('\n');
}

function renderSurge(nodes, baseUrl, accessToken) {
  const proxies = nodes
    .filter((node) => node.type === 'vmess' || node.type === 'trojan')
    .map((node) => {
      if (node.type === 'vmess') {
        return `${node.name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || '/'}, ws-headers=Host:${node.host || ''}, tls=${node.tls ? 'true' : 'false'}, sni=${node.sni || ''}`;
      }
      return `${node.name} = trojan, ${node.server}, ${node.port}, password=${node.password || ''}, sni=${node.sni || ''}`;
    });

  return [
    '[General]',
    'skip-proxy = 127.0.0.1, localhost',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    'Proxy = select, ' +
      nodes
        .filter((n) => n.type === 'vmess' || n.type === 'trojan')
        .map((n) => n.name)
        .join(', '),
    '',
    '[Rule]',
    'FINAL,Proxy',
    '',
    '; token-protected subscription',
    `; ${baseUrl}?token=${accessToken}`,
  ].join('\n');
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

async function createUniqueShortId(store, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await store.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

async function handleGenerate(request, env, url) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }
  const subStore = getSubStore(env);

  const options = {
    namePrefix: body.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
  };

  let baseNodes;
  let preferredEndpoints;
  let nodes;
  try {
    baseNodes = parseRawLinks(body.nodeLinks || '');
    preferredEndpoints = parsePreferredEndpoints(body.preferredIps || '');

    if (!baseNodes.length) return json({ ok: false, error: '没有识别到可用节点' }, 400);
    if (!preferredEndpoints.length) return json({ ok: false, error: '没有识别到可用优选地址' }, 400);

    nodes = buildNodes(baseNodes, preferredEndpoints, options);
  } catch (error) {
    return json({ ok: false, error: error.message || '节点或优选地址解析失败' }, 400);
  }

  const payload = {
    version: 1,
    createdAt: new Date().toISOString(),
    options,
    nodes,
  };

  const dedupHash = await buildDedupHash(body);
  const dedupKey = `dedup:${dedupHash}`;

  let id = await subStore.get(dedupKey);

  if (!id) {
    id = await createUniqueShortId(subStore);
    const ttl = 60 * 60 * 24 * 7; // 7天

    await subStore.put(`sub:${id}`, JSON.stringify(payload), {
      expirationTtl: ttl,
    });

    await subStore.put(dedupKey, id, {
      expirationTtl: ttl,
    });
  }

  const origin = url.origin;
  const accessToken = env.SUB_ACCESS_TOKEN || '';
  const withToken = (target) =>
    `${origin}/sub/${id}${
      target
        ? `?target=${target}&token=${encodeURIComponent(accessToken)}`
        : `?token=${encodeURIComponent(accessToken)}`
    }`;

  return json({
    ok: true,
    storage: 'kv',
    deduplicated: true,
    shortId: id,
    urls: {
      auto: withToken(''),
      raw: withToken('raw'),
      clash: withToken('clash'),
      surge: withToken('surge'),
    },
    counts: {
      inputNodes: baseNodes.length,
      preferredEndpoints: preferredEndpoints.length,
      outputNodes: nodes.length,
    },
    preview: nodes.slice(0, 20).map((node) => ({
      name: node.name,
      type: node.type,
      server: node.server,
      port: node.port,
      host: node.host || '',
      sni: node.sni || '',
    })),
    warnings: accessToken ? [] : ['未检测到 SUB_ACCESS_TOKEN，订阅链接将没有第二层访问保护。'],
  });
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) return { ok: true };
  const provided = url.searchParams.get('token') || '';
  if (!provided || provided !== expected) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }
  return { ok: true };
}

async function handleSub(url, env) {
  const subStore = getSubStore(env);
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);

  const raw = await subStore.get(`sub:${id}`);
  if (!raw) return text('not found', 404);

  const record = JSON.parse(raw);
  const nodes = record.nodes || [];
  const target = (url.searchParams.get('target') || 'raw').toLowerCase();

  if (target === 'clash') {
    return text(renderClash(nodes), 200, 'text/yaml; charset=utf-8');
  }
  if (target === 'surge') {
    return text(
      renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ''),
      200,
      'text/plain; charset=utf-8',
    );
  }
  return text(renderRaw(nodes), 200, 'text/plain; charset=utf-8');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        },
      });
    }

    if (request.method === 'POST' && url.pathname === '/api/generate') {
      try {
        return await handleGenerate(request, env, url);
      } catch (error) {
        return json({ ok: false, error: error.message || '生成订阅失败' }, 500);
      }
    }

    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      try {
        return await handleSub(url, env);
      } catch (error) {
        return text(error.message || '订阅读取失败', 500);
      }
    }

    return env.ASSETS.fetch(request);
  },
};
