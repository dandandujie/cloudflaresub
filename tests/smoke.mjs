import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import {
  decryptPayload,
  encryptPayload,
  expandNodes,
  parseNodeLinks,
  parsePreferredEndpoints,
  renderClashSubscription,
  renderRawSubscription,
  renderSurgeSubscription,
} from '../src/core.js';

const vmess = 'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJkZW1vLXdzLXRscyIsCiAgImFkZCI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAicG9ydCI6ICI0NDMiLAogICJpZCI6ICIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLAogICJzY3kiOiAiYXV0byIsCiAgIm5ldCI6ICJ3cyIsCiAgInRscyI6ICJ0bHMiLAogICJwYXRoIjogIi93cyIsCiAgImhvc3QiOiAiZWRnZS5leGFtcGxlLmNvbSIsCiAgInNuaSI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAiZnAiOiAiY2hyb21lIiwKICAiYWxwbiI6ICJoMixodHRwLzEuMSIKfQ==';
const hysteria2 = 'hysteria2://demo%3Apass@hy.example.com:443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=obfs-secret&alpn=h3#demo-hy2';
const hysteria2QueryAuth = 'hy2://hy.example.com:443?auth=demo%3Apass&peer=hy.example.com&skip-cert-verify=true&obfs=salamander&obfs_password=obfs-secret&mport=443-8443#query-auth';

const { nodes } = parseNodeLinks(vmess);
assert.equal(nodes.length, 1);
assert.equal(nodes[0].type, 'vmess');
assert.equal(nodes[0].server, 'edge.example.com');

const { endpoints } = parsePreferredEndpoints('104.16.1.2#HK\n104.17.2.3:2053#US');
assert.equal(endpoints.length, 2);

const expanded = expandNodes(nodes, endpoints, { keepOriginalHost: true, namePrefix: 'CF' });
assert.equal(expanded.nodes.length, 2);
assert.equal(expanded.nodes[0].server, '104.16.1.2');
assert.equal(expanded.nodes[0].hostHeader, 'edge.example.com');
assert.equal(expanded.nodes[1].port, 2053);

const raw = renderRawSubscription(expanded.nodes);
assert.ok(raw.length > 10);

const clash = renderClashSubscription(expanded.nodes);
assert.match(clash, /proxies:/);
assert.match(clash, /edge\.example\.com/);

const surge = renderSurgeSubscription(expanded.nodes, 'https://sub.example.com/sub/demo?target=surge');
assert.match(surge, /\[Proxy]/);
assert.match(surge, /vmess/);

const { nodes: hy2Nodes } = parseNodeLinks(hysteria2);
assert.equal(hy2Nodes.length, 1);
assert.equal(hy2Nodes[0].type, 'hysteria2');
assert.equal(hy2Nodes[0].password, 'demo:pass');
assert.equal(hy2Nodes[0].sni, 'hy.example.com');
assert.equal(hy2Nodes[0].allowInsecure, true);
assert.equal(hy2Nodes[0].obfs, 'salamander');
assert.equal(hy2Nodes[0].obfsPassword, 'obfs-secret');

const { nodes: hy2AliasNodes } = parseNodeLinks(hysteria2.replace('hysteria2://', 'hy2://'));
assert.equal(hy2AliasNodes[0].type, 'hysteria2');

const { nodes: hy2QueryAuthNodes } = parseNodeLinks(hysteria2QueryAuth);
assert.equal(hy2QueryAuthNodes[0].password, 'demo:pass');
assert.equal(hy2QueryAuthNodes[0].sni, 'hy.example.com');
assert.equal(hy2QueryAuthNodes[0].allowInsecure, true);
assert.equal(hy2QueryAuthNodes[0].ports, '443-8443');

const hy2Expanded = expandNodes(hy2Nodes, endpoints, { keepOriginalHost: true, namePrefix: 'CF' });
assert.equal(hy2Expanded.nodes.length, 2);
assert.equal(hy2Expanded.nodes[0].server, '104.16.1.2');
assert.equal(hy2Expanded.nodes[0].sni, 'hy.example.com');

const hy2Raw = Buffer.from(renderRawSubscription(hy2Expanded.nodes), 'base64').toString('utf8');
assert.match(hy2Raw, /hysteria2:\/\/demo%3Apass@104\.16\.1\.2:443/);
assert.match(hy2Raw, /obfs-password=obfs-secret/);

const hy2Clash = renderClashSubscription(hy2Expanded.nodes);
assert.match(hy2Clash, /type: hysteria2/);
assert.match(hy2Clash, /obfs-password: "obfs-secret"/);
assert.match(hy2Clash, /skip-cert-verify: true/);

const store = new Map();
const env = {
  SUB_ACCESS_TOKEN: 'token',
  SUB_STORE: {
    async get(key) {
      return store.get(key) || null;
    },
    async put(key, value) {
      store.set(key, value);
    },
  },
  ASSETS: {
    fetch() {
      return new Response('asset');
    },
  },
};

const generateResponse = await worker.fetch(
  new Request('https://sub.example.com/api/generate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      nodeLinks: hysteria2QueryAuth,
      preferredIps: '104.16.1.2#HK',
      keepOriginalHost: true,
    }),
  }),
  env,
);
const generatePayload = await generateResponse.json();
assert.equal(generateResponse.status, 200);
assert.equal(generatePayload.ok, true);
assert.equal(generatePayload.preview[0].type, 'hysteria2');

const badGenerateResponse = await worker.fetch(
  new Request('https://sub.example.com/api/generate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      nodeLinks: 'hy2://hy.example.com:443',
      preferredIps: '104.16.1.2#HK',
      keepOriginalHost: true,
    }),
  }),
  env,
);
const badGeneratePayload = await badGenerateResponse.json();
assert.equal(badGenerateResponse.status, 400);
assert.equal(badGeneratePayload.ok, false);
assert.match(badGeneratePayload.error, /Hysteria2/);

const missingKvResponse = await worker.fetch(
  new Request('https://sub.example.com/api/generate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      nodeLinks: hysteria2,
      preferredIps: '104.16.1.2#HK',
      keepOriginalHost: true,
    }),
  }),
  { SUB_ACCESS_TOKEN: 'token' },
);
const missingKvPayload = await missingKvResponse.json();
assert.equal(missingKvResponse.status, 500);
assert.equal(missingKvPayload.ok, false);
assert.match(missingKvPayload.error, /SUB_STORE/);

const secret = 'this-is-a-very-secret-key';
const token = await encryptPayload({ nodes: expanded.nodes }, secret);
const payload = await decryptPayload(token, secret);
assert.equal(payload.nodes.length, 2);

console.log('smoke test passed');
