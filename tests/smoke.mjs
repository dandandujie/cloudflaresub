import assert from 'node:assert/strict';
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

const secret = 'this-is-a-very-secret-key';
const token = await encryptPayload({ nodes: expanded.nodes }, secret);
const payload = await decryptPayload(token, secret);
assert.equal(payload.nodes.length, 2);

console.log('smoke test passed');
