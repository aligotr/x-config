// Источник: https://github.com/zeklop/shadowrocket-configs/blob/main/scripts/gemini-auto.js
// Shadowrocket: общий DNS/cron-скрипт. TLS проверяется штатным HTTP-клиентом.
// Разные HTTPS origins изолируют соединения провайдеров; Host у всех — Gemini.
// ponytail: IPv4 и одна стартовая страница; при потребности в проверке диалога
// нужен отдельный авторизованный монитор, без сохранения cookies в этом скрипте.
const PROVIDERS = [
  { id: 'xbox', url: 'https://xbox-dns.ru/dns-query', probe: 'ai.google.dev' },
  { id: 'geohide', url: 'https://geohide.ru/dns-query', probe: 'makersuite.google.com' },
  { id: 'bezmezhau', url: 'https://dns.bezmezhau.com/dns-query', probe: 'bard.google.com' },
  { id: 'comss', url: 'https://dns.comss.one/dns-query', probe: 'gemini.google' }
];
const KEY = 'gemini-auto-v1';
const TARGET = 'gemini.google.com';
const MAX_AGE = 180000;
const now = () => Date.now();
const log = message => console.log('GEMINI-AUTO ' + message);
function read() {
  try { return JSON.parse($persistentStore.read(KEY) || '{}'); }
  catch (_) { return {}; }
}
function save(state) { $persistentStore.write(JSON.stringify(state), KEY); }
function request(options, method = 'get') {
  return new Promise(resolve => $httpClient[method]({ policy: 'DIRECT', timeout: 4,
    'auto-redirect': false, ...options }, (error, response, data) => resolve({
      error, status: response && response.status, data
    })));
}
function query(host) {
  const bytes = [0x47, 0x4d, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
  for (const label of host.split('.')) {
    if (!/^[a-z0-9_-]{1,63}$/i.test(label)) throw new Error('Недопустимое имя');
    bytes.push(label.length, ...Array.from(label, c => c.charCodeAt(0)));
  }
  bytes.push(0, 0, 1, 0, 1);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = bytes[i] * 65536 + (bytes[i + 1] || 0) * 256 + (bytes[i + 2] || 0);
    result += alphabet[n >>> 18] + alphabet[(n >>> 12) & 63];
    if (i + 1 < bytes.length) result += alphabet[(n >>> 6) & 63];
    if (i + 2 < bytes.length) result += alphabet[n & 63];
  }
  return result;
}
function addresses(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 12) throw new Error('Короткий DNS');
  const word = p => {
    if (p + 2 > bytes.length) throw new Error('Короткая запись');
    return bytes[p] * 256 + bytes[p + 1];
  };
  function skip(p) {
    while (p < bytes.length) {
      const n = bytes[p++];
      if (!n) return p;
      if ((n & 192) === 192) { word(p - 1); return p + 1; }
      if (n > 63 || p + n > bytes.length) throw new Error('Битое имя');
      p += n;
    }
    throw new Error('Короткое имя');
  }
  if (word(0) !== 0x474d || !(bytes[2] & 128) || bytes[2] & 2 || (bytes[3] & 15)) {
    throw new Error('Ошибка DNS');
  }
  let p = 12;
  for (let i = 0; i < word(4); i++) { p = skip(p); word(p + 2); p += 4; }
  const result = [];
  for (let i = 0; i < word(6); i++) {
    p = skip(p);
    const type = word(p), klass = word(p + 2), length = word(p + 8);
    p += 10;
    if (p + length > bytes.length) throw new Error('Короткий RDATA');
    if (type === 1 && klass === 1 && length === 4) {
      const octets = Array.from(bytes.slice(p, p + 4));
      // Отсечь фильтрующие ответы, локальные/fake-IP и multicast.
      if (octets[0] !== 0 && octets[0] !== 10 && octets[0] !== 127 && octets[0] < 224 &&
          !(octets[0] === 169 && octets[1] === 254) &&
          !(octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) &&
          !(octets[0] === 192 && octets[1] === 168) &&
          !(octets[0] === 198 && (octets[1] === 18 || octets[1] === 19))) {
        result.push(octets.join('.'));
      }
    }
    p += length;
  }
  if (!result.length) throw new Error('Нет публичного IPv4');
  return [...new Set(result)];
}
async function resolve(provider, host, timeout = 4) {
  const r = await request({ url: provider.url + '?dns=' + query(host),
    headers: { Accept: 'application/dns-message' }, 'binary-mode': true, timeout });
  if (r.error || r.status !== 200) throw new Error('DoH ' + (r.status || r.error));
  return addresses(r.data);
}
async function dns(host) {
  const state = read();
  // Эти четыре имени закреплены за провайдерами: их origin нельзя переставлять
  // между IP, пока HTTP-клиент хранит живое соединение.
  const probe = PROVIDERS.find(p => p.probe === host);
  if (probe) {
    const binding = (state.bindings || {})[probe.id];
    if (!binding || !binding.ip) return { addresses: [], ttl: 1 };
    log('probe-dns ' + probe.id + ' ' + binding.ip);
    return { addresses: [binding.ip], ttl: 1 };
  }
  const provider = PROVIDERS.find(p => p.id === state.selected) || PROVIDERS[0];
  const binding = (state.bindings || {})[provider.id];
  if (host === TARGET && binding && binding.ok && now() - binding.ok < MAX_AGE) {
    log('dns ' + provider.id + ' ' + host + ' ' + binding.ip);
    return { addresses: [binding.ip], ttl: 30 };
  }
  // Не выдавать непроверенный шлюз Gemini, в том числе до первого cron.
  if (host === TARGET) return { addresses: [], ttl: 1 };
  // Обычные Google-ресурсы не должны ждать cron при отказе DoH.
  // Четыре короткие попытки помещаются в timeout DNS-скрипта; Comss последним.
  const ordered = [provider, ...PROVIDERS.filter(p => p.id !== provider.id)];
  let lastError;
  for (const candidate of ordered) {
    try {
      const ips = await resolve(candidate, host, 1);
      log('dns ' + candidate.id + ' ' + host + ' ' + ips.join(','));
      return { addresses: ips, ttl: 30 };
    } catch (error) { lastError = error; }
  }
  throw lastError;
}
async function monitor() {
  const state = read();
  state.bindings = state.bindings || {};
  const previous = state.selected;
  const ordered = [...PROVIDERS].sort((a, b) =>
    (b.id === previous ? 1 : 0) - (a.id === previous ? 1 : 0));
  let selected;
  for (const provider of ordered) {
    try {
      const ips = await resolve(provider, TARGET);
      let binding = state.bindings[provider.id];
      if (!binding || !binding.ip) binding = { ip: ips[0] };
      state.bindings[provider.id] = binding;
      save(state); // DNS-скрипт вызывается другим JS-контекстом.
      const full = !binding.page || now() - binding.page > 600000;
      const r = await request({ url: 'https://' + provider.probe + '/app?health=' + now(),
        headers: { Host: TARGET, 'Cache-Control': 'no-cache' } }, full ? 'get' : 'head');
      const page = !full || (typeof r.data === 'string' &&
        /<title[^>]*>[^<]*Gemini/i.test(r.data) &&
        !/Gemini isn[’']t currently supported in your country/i.test(r.data));
      if (r.error || r.status !== 200 || !page) throw new Error('HTTPS ' + (r.status || r.error));
      binding.ok = now();
      if (full) binding.page = now();
      selected = provider.id;
      log('healthy ' + provider.id + ' ip=' + binding.ip + ' version=2');
      break;
    } catch (error) {
      log('failed ' + provider.id + ' ' + String(error));
      // HTTP timeout не доказывает закрытие pooled-соединения. Binding
      // сохраняется и после ошибки: непроверенный новый IP не выдаём.
      if (state.bindings[provider.id]) state.bindings[provider.id].ok = 0;
      save(state);
    }
  }
  if (selected) state.selected = selected;
  state.checked = now();
  state.unavailable = !selected;
  save(state);
  if (selected && previous !== selected) {
    log('selected ' + selected);
    $notification.post('Gemini Smart DNS', 'Выбран ' + selected, 'Проверка стартовой страницы прошла; статус аккаунта не проверяется');
  } else if (!selected) log('unavailable: все проверки не прошли');
}
(typeof $domain === 'string' ? dns($domain.toLowerCase().replace(/\.$/, '')) : monitor())
  .then(result => $done(result || {}))
  .catch(error => { log('error ' + String(error)); $done({ addresses: [], ttl: 1 }); });
