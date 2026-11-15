import { newTransfer, parseTransferLink, transferLink } from './src/envelope.mjs';
import { compareRevision, openRevision, sealRevision } from './src/direct-revision.mjs';
import { createPublication, publishPublication, readPublication, saveCheckpoint, createWriterLink,
  claimWriter, exchangeSettings, readWriterLink, prepareContinuation, enableContinuation, saveContinuation,
  enrollRotationKey, rotatePublication } from './src/publication.mjs';
import { createRotationKeyPair, openRotationAccess, sealRotationAccess } from './src/rotation-client.mjs';
import { parseInvitationLink } from './src/pairing-client.mjs';
import { normalizeCode } from './src/short-code-crypto.mjs';
import { registerShortCode, resolveShortCode, ShortCodeError } from './src/short-code.mjs';
import { createEditorState, editDraft, prepareSend, receiveVersion } from './src/editor-state.mjs';
import { qrImage } from './qr.mjs';
import { setupPairing } from './pair.mjs';

const controls = Object.fromEntries(Array.from(document.querySelectorAll('[id]'), node => [node.id, node]));
const editor = controls.draft;
const status = controls.status;
const sharePanel = controls['share-dialog'];
const originPage = new URL(location.pathname, location.origin);
const expiryFormat = new Intl.DateTimeFormat('ru', { dateStyle: 'medium', timeStyle: 'short' });
const drafts = new Map();
let session;
let files = [];
let readFiles = [];
let downloads = [];
let busy = false;
let revision = 0;
let savedRevision = 0;
let generation = 0;
let qrGeneration = 0;
let qrUrl;
let peer;
const exchangeDialog = controls['exchange-dialog'];
const writable = current => Boolean(current?.owner || current?.writer && current.canWrite || current?.direct);
const writerKey = id => 'hop.writer.' + id;
const groupFor = current => current.stableId ?? current.access.id;
const groupKey = locator => 'hop.group.' + locator;
const rotationKey = (group, owner) => 'hop.rotation.' + (owner ? 'owner.' : 'writer.') + group;
const enrolling = new Map();
let refreshBusy = false;
let conflictVersion;
let revocation;
const compose = () => ({ text: editor.value, files: Array.from(files) });

function remember(key, value) {
  try { localStorage.setItem(key, value); } catch { /* Storage may be disabled. */ }
}

function recall(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}

function ownerKey(id) {
  return 'hop.owner.' + id;
}

function localRotationKey(group, owner) {
  try { return JSON.parse(recall(rotationKey(group, owner))); }
  catch { return null; }
}

async function rotationKeyFor(group, credential, owner) {
  const key = rotationKey(group, owner);
  if (enrolling.has(key)) return enrolling.get(key);
  const task = async () => {
    const stored = localRotationKey(group, owner);
    if (stored?.credential === credential) return stored;
    const candidate = stored ?? await createRotationKeyPair();
    remember(key, JSON.stringify(candidate));
    if (!localRotationKey(group, owner)) throw Error('Browser storage is unavailable');
    await enrollRotationKey(group, credential, candidate.publicKey);
    const ready = { ...candidate, credential };
    remember(key, JSON.stringify(ready));
    return ready;
  };
  const pending = navigator.locks.request(key, task);
  enrolling.set(key, pending);
  try { return await pending; }
  finally { enrolling.delete(key); }
}

const shortCodeKey = id => 'hop.short-code.' + id;

function report(text = '', error = false) {
  status.textContent = text;
  status.toggleAttribute('data-error', error);
}

function explain(error) {
  switch (error?.status) {
    case 404: return 'Передача не найдена или срок истёк. Проверь ссылку.';
    case 410: return 'Срок передачи истёк.';
    case 507: return 'Хранилище заполнено. Попробуй отправить позже.';
    case 413: return 'Передача слишком большая. Уменьши объём текста или файлов.';
    case 409: return 'Передача уже обновилась. Скопируй черновик и открой актуальную версию.';
    case 401:
    case 403: return 'Право на отправку недоступно. Создай новую передачу.';
    default:
      if (error?.name === 'OperationError') return 'Не удалось расшифровать передачу. Проверь полную ссылку.';
      return 'Не удалось обратиться к передаче. Проверь соединение и попробуй ещё раз.';
  }
}

function lock(value) {
  busy = value;
  for (const id of ['create', 'send', 'home-button']) controls[id].disabled = value;
  controls['open-form'].querySelector('button').disabled = value;
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  controls.theme.setAttribute('aria-pressed', String(theme === 'dark'));
  remember('hop.theme', theme);
}
applyTheme(recall('hop.theme') ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
controls.theme.addEventListener('click', () => {
  applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});

function showExpiry() {
  const time = controls.expires;
  if (!session?.expiresAt) {
    time.hidden = true;
    return;
  }
  const minutes = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 60_000));
  time.dateTime = new Date(session.expiresAt).toISOString();
  time.title = 'До ' + expiryFormat.format(session.expiresAt);
  time.textContent = minutes > 0 ? 'Осталось ' + new Intl.NumberFormat('ru', {
    style: 'unit', unit: minutes >= 60 ? 'hour' : 'minute', unitDisplay: 'long',
  }).format(minutes >= 60 ? Math.ceil(minutes / 60) : minutes) : 'Срок истёк';
  time.hidden = false;
}
setInterval(showExpiry, 30_000);

function clearDownloads() {
  for (const url of downloads) URL.revokeObjectURL(url);
  downloads = [];
}

function showFiles(editable) {
  clearDownloads();
  const selected = editable ? files : readFiles;
  controls['file-count'].textContent = selected.length;
  const list = editable ? controls['draft-files'] : controls['received-files'];
  const other = editable ? controls['received-files'] : controls['draft-files'];
  other.replaceChildren();
  other.hidden = true;
  list.hidden = false;
  list.replaceChildren();
  for (const [index, file] of selected.entries()) {
    const item = document.createElement('li');
    if (editable) {
      const name = document.createElement('span');
      if (session?.direct) {
        const download = document.createElement('a');
        download.href = URL.createObjectURL(file.blob);
        downloads.push(download.href);
        download.download = file.name;
        download.textContent = file.name;
        name.append(download);
      } else name.textContent = file.name;
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'button';
      remove.textContent = 'Убрать';
      remove.setAttribute('aria-label', 'Убрать файл ' + file.name);
      remove.addEventListener('click', () => {
        files.splice(index, 1);
        ++revision;
        showFiles(true);
        (list.children[index]?.querySelector('button') ?? list.lastElementChild?.querySelector('button') ?? controls.attachments).focus();
      });
      item.append(name, remove);
    } else {
      const link = document.createElement('a');
      link.href = URL.createObjectURL(file.blob);
      downloads.push(link.href);
      link.download = file.name;
      link.textContent = file.name;
      item.append(link);
    }
    list.append(item);
  }
  controls['files-empty'].hidden = selected.length !== 0;
}

function showWorkspace(current, content) {
  saveDraft();
  const sameTransfer = session?.access.id === current.access.id;
  session = current;
  controls.home.hidden = true;
  controls.workspace.hidden = false;
  controls['new-connection'].hidden = false;
  if (!sameTransfer) selectView('text');
  controls.share.hidden = Boolean(current.revoked || (current.direct && !current.continuation));
  const editable = writable(current);
  controls['read-only'].hidden = editable || Boolean(current.revoked);
  controls['exchange-open'].hidden = !current.owner;
  conflictVersion = undefined;
  controls.send.textContent = 'Отправить';
  editor.hidden = !editable;
  controls['read-text'].hidden = editable;
  controls.send.hidden = !editable;
  controls['copy-text'].hidden = false;
  controls['copy-text'].disabled = !content.text;
  controls['attach-control'].hidden = !editable;
  if (editable) {
    const unsent = drafts.get(current.access.id);
    const draft = unsent ?? content;
    editor.value = draft.text;
    controls['copy-text'].disabled = !draft.text;
    files = Array.from(draft.files);
    savedRevision = revision;
    if (unsent) ++revision;
    controls['draft-label'].htmlFor = 'draft';
  } else {
    controls['read-text'].textContent = content.text;
    controls['copy-text'].disabled = !content.text;
    controls['draft-label'].removeAttribute('for');
    readFiles = content.files;
  }
  showFiles(editable);
  showExpiry();
  if (editable && controls.workspace.dataset.view !== 'files' && sharePanel.hidden) editor.focus();
  else if (current.revoked) (content.text ? controls['copy-text'] : controls['home-button']).focus();
  else controls.share.focus();
}

function saveDraft() {
  if (!(session?.owner || session?.writer) || !writable(session)) return;
  if (revision === savedRevision) drafts.delete(session.access.id);
  else drafts.set(session.access.id, { text: editor.value, files: Array.from(files) });
}

function showHome({ preserveHash = false } = {}) {
  saveDraft();
  peer = undefined;
  pairing.close();
  if (!sharePanel.hidden) closeShare(false);
  if (exchangeDialog.open) exchangeDialog.close();
  clearDownloads();
  session = undefined;
  files = [];
  readFiles = [];
  editor.value = '';
  controls['read-text'].textContent = '';
  controls.attachments.value = '';
  controls['open-url'].value = '';
  controls.workspace.hidden = true;
  controls['new-connection'].hidden = true;
  controls.share.hidden = true;
  controls.home.hidden = false;
  if (location.hash && !preserveHash) history.replaceState(null, '', originPage.href);
  report();
  controls.create.focus();
}

controls['home-button'].addEventListener('click', showHome);
controls['new-connection'].addEventListener('click', showHome);

function selectView(view) {
  controls.workspace.dataset.view = view;
  for (const name of ['text', 'files']) controls['view-' + name].setAttribute('aria-pressed', String(view === name));
}

controls['view-text'].addEventListener('click', () => selectView('text'));
controls['view-files'].addEventListener('click', () => selectView('files'));
const deviceType = /iPhone|iPad|Android/i.test(navigator.userAgent) ? 'Телефон или планшет'
  : /Windows/i.test(navigator.userAgent) ? 'Компьютер Windows'
  : /Macintosh/i.test(navigator.userAgent) ? 'Mac' : '';
if (deviceType) controls['device-name'].textContent = deviceType;
if (/iPhone|iPad|Android/i.test(navigator.userAgent)) controls['device-icon'].setAttribute('href', '#i-phone');


controls.create.addEventListener('click', async () => {
  if (busy) return;
  const request = ++generation;
  lock(true);
  report('Создаём ссылку…');
  try {
    const created = await createPublication({ text: '', files: [] });
    if (request !== generation) return;
    remember(ownerKey(created.access.id), created.owner);
    history.replaceState(null, '', transferLink(originPage, created.access));
    showWorkspace(created, { text: '', files: [] });
    report('Ссылка готова. Нажми «Отправить», чтобы опубликовать данные.');
  } catch (error) {
    if (request === generation) report(explain(error), true);
  } finally {
    if (request === generation) {
      lock(false);
      if (!controls.home.hidden) controls.create.focus();
    }
  }
});

async function open(access, offeredWriter, shortCode, offeredGroup) {
  peer = undefined;
  pairing.close();
  const request = ++generation;
  if (!sharePanel.hidden) closeShare(false);
  if (exchangeDialog.open) exchangeDialog.close();
  lock(true);
  report('Открываем передачу…');
  try {
    if (shortCode) access = await resolveShortCode(shortCode);
    const stableId = offeredGroup ?? recall(groupKey(access.id)) ?? access.id;
    const owner = recall(ownerKey(stableId));
    let writer = owner ? null : recall(writerKey(stableId));
    let rejectedWriter;
    let settings;
    if (owner || writer) {
      try {
        settings = await exchangeSettings(stableId, owner ?? writer);
        if (settings.locator && settings.locator !== access.id) {
          const keys = localRotationKey(stableId, Boolean(owner));
          access = await openRotationAccess(stableId, settings.locator, settings.recovery, keys?.privateKey);
        }
      } catch (error) {
        if (error.status !== 403 || owner) throw error;
        rejectedWriter = writer;
        writer = null;
      }
    }
    const incoming = await readPublication(access);
    if (offeredWriter && !owner && !writer) {
      const pendingKey = 'hop.claim.' + stableId;
      const key = rotationKey(stableId, false);
      writer = await navigator.locks.request(key, async () => {
        const claimed = recall(writerKey(stableId));
        if (claimed && claimed !== rejectedWriter) return claimed;
        const device = recall(pendingKey) ?? newTransfer().secret;
        const candidate = localRotationKey(stableId, false) ?? await createRotationKeyPair();
        remember(pendingKey, device);
        remember(key, JSON.stringify(candidate));
        if (!localRotationKey(stableId, false)) throw Error('Browser storage is unavailable');
        try { await claimWriter(stableId, offeredWriter, device, access.id, candidate.publicKey); }
        catch (error) { if (error.status === 403) return null; throw error; }
        remember(writerKey(stableId), device);
        remember(key, JSON.stringify({ ...candidate, credential: device }));
        try { localStorage.removeItem(pendingKey); } catch { /* Storage may be disabled. */ }
        return device;
      });
    }
    if (writer) {
      try { settings ??= await exchangeSettings(stableId, writer); }
      catch (error) { if (error.status !== 403) throw error; writer = null; }
    }
    if (request !== generation) return;
    if (writer) {
      remember(writerKey(stableId), writer);
      void rotationKeyFor(stableId, writer, false).catch(() => {});
    }
    if (owner || writer) remember(groupKey(access.id), stableId);
    if (offeredWriter || shortCode || settings?.locator === access.id) {
      history.replaceState(null, '', transferLink(originPage, access));
    }
    showWorkspace({ ...incoming, access, stableId, owner, writer, canWrite: settings?.canWrite }, incoming.content);
    report(incoming.content.text || incoming.content.files.length ? '' : 'Данные ещё не отправлены.');
  } catch (error) {
    if (request !== generation) return;
    showHome();
    if (shortCode) {
      controls['open-url'].value = shortCode;
      report(shortCodeError(error), true);
    } else report(explain(error), true);
  } finally {
    if (request === generation) {
      lock(false);
      if (!controls.home.hidden) controls['open-url'].focus();
    }
  }
}

function shortCodeError(error) {
  if (error.status === 404) return 'Код не найден или срок передачи истёк. Проверь код или открой полную ссылку.';
  if (error.status === 429) return 'Слишком много попыток. Подожди минуту или открой полную ссылку.';
  if (error instanceof ShortCodeError && error.code === 'registered') return 'Код уже создан в другом окне. Можно скопировать полную ссылку.';
  return 'Код сейчас недоступен. Попробуй ещё раз или воспользуйся полной ссылкой.';
}

controls['open-form'].addEventListener('submit', event => {
  event.preventDefault();
  if (busy) return;
  const input = controls['open-url'].value.trim();
  const code = normalizeCode(input);
  if (code) {
    void open(null, null, code);
    return;
  }
  let access;
  let writer;
  let offeredGroup;
  try {
    const url = new URL(input);
    if (url.origin !== location.origin || url.pathname !== originPage.pathname) throw Error();
    if (url.hash.startsWith('#pair/')) {
      const invitation = parseInvitationLink(url);
      history.replaceState(null, '', url.href);
      openPair(invitation);
      return;
    }
    const invite = readWriterLink(url);
    writer = invite.writer;
    offeredGroup = invite.stableId;
    access = parseTransferLink(invite.url);
  } catch {
    report('Введи 8 символов кода или вставь полную ссылку на передачу.', true);
    controls['open-url'].focus();
    return;
  }
  controls['open-url'].value = '';
  if (writer) {
    const invited = new URL(transferLink(originPage, access));
    invited.hash += '/write/' + writer;
    if (offeredGroup) invited.hash += '/group/' + offeredGroup;
    history.replaceState(null, '', invited);
  } else history.replaceState(null, '', transferLink(originPage, access));
  void open(access, writer, null, offeredGroup);
});

controls.attachments.addEventListener('change', event => {
  const added = Array.from(event.target.files, blob => ({ name: blob.name, blob }));
  event.target.value = '';
  if (!added.length) return;
  const next = [...files, ...added];
  const bytes = next.reduce((sum, { blob }) => sum + blob.size, 0);
  if (next.length > 10) return report('К передаче можно добавить до 10 файлов.', true);
  if (bytes > 100_000_000) return report('Файлы вместе должны занимать не больше 100 МБ.', true);
  files = next;
  ++revision;
  showFiles(true);
  report();
});

editor.addEventListener('input', () => { ++revision; controls['copy-text'].disabled = !editor.value; });

controls.send.addEventListener('click', async () => {
  if (busy || !writable(session)) return;
  const text = editor.value;
  if (new TextEncoder().encode(text).length > 1_048_576) {
    report('Текст слишком большой. Уменьши объём до 1 МиБ.', true);
    return;
  }
  if (session.direct) return sendToPeer();
  if (conflictVersion === session.version) {
    conflictVersion = undefined;
    report('Нажми «Отправить» ещё раз, чтобы заменить полученную версию.');
    return;
  }
  const request = ++generation;
  const sentRevision = revision;
  lock(true);
  report('Отправляем…');
  try {
    const result = await publishPublication({ ...session, owner: session.owner ?? session.writer }, { text, files: Array.from(files) });
    if (request !== generation) return;
    session = { ...session, ...result };
    savedRevision = sentRevision;
    showExpiry();
    report(revision === savedRevision ? 'Отправлено.' : 'Отправлено. Новые изменения ещё не отправлены.');
  } catch (error) {
    if (request === generation) report(explain(error), true);
  } finally {
    if (request === generation) {
      lock(false);
      controls.send.focus();
    }
  }
});

async function copy(text, message, output = report) {
  try {
    await navigator.clipboard.writeText(text);
    output(message);
  } catch {
    output('Не удалось скопировать. Выдели и скопируй вручную.', true);
  }
}

controls['copy-text'].addEventListener('click', () => {
  void copy(writable(session) ? editor.value : controls['read-text'].textContent, 'Текст скопирован.');
});
controls['copy-link'].addEventListener('click', () => {
  void copy(controls['share-url'].value, 'Ссылка скопирована.', text => { controls['qr-status'].textContent = text; });
});

function savedShortCode(id) {
  try {
    const saved = JSON.parse(recall(shortCodeKey(id)));
    return normalizeCode(saved?.code ?? '') && Number.isSafeInteger(saved.epoch) ? saved : null;
  } catch { return null; }
}

function showShortCode(code) {
  controls['enable-short-code'].hidden = Boolean(code);
  controls['copy-short-code'].hidden = controls['short-code'].hidden = !code;
  controls['short-code'].value = code ? code.slice(0, 4) + ' ' + code.slice(4) : '';
}

controls['enable-short-code'].addEventListener('click', async () => {
  const current = session;
  if (sharePanel.hidden || !current?.owner || current.direct || current.creatingCode) return;
  const button = controls['enable-short-code'];
  const key = shortCodeKey(current.access.id);
  const stillSharing = () => !sharePanel.hidden && session?.access.id === current.access.id;
  const save = value => {
    current.shortCode = value;
    if (session?.access.id === current.access.id) session.shortCode = value;
    remember(key, JSON.stringify(value));
  };
  let pending = current.shortCode ?? savedShortCode(current.access.id);
  current.creatingCode = true;
  button.disabled = true;
  controls['short-code-status'].textContent = 'Создаём код…';
  try {
    const code = await registerShortCode(current.access, current.owner, pending, value => {
      pending = value;
      save(value);
    });
    save({ ...pending, ready: true });
    if (!stillSharing()) return;
    showShortCode(code);
    controls['short-code-status'].textContent = '';
    controls['short-code'].focus();
  } catch (error) {
    if (!stillSharing()) return;
    controls['short-code-status'].textContent = shortCodeError(error);
  } finally {
    current.creatingCode = false;
    if (session?.access.id === current.access.id) session.creatingCode = false;
    if (stillSharing()) button.disabled = false;
  }
});

controls.share.addEventListener('click', async () => {
  if (!session) return;
  if (!sharePanel.hidden) return closeShare();
  const link = transferLink(originPage, session.continuation ?? session.access);
  const request = ++qrGeneration;
  controls['short-code-controls'].hidden = !session.owner || Boolean(session.direct);
  const saved = session.shortCode ?? savedShortCode(session.access.id);
  showShortCode(saved?.ready ? saved.code : null);
  controls['enable-short-code'].disabled = Boolean(session.creatingCode);
  controls['short-code-status'].textContent = session.creatingCode ? 'Создаём код…' : '';
  controls['share-url'].value = link;
  controls['qr-status'].textContent = session.direct && !peer?.checkpointSaved
    ? 'По этой ссылке данные откроются после сохранения передачи.' : '';
  controls['qr-box'].replaceChildren();
  controls['share-writer'].hidden = !session.owner || Boolean(session.direct);
  controls['share-instruction'].textContent = controls['short-code-controls'].hidden
    ? 'Сканируй QR камерой или скопируй ссылку.' : 'Сканируй QR или введи код на главной Hop.';
  sharePanel.hidden = false;
  controls.share.setAttribute('aria-expanded', 'true');
  controls['close-share'].focus();
  try {
    const image = await qrImage(link);
    if (sharePanel.hidden || request !== qrGeneration) return;
    if (qrUrl) URL.revokeObjectURL(qrUrl);
    qrUrl = URL.createObjectURL(image);
    const qr = document.createElement('img');
    qr.id = 'qr-image';
    qr.width = qr.height = 240;
    qr.alt = 'QR со ссылкой на передачу';
    qr.src = qrUrl;
    controls['qr-box'].replaceChildren(qr);
  } catch {
    if (!sharePanel.hidden && request === qrGeneration) controls['qr-status'].textContent = 'QR недоступен. Скопируй ссылку.';
  }
});

controls['close-share'].addEventListener('click', () => closeShare());
controls['copy-short-code'].addEventListener('click', () => {
  void copy(controls['short-code'].value, 'Код скопирован.', text => { controls['short-code-status'].textContent = text; });
});
controls['share-writer'].addEventListener('click', () => {
  closeShare(false);
  controls['exchange-open'].click();
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && !sharePanel.hidden && !exchangeDialog.open) closeShare();
});

function closeShare(restore = true) {
  ++qrGeneration;
  sharePanel.hidden = true;
  controls.share.setAttribute('aria-expanded', 'false');
  if (qrUrl) URL.revokeObjectURL(qrUrl);
  qrUrl = undefined;
  controls['qr-box'].replaceChildren();
  controls['share-url'].value = '';
  controls['short-code'].value = '';
  if (restore && !controls.share.hidden) controls.share.focus();
}

const pairing = setupPairing({
  onConnected({ channel, role, access, continuation: recovery }) {
    const empty = { text: '', files: [] };
    const { access: continuation, writer } = recovery;
    const current = { channel, role, access, continuation, writer, state: createEditorState(0, empty), latest: null, order: { clock: 0, role } };
    peer = current;
    showWorkspace({ direct: true, access, continuation }, empty);
    history.replaceState(null, '', transferLink(originPage, continuation));
    current.preparation = role === 'owner'
      ? prepareContinuation(continuation, writer, owner => {
        current.owner = owner;
        remember(ownerKey(continuation.id), owner);
      }).catch(() => null)
      : null;
    if (role === 'recipient') remember(writerKey(continuation.id), writer);
    report('Устройства соединены.');
  },
  async onEnvelope(blob, { access }) {
    const current = peer;
    if (!current || current.access.id !== access.id) throw Error('Pair is closed');
    const other = current.role === 'owner' ? 'recipient' : 'owner';
    const received = await openRevision(access, blob, other);
    if (peer !== current) throw Error('Pair is closed');
    if (compareRevision(received.revision, current.order) <= 0) return;
    if (current.pending && compareRevision(received.revision, current.pending.order) < 0) {
      current.pending.fallback = received;
      return;
    }
    applyIncoming(current, received);
  },
  onDisconnected({ access }) {
    if (!peer || peer.access.id !== access.id) return;
    peer.channel = null;
    controls.send.textContent = 'Сохранить по ссылке';
    report('Соединение прервано. Можно сохранить данные по ссылке.');
    void saveAfterDisconnect(peer);
  },
});

function applyIncoming(current, { revision: order, content }) {
  const supersedesConcurrentSend = order.clock === current.order.clock && current.order.role === current.role;
  current.order = order;
  current.latest = content;
  if (supersedesConcurrentSend && revision === savedRevision) ++revision;
  const state = revision === savedRevision ? current.state : editDraft(current.state, compose());
  current.state = receiveVersion(state, state.version + 1, content);
  if (!current.state.dirty) {
    editor.value = content.text;
    controls['copy-text'].disabled = !editor.value;
    files = Array.from(content.files);
    showFiles(true);
    report('Получено.');
  } else {
    report('Пришла новая версия с другого устройства. Черновик сохранён.');
  }
}

async function saveAfterDisconnect(current) {
  if (busy || peer !== current || current.channel || !current.latest || current.checkpointSaved) return;
  lock(true);
  try {
    const access = current.continuation;
    const prepared = await current.preparation;
    if (!prepared && current.owner) await enableContinuation(access, current.owner, current.writer);
    const credential = current.owner ?? current.writer;
    let settings;
    try { settings = await exchangeSettings(access.id, credential); }
    catch (error) { if (error.status !== 404 && error.status !== 403) throw error; }
    const canContinue = Boolean(settings?.canWrite);
    const stored = canContinue
      ? settings.version === 1
        ? await saveContinuation({ access, owner: credential, version: 1 }, current.latest)
        : await readPublication(access, { confirm: false })
      : await saveCheckpoint(access, current.latest);
    if (peer !== current) return;
    if (canContinue) {
      const dirty = revision !== savedRevision;
      const draft = compose();
      const content = stored.content ?? current.latest;
      if (dirty) drafts.set(access.id, draft);
      peer = undefined;
      pairing.close();
      showWorkspace({ access, ...stored, owner: current.owner, writer: current.owner ? null : current.writer, canWrite: true }, content);
      report(dirty ? 'Передача сохранена по ссылке. Черновик ещё не отправлен.' : 'Передача сохранена по ссылке.');
      return;
    }
    current.checkpointSaved = true;
    session = { ...session, continuation: access, expiresAt: stored.expiresAt };
    history.replaceState(null, '', transferLink(originPage, current.continuation));
    controls.share.hidden = false;
    controls.send.textContent = 'Новая публикация';
    showExpiry();
    report(revision !== savedRevision ? 'Передача сохранена по ссылке. Черновик ещё не отправлен.' : 'Передача сохранена по ссылке.');
  } catch (error) {
    if (peer === current) {
      const message = error.status === 403 || error.status === 409
        ? 'Другое устройство сохраняет передачу. Попробуй открыть ссылку или повторить сохранение.'
        : explain(error);
      report(message, true);
    }
  } finally {
    lock(false);
  }
}

async function sendToPeer() {
  const current = peer;
  if (!current) return;
  const content = compose();
  const sentRevision = revision;
  if (current.channel) {
    if (current.draftRevision !== revision) {
      current.state = editDraft(current.state, content);
      current.draftRevision = revision;
    }
    const intent = prepareSend(current.state);
    current.state = intent.state;
    if (!intent.request) {
      report('Отправка заменит полученную версию. Нажми «Отправить» ещё раз.');
      return;
    }
  }
  lock(true);
  try {
    if (!current.channel) {
      if (current.latest && !current.checkpointSaved) {
        lock(false);
        await saveAfterDisconnect(current);
        return;
      }
      const saved = await createPublication(content);
      if (peer !== current) return;
      peer = undefined;
      pairing.close();
      remember(ownerKey(saved.access.id), saved.owner);
      history.replaceState(null, '', transferLink(originPage, saved.access));
      const remaining = compose();
      const hasChanges = revision !== sentRevision;
      showWorkspace(saved, hasChanges ? remaining : content);
      if (hasChanges) ++revision;
      report(hasChanges ? 'Сохранено. Новые изменения ещё не отправлены.' : 'Сохранено. Передачу можно открыть по ссылке.');
      return;
    }
    const version = current.state.version;
    const order = { clock: current.order.clock + 1, role: current.role };
    const pending = { order, fallback: null };
    current.pending = pending;
    const blob = await sealRevision(current.access, order, content);
    if (peer !== current || !current.channel) throw Error('Pair is closed');
    if (current.state.version !== version) {
      report('Пришла новая версия. Проверь черновик перед отправкой.');
      return;
    }
    await current.channel.send(blob);
    if (peer !== current) return;
    if (current.state.version === version) {
      current.order = order;
      current.latest = content;
      current.state = createEditorState(version, content);
      savedRevision = sentRevision;
      current.draftRevision = undefined;
      report(revision === savedRevision ? 'Отправлено.' : 'Отправлено. Новые изменения ещё не отправлены.');
    }
  } catch (error) {
    if (peer === current) {
      const fallback = current.pending?.fallback;
      if (fallback && compareRevision(fallback.revision, current.order) > 0) applyIncoming(current, fallback);
      report(current.channel ? explain(error) : 'Соединение прервано. Можно сохранить черновик по ссылке.', true);
    }
  } finally {
    current.pending = null;
    lock(false);
    if (!controls.send.hidden) controls.send.focus();
    void saveAfterDisconnect(current);
  }
}

function openPair(invitation) {
  ++generation;
  lock(false);
  showHome({ preserveHash: true });
  pairing.open(invitation);
}

async function refreshExchange() {
  const current = session;
  if (busy || refreshBusy || current?.direct || !(current?.owner || current?.writer)) return;
  refreshBusy = true;
  try {
    let settings;
    const stableId = groupFor(current);
    try { settings = await exchangeSettings(stableId, current.owner ?? current.writer); }
    catch (error) {
      if (error.status !== 403 || current.owner || session !== current) throw error;
      let readOnly;
      try { readOnly = await readPublication(current.access, { confirm: false }); }
      catch (readError) {
        if (readError.status !== 404 || session !== current || busy) throw readError;
        const local = writable(current) ? compose() : drafts.get(current.access.id) ??
          { text: controls['read-text'].textContent, files: readFiles };
        try { localStorage.removeItem(writerKey(stableId)); } catch { /* Storage may be disabled. */ }
        showWorkspace({ access: current.access, stableId, revoked: true }, local);
        report('Владелец отключил доступ. Текст и файлы из этой вкладки можно сохранить.', true);
        return;
      }
      if (session !== current || busy) return;
      showWorkspace({ ...current, ...readOnly, writer: null, canWrite: false }, readOnly.content);
      try { localStorage.removeItem(writerKey(stableId)); } catch { /* Storage may be disabled. */ }
      report('Владелец отключил запись. Передачу ещё можно читать.');
      return;
    }
    if (session !== current || busy) return;
    if (current.writer) void rotationKeyFor(stableId, current.writer, false).catch(() => {});
    renderExchange(settings);
    const rotated = settings.locator && settings.locator !== current.access.id;
    if (!rotated && settings.version === current.version && settings.canWrite === writable(current)) return;
    let access = current.access;
    if (rotated) {
      const pair = localRotationKey(stableId, Boolean(current.owner));
      access = await openRotationAccess(stableId, settings.locator, settings.recovery, pair?.privateKey);
    }
    const incoming = await readPublication(access, { confirm: false });
    if (session !== current || busy) return;
    const contentMayHaveChanged = incoming.contentVersion > (current.contentVersion ?? current.version);
    const changed = contentMayHaveChanged && revision !== savedRevision && writable(current);
    const active = document.activeElement;
    const previousConflict = conflictVersion;
    if (rotated) {
      remember(groupKey(access.id), stableId);
      history.replaceState(null, '', transferLink(originPage, access));
      if (revision !== savedRevision) drafts.set(access.id, compose());
      if (!sharePanel.hidden) closeShare(false);
      clearWriterLink();
    }
    showWorkspace({ ...current, ...incoming, access, stableId, canWrite: settings.canWrite,
      ...(rotated && { shortCode: null, creatingCode: false }) }, incoming.content);
    if (previousConflict !== undefined && writable(session)) conflictVersion = incoming.version;
    if (active?.getClientRects().length && (!exchangeDialog.open || exchangeDialog.contains(active))) active.focus();
    if (changed) {
      conflictVersion = incoming.version;
      report('Пришла новая версия. Черновик сохранён.');
    }
  } catch { /* A retry on the next tick keeps local edits intact. */ }
  finally { refreshBusy = false; }
}

function closeRevocation() {
  const member = revocation?.member;
  revocation = undefined;
  controls['revoke-confirm'].hidden = true;
  controls['exchange-controls'].hidden = false;
  if (exchangeDialog.open && member) {
    (controls['exchange-members'].querySelector(`[data-member="${CSS.escape(member)}"]`)
      ?? controls['exchange-close']).focus();
  }
}

function clearWriterLink() {
  controls['copy-writer'].hidden = true;
  controls['writer-status'].textContent = '';
  controls['writer-link'].value = '';
  controls['writer-link'].hidden = controls['writer-label'].hidden = true;
}

function revokeStatus(message = '') {
  controls['revoke-status'].textContent = message;
  controls['revoke-status'].hidden = !message;
}

controls['revoke-cancel'].addEventListener('click', closeRevocation);
controls['revoke-apply'].addEventListener('click', async () => {
  const current = session;
  const { member } = revocation ?? {};
  if (!member || !current?.owner || busy) return;
  const stableId = groupFor(current);
  const button = controls['revoke-apply'];
  button.disabled = true;
  controls['revoke-cancel'].disabled = controls['exchange-close'].disabled = true;
  lock(true);
  revokeStatus('Обновляем доступ…');
  try {
    const ownerKeys = await rotationKeyFor(stableId, current.owner, true);
    const settings = await exchangeSettings(stableId, current.owner);
    if (settings.locator !== current.access.id) throw Object.assign(Error(), { status: 409 });
    const remaining = settings.members.filter(entry => entry.id !== member);
    if (remaining.some(entry => !entry.key)) {
      revokeStatus('Попроси остальных участников открыть передачу, чтобы они сохранили доступ.');
      return;
    }
    const incoming = await readPublication(current.access, { confirm: false });
    const access = newTransfer();
    const recovery = await Promise.all([
      { id: 'owner', key: ownerKeys.publicKey }, ...remaining,
    ].map(async entry => ({ member: entry.id, wrapper: await sealRotationAccess(stableId, access, entry.key) })));
    const saved = await rotatePublication({ ...current, stableId, version: incoming.version }, incoming.content,
      { member, access, recovery });
    remember(groupKey(access.id), stableId);
    if (session !== current) return;
    if (revision !== savedRevision) drafts.set(access.id, compose());
    history.replaceState(null, '', transferLink(originPage, access));
    showWorkspace({ ...current, ...saved, access, stableId, shortCode: null, creatingCode: false }, incoming.content);
    closeRevocation();
    if (exchangeDialog.open) {
      clearWriterLink();
      renderExchange({ ...settings, members: remaining });
      controls['exchange-status'].textContent = 'Участник отключён. Ссылка обновлена.';
    }
    report('Участник отключён. Новая ссылка в меню «Подключить».');
  } catch (error) {
    if (revocation && exchangeDialog.open) revokeStatus(explain(error));
    else report(explain(error), true);
  } finally {
    button.disabled = controls['revoke-cancel'].disabled = controls['exchange-close'].disabled = false;
    lock(false);
    if (exchangeDialog.open) (revocation ? button : controls['exchange-close']).focus();
  }
});

function renderExchange(settings) {
  if (!exchangeDialog.open) return;
  controls['exchange-mode'].textContent = settings.mode === 'exchange' ? 'Оставить только чтение' : 'Включить обмен';
  controls['exchange-mode'].dataset.next = settings.mode === 'exchange' ? 'read' : 'exchange';
  const members = settings.members ?? [];
  if (!revocation) controls['exchange-status'].textContent = 'Участников: ' + (members.length + 1) + ' из 8. На связи: ' +
    (members.filter(member => member.present).length + 1) + '.';
  const list = controls['exchange-members'];
  const fingerprint = JSON.stringify(members);
  if (list.dataset.members === fingerprint) return;
  list.dataset.members = fingerprint;
  const focusId = document.activeElement?.dataset.member;
  list.replaceChildren(...members.map((member, index) => {
    const item = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = 'Участник ' + (index + 1) + (member.present ? ' · на связи' : ' · не в сети');
    const button = document.createElement('button');
    button.className = 'button';
    button.type = 'button';
    button.dataset.member = member.id;
    button.textContent = 'Отключить';
    button.addEventListener('click', () => {
      if (session?.direct || busy) return;
      revocation = { member: member.id };
      controls['exchange-controls'].hidden = true;
      controls['revoke-confirm'].hidden = false;
      revokeStatus();
      controls['revoke-cancel'].focus();
    });
    item.append(label, button);
    return item;
  }));
  if (focusId) (Array.from(list.querySelectorAll('button')).find(button => button.dataset.member === focusId)
    ?? controls['exchange-invite']).focus();
}

controls['exchange-open'].addEventListener('click', async () => {
  if (!session?.owner || session.direct) return;
  controls['exchange-mode'].disabled = true;
  delete controls['exchange-mode'].dataset.next;
  controls['exchange-status'].textContent = 'Загружаем…';
  exchangeDialog.showModal();
  controls['exchange-close'].focus();
  try { renderExchange(await exchangeSettings(groupFor(session), session.owner)); }
  catch (error) { controls['exchange-status'].textContent = explain(error); }
  finally { controls['exchange-mode'].disabled = false; }
});
controls['exchange-close'].addEventListener('click', () => exchangeDialog.close());
exchangeDialog.addEventListener('close', () => {
  closeRevocation();
  clearWriterLink();
  if (!controls['exchange-open'].hidden) controls['exchange-open'].focus();
});
exchangeDialog.addEventListener('cancel', event => {
  if (!revocation) return;
  event.preventDefault();
  if (!busy) closeRevocation();
});
exchangeDialog.addEventListener('keydown', event => {
  if (event.key !== 'Tab') return;
  const fields = [...['exchange-close', 'exchange-invite', 'writer-link', 'copy-writer', 'exchange-mode'].map(id => controls[id]),
    ...controls['exchange-members'].querySelectorAll('button'), controls['revoke-cancel'], controls['revoke-apply']]
    .filter(field => field.getClientRects().length && !field.disabled);
  const index = fields.indexOf(document.activeElement);
  event.preventDefault();
  fields[(index + (event.shiftKey ? -1 : 1) + fields.length) % fields.length].focus();
});
controls['exchange-mode'].addEventListener('click', async () => {
  const button = controls['exchange-mode'];
  if (!button.dataset.next || !session?.owner || busy) return;
  button.disabled = true;
  try { renderExchange(await exchangeSettings(groupFor(session), session.owner, 'mode', { mode: button.dataset.next })); }
  catch (error) { controls['exchange-status'].textContent = explain(error); }
  finally { button.disabled = false; if (exchangeDialog.open) button.focus(); }
});
controls['exchange-invite'].addEventListener('click', async () => {
  const current = session;
  if (busy || !current?.owner) return;
  const button = controls['exchange-invite'];
  button.disabled = true;
  try {
    const group = groupFor(current);
    const link = await createWriterLink(originPage, current.access, current.owner, group);
    renderExchange(await exchangeSettings(group, current.owner, 'mode', { mode: 'exchange' }));
    if (!exchangeDialog.open || session !== current) return;
    controls['writer-link'].value = link;
    controls['writer-link'].hidden = controls['writer-label'].hidden = false;
    controls['copy-writer'].hidden = false;
    controls['writer-status'].textContent = '';
    controls['copy-writer'].focus();
  } catch (error) { controls['exchange-status'].textContent = explain(error); }
  finally {
    button.disabled = false;
    if (exchangeDialog.open && controls['copy-writer'].hidden) button.focus();
  }
});
controls['copy-writer'].addEventListener('click', () => {
  void copy(controls['writer-link'].value, 'Приглашение скопировано.', text => { controls['writer-status'].textContent = text; });
});
setInterval(refreshExchange, 1500);

function openCurrentLocation() {
  if (!location.hash) {
    ++generation;
    lock(false);
    showHome();
    return;
  }
  try {
    if (location.hash.startsWith('#pair/')) {
      openPair(parseInvitationLink(location.href));
      return;
    }
    const invite = readWriterLink(location.href);
    void open(parseTransferLink(invite.url), invite.writer, null, invite.stableId);
  } catch {
    ++generation;
    lock(false);
    showHome();
    report('Ссылка повреждена. Вставь её целиком.', true);
    controls['open-url'].focus();
  }
}

window.addEventListener('hashchange', openCurrentLocation);
if (location.hash) openCurrentLocation();
