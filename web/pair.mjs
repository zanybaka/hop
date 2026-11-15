import { offerPair, joinPair, decidePair, cancelPair, pairStatus, invitationLink, pairSignals } from './src/pairing-client.mjs';
import { connectLocal } from './src/local-channel.mjs';
import { registerPairCode } from './src/short-code.mjs';
import { qrImage } from './qr.mjs';

function delay(signal) {
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timer); reject(signal.reason); };
    if (signal.aborted) return reject(signal.reason);
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', abort);
      resolve();
    }, 350);
    signal.addEventListener('abort', abort, { once: true });
  });
}

export function setupPairing({ onConnected, onEnvelope, onDisconnected }) {
  const byId = id => document.getElementById(id);
  const dialog = byId('pair-dialog');
  const start = byId('pair-start');
  const status = byId('pair-status');
  const dismiss = byId('pair-close');
  const box = byId('pair-qr-box');
  const linkGroup = byId('pair-link-group');
  const codeGroup = byId('pair-code-group');
  const codeInput = byId('pair-code');
  const codeStatus = byId('pair-code-status');
  const codeCopy = byId('pair-code-copy');
  const input = byId('pair-url');
  const copy = byId('pair-copy');
  const actions = byId('pair-actions');
  const decline = byId('pair-decline');
  const approve = byId('pair-approve');
  const join = byId('pair-join');
  let attempt;

  function clearShare(current) {
    box.replaceChildren();
    box.hidden = true;
    if (current?.qr) URL.revokeObjectURL(current.qr);
    if (current) current.qr = undefined;
    linkGroup.hidden = true;
    input.value = '';
    codeGroup.hidden = true;
    codeInput.value = '';
    codeStatus.hidden = true;
  }

  function dispose() {
    const previous = attempt;
    attempt = undefined;
    previous?.controller.abort();
    if (previous?.role === 'owner' && previous.token && !previous.connected) {
      void cancelPair(previous.token).catch(() => {});
    }
    clearShare(previous);
  }

  function begin(role, text) {
    dispose();
    const current = { role, controller: new AbortController() };
    attempt = current;
    actions.hidden = true;
    status.textContent = text;
    if (!dialog.open) dialog.showModal();
    dismiss.focus();
    return current;
  }

  function showActions(current, kind) {
    if (attempt !== current) return;
    actions.hidden = false;
    for (const [button, show] of [[decline, kind === 'decision'], [approve, kind === 'decision'], [join, kind === 'join']]) {
      button.hidden = !show;
      button.disabled = false;
    }
    (kind === 'decision' ? decline : join).focus();
  }

  function error(current, text) {
    if (attempt !== current) return;
    clearShare(current);
    actions.hidden = true;
    status.textContent = text;
    dismiss.focus();
  }

  async function watch(current) {
    const { signal } = current.controller;
    try {
      let before;
      for (;;) {
        const { state, expiresAt } = await pairStatus(current.token, signal);
        if (signal.aborted || attempt !== current) return;
        if (expiresAt <= Date.now()) {
          error(current, 'Срок приглашения истёк. Создай новое.');
          return;
        }
        if (state === 'declined' || state === 'cancelled') {
          error(current, 'Подключение отклонено. Можно начать заново.');
          return;
        }
        if (state === 'approved') break;
        if (state !== before && state === 'joined' && current.role === 'owner') {
          clearShare(current);
          status.textContent = 'Другое устройство просит подключиться.';
          showActions(current, 'decision');
        }
        before = state;
        await delay(signal);
      }
      clearShare(current);
      actions.hidden = true;
      status.textContent = 'Устанавливаем прямое соединение…';
      dismiss.focus();
      const signals = await pairSignals(current.token, current.invitation);
      const access = { id: current.invitation.invitation, secret: current.invitation.secret };
      const info = { role: current.role, access };
      let activate;
      let channelClosed = false;
      const ready = new Promise(resolve => { activate = resolve; });
      signal.addEventListener('abort', activate, { once: true });
      const channel = await connectLocal({
        ...signals, role: current.role, signal,
        async onMessage(blob) {
          await ready;
          signal.throwIfAborted();
          return onEnvelope(blob, info);
        },
        onClose() {
          channelClosed = true;
          onDisconnected(info);
        },
      });
      if (signal.aborted) { channel.close(); return; }
      try {
        const continuation = await signals.continuation();
        if (signal.aborted) { channel.close(); return; }
        if (channelClosed) throw Error('Pair channel closed during setup');
        current.connected = true;
        dialog.close();
        await onConnected({ ...info, channel, continuation });
      } catch (failure) {
        channel.close();
        throw failure;
      } finally {
        signal.removeEventListener('abort', activate);
        activate();
      }
    } catch (failure) {
      if (signal.aborted) return;
      error(current, failure?.message?.includes('(404)')
        ? 'Приглашение недоступно. Создай новое.'
        : 'Не удалось соединить устройства. Проверь, что они в одной сети, и попробуй ещё раз.');
    }
  }

  start.addEventListener('click', async () => {
    const current = begin('owner', 'Готовим приглашение…');
    try {
      const { invitation, owner } = await offerPair();
      if (attempt !== current) {
        void cancelPair(owner).catch(() => {});
        return;
      }
      current.token = owner;
      const secret = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
      current.invitation = { invitation, secret };
      const link = invitationLink(new URL(location.pathname, location.origin), invitation, secret);
      input.value = link;
      linkGroup.hidden = false;
      status.textContent = 'Подключи второе устройство в этой сети.';
      codeStatus.textContent = 'Готовим короткий код…';
      codeStatus.hidden = false;
      void showCode(current);
      void watch(current);
      try {
        const blob = await qrImage(link);
        if (attempt !== current || linkGroup.hidden) return;
        const img = document.createElement('img');
        img.id = 'pair-qr-image';
        img.alt = 'QR приглашения для другого устройства';
        img.width = img.height = 240;
        current.qr = URL.createObjectURL(blob);
        img.src = current.qr;
        box.replaceChildren(img);
        box.hidden = false;
      } catch { /* The invitation can still be copied. */ }
    } catch {
      error(current, 'Не удалось создать приглашение. Попробуй ещё раз.');
    }
  });

  async function showCode(current) {
    try {
      const code = await registerPairCode(current.invitation, current.token);
      if (attempt !== current || linkGroup.hidden) return;
      codeInput.value = code.replace(/^(.{4})/, '$1 ');
      codeGroup.hidden = false;
      codeStatus.hidden = true;
    } catch {
      if (attempt === current && !linkGroup.hidden) {
        codeStatus.textContent = 'Код недоступен. Используй QR или ссылку.';
      }
    }
  }

  async function copyInvitation(field, message) {
    const current = attempt;
    try {
      await navigator.clipboard.writeText(field.value);
      if (attempt === current) status.textContent = message;
    } catch {
      if (attempt === current) {
        field.select();
        status.textContent = 'Скопируй выделенный текст.';
      }
    }
  }
  copy.addEventListener('click', () => void copyInvitation(input, 'Приглашение скопировано. Открой его на другом устройстве.'));
  codeCopy.addEventListener('click', () => void copyInvitation(codeInput, 'Короткий код скопирован.'));

  const decision = async accepted => {
    const current = attempt;
    if (!current || current.role !== 'owner') return;
    approve.disabled = decline.disabled = true;
    try {
      await decidePair(current.token, accepted);
      if (!accepted) error(current, 'Подключение отклонено.');
    } catch {
      error(current, 'Не удалось подтвердить запрос. Создай новое приглашение.');
    }
  };
  decline.addEventListener('click', () => void decision(false));
  approve.addEventListener('click', () => void decision(true));
  async function requestJoin(current) {
    join.disabled = true;
    try {
      const { recipient } = await joinPair(current.invitation.invitation);
      if (attempt !== current) return;
      current.token = recipient;
      actions.hidden = true;
      status.textContent = 'Ждём подтверждения на первом устройстве…';
      dismiss.focus();
      void watch(current);
    } catch {
      error(current, 'Приглашение недоступно. Попроси создать новое.');
    }
  }
  join.addEventListener('click', () => {
    if (attempt?.role === 'recipient') void requestJoin(attempt);
  });

  function dismissDialog() {
    if (dialog.open) return;
    const recipient = attempt?.role === 'recipient';
    if (!attempt?.connected) {
      dispose();
      if (recipient && location.hash.startsWith('#pair/')) history.replaceState(null, '', location.pathname + location.search);
      if (!start.hidden && !start.closest('[hidden]')) start.focus();
    }
  }
  dismiss.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', dismissDialog);
  dialog.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const fields = [dismiss, codeInput, codeCopy, input, copy, decline, approve, join]
      .filter(field => !field.disabled && !field.closest('[hidden]'));
    const index = fields.indexOf(document.activeElement);
    const step = event.shiftKey ? -1 : 1;
    event.preventDefault();
    fields[(index + step + fields.length) % fields.length].focus();
  });

  return {
    open(invitation) {
      const current = begin('recipient', 'Подключись, если на первом устройстве открыто это приглашение.');
      current.invitation = invitation;
      showActions(current, 'join');
    },
    openCode(invitation) {
      const current = begin('recipient', 'Отправляем запрос на первое устройство…');
      current.invitation = invitation;
      void requestJoin(current);
    },
    close() {
      dispose();
      if (dialog.open) dialog.close();
    },
  };
}
