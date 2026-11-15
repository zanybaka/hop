import { DIRECT_HEADER_BYTES } from './direct-revision.mjs';

// WebRTC transports already encrypted HOPG envelopes. Signals contain SDP only.
const CHANNEL = 'hop-envelope-v1';
const MAX_BYTES = 8 + 6_311_936 + 100_000_000 + 32 + DIRECT_HEADER_BYTES;
const FRAME_BYTES = 16 * 1024;
const CHUNK_BYTES = FRAME_BYTES - 1;
const HEADER = 1;
const CHUNK = 2;
const RECEIPT = 3;
const HIGH_WATER = 256 * 1024;
const LOW_WATER = HIGH_WATER / 2;
const TRANSFER_TIMEOUT = 120_000;
const POLL_MS = 150;

function abortable(operation, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    if (signal.aborted) return abort();
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve().then(() => {
      signal.throwIfAborted();
      return operation();
    }).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

function waitFor(target, name, condition, signal) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      target.removeEventListener(name, check);
      signal.removeEventListener('abort', abort);
    };
    const abort = () => { cleanup(); reject(signal.reason); };
    const check = () => {
      if (!condition()) return;
      cleanup();
      resolve();
    };
    if (signal.aborted) return abort();
    signal.addEventListener('abort', abort, { once: true });
    target.addEventListener(name, check);
    check();
  });
}

function pause(signal) {
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    if (signal.aborted) return reject(signal.reason);
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', abort);
      resolve();
    }, POLL_MS);
    signal.addEventListener('abort', abort, { once: true });
  });
}

export async function connectLocal({
  role, sendSignal, readSignal, onMessage, onClose = () => {}, signal, timeoutMs = 15_000,
}) {
  if (role !== 'owner' && role !== 'recipient') throw new TypeError('Unknown pairing role');
  if (![sendSignal, readSignal, onMessage, onClose].every(callback => typeof callback === 'function') ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new TypeError('Invalid channel options');
  }
  signal?.throwIfAborted();
  const peer = new RTCPeerConnection({ iceServers: [] });
  const lifecycle = new AbortController();
  const setupTimer = setTimeout(() => close(new Error('Local connection timed out')), timeoutMs);
  let channel;
  let established = false;
  let sending = false;
  let incoming;
  let delivering = false;
  let awaitingReceipt = false;

  function close(reason = new Error('Local connection closed')) {
    if (lifecycle.signal.aborted) return;
    lifecycle.abort(reason);
    clearTimeout(setupTimer);
    clearTimeout(incoming?.timer);
    incoming = undefined;
    signal?.removeEventListener('abort', cancelled);
    channel?.close();
    peer.close();
    if (established) onClose();
  }
  const cancelled = () => close(signal.reason);
  signal?.addEventListener('abort', cancelled, { once: true });
  peer.addEventListener('connectionstatechange', () => {
    if (['failed', 'closed', 'disconnected'].includes(peer.connectionState)) close();
  });

  function receive(event) {
    const buffer = event.data;
    if (!(buffer instanceof ArrayBuffer) || buffer.byteLength === 0) return close(new Error('Expected binary data'));
    const frame = new Uint8Array(buffer);
    if (frame[0] === RECEIPT && frame.byteLength === 1 && awaitingReceipt) {
      awaitingReceipt = false;
      channel.dispatchEvent(new Event('hopreceipt'));
      return;
    }
    if (frame[0] === HEADER && !incoming && !delivering && frame.byteLength === 5) {
      const size = new DataView(buffer).getUint32(1);
      if (size === 0 || size > MAX_BYTES) return close(new Error('Invalid transfer length'));
      incoming = {
        size, received: 0, chunks: [],
        timer: setTimeout(() => close(new Error('Local receive timed out')), TRANSFER_TIMEOUT),
      };
      return;
    }
    if (frame[0] !== CHUNK || !incoming) return close(new Error('Invalid transfer frame'));
    const remaining = incoming.size - incoming.received;
    if (frame.byteLength - 1 !== Math.min(CHUNK_BYTES, remaining)) return close(new Error('Invalid transfer chunk'));
    incoming.chunks.push(frame.subarray(1));
    incoming.received += frame.byteLength - 1;
    if (incoming.received !== incoming.size) return;

    const blob = new Blob(incoming.chunks, { type: 'application/octet-stream' });
    clearTimeout(incoming.timer);
    incoming = undefined;
    delivering = true;
    Promise.resolve().then(() => {
      if (!lifecycle.signal.aborted) return onMessage(blob);
    }).then(() => {
      delivering = false;
      if (!lifecycle.signal.aborted) channel.send(Uint8Array.of(RECEIPT));
    }).catch(close);
  }

  function attach(candidate) {
    if (channel || candidate.label !== CHANNEL || !candidate.ordered ||
        candidate.maxPacketLifeTime !== null || candidate.maxRetransmits !== null) {
      candidate.close();
      close(new Error('Unexpected local data channel'));
      return;
    }
    channel = candidate;
    channel.binaryType = 'arraybuffer';
    channel.bufferedAmountLowThreshold = LOW_WATER;
    channel.addEventListener('message', receive);
    channel.addEventListener('close', () => close());
    channel.addEventListener('error', () => close(new Error('Local data channel failed')));
  }

  peer.addEventListener('datachannel', ({ channel }) => {
    attach(channel);
    peer.dispatchEvent(new Event('hopchannel'));
  });

  const operation = fn => abortable(fn, lifecycle.signal);
  const localDescription = async description => {
    await operation(() => peer.setLocalDescription(description));
    await waitFor(peer, 'icegatheringstatechange', () => peer.iceGatheringState === 'complete', lifecycle.signal);
    const { type, sdp } = peer.localDescription;
    await operation(() => sendSignal({ type, sdp }, { signal: lifecycle.signal }));
  };
  async function remoteDescription(type) {
    for (;;) {
      const remote = await operation(() => readSignal({ signal: lifecycle.signal }));
      if (remote != null) {
        if (remote.type !== type || typeof remote.sdp !== 'string') throw new Error('Invalid pairing signal');
        await operation(() => peer.setRemoteDescription({ type, sdp: remote.sdp }));
        return;
      }
      await pause(lifecycle.signal);
    }
  }

  try {
    if (role === 'owner') {
      attach(peer.createDataChannel(CHANNEL, { ordered: true }));
      await localDescription(await operation(() => peer.createOffer()));
      await remoteDescription('answer');
    } else {
      await remoteDescription('offer');
      await localDescription(await operation(() => peer.createAnswer()));
    }
    await waitFor(peer, 'hopchannel', () => channel != null, lifecycle.signal);
    await waitFor(channel, 'open', () => channel.readyState === 'open', lifecycle.signal);
    if (peer.sctp?.maxMessageSize < FRAME_BYTES) throw new Error('Local channel message limit is too small');
    lifecycle.signal.throwIfAborted();
    established = true;
    clearTimeout(setupTimer);
  } catch (error) {
    close(error);
    throw error;
  }

  return {
    async send(blob) {
      if (!(blob instanceof Blob) || blob.size === 0 || blob.size > MAX_BYTES) throw new Error('Invalid transfer payload');
      if (sending) throw new Error('Another transfer is in progress');
      lifecycle.signal.throwIfAborted();
      const header = new Uint8Array(5);
      header[0] = HEADER;
      new DataView(header.buffer).setUint32(1, blob.size);
      sending = true;
      const timer = setTimeout(() => close(new Error('Local send timed out')), TRANSFER_TIMEOUT);
      try {
        channel.send(header);
        for (let offset = 0; offset < blob.size; offset += CHUNK_BYTES) {
          if (channel.bufferedAmount > HIGH_WATER) {
            await waitFor(channel, 'bufferedamountlow', () => channel.bufferedAmount <= LOW_WATER, lifecycle.signal);
          }
          const chunk = await operation(() => blob.slice(offset, offset + CHUNK_BYTES).arrayBuffer());
          if (offset + chunk.byteLength === blob.size) awaitingReceipt = true;
          const frame = new Uint8Array(chunk.byteLength + 1);
          frame[0] = CHUNK;
          frame.set(new Uint8Array(chunk), 1);
          channel.send(frame);
        }
        await waitFor(channel, 'hopreceipt', () => !awaitingReceipt, lifecycle.signal);
      } catch (error) {
        close(error);
        throw error;
      } finally {
        clearTimeout(timer);
        sending = false;
      }
    },
    close: () => close(),
  };
}
