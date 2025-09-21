// aes_chat.js
// Secure Chat demo: message-level AES-GCM (PBKDF2 => AES-256-GCM)
// Each message has its own random salt (16 bytes) and IV (12 bytes).
// Stored message format: Base64(salt||iv||ciphertext)

// --- Helpers ---
const TE = new TextEncoder();
const TD = new TextDecoder();

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    TE.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 150000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptMessage(plaintext, password) {
  if (!password) throw new Error('Password required.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, TE.encode(plaintext));

  const combined = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.byteLength);
  combined.set(new Uint8Array(ct), salt.byteLength + iv.byteLength);

  return arrayBufferToBase64(combined.buffer);
}

async function tryDecryptMessage(base64Combined, password) {
  // returns plaintext or throws if decryption fails
  if (!base64Combined) throw new Error('No ciphertext');
  if (!password) throw new Error('Password required.');
  const combinedBuf = base64ToArrayBuffer(base64Combined);
  const combined = new Uint8Array(combinedBuf);

  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ct = combined.slice(28).buffer;

  const key = await deriveKey(password, salt);
  try {
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return TD.decode(plainBuf);
  } catch (e) {
    throw new Error('Decrypt failed');
  }
}

// --- UI / App state ---
const messages = []; // array of {id, from: 'A'|'B', ciphertext, timestamp}

function mkId() {
  return Math.random().toString(36).slice(2, 9);
}

function appendMessageToDOM(msg) {
  // For both panes we append the ciphertext bubble. Each pane will attempt to decrypt with its password.
  const { id, from, ciphertext, ts } = msg;
  const time = new Date(ts).toLocaleTimeString();

  const containerA = document.getElementById('messagesA');
  const containerB = document.getElementById('messagesB');

  const bubbleA = document.createElement('div');
  bubbleA.className = 'msg ' + (from === 'A' ? 'sent' : 'recv');
  bubbleA.id = `msg-${id}-A`;
  bubbleA.dataset.cipher = ciphertext;
  bubbleA.innerHTML = `<div class="meta">${from} • ${time}</div><div class="body lock">Locked</div>`;
  containerA.appendChild(bubbleA);

  const bubbleB = document.createElement('div');
  bubbleB.className = 'msg ' + (from === 'B' ? 'sent' : 'recv');
  bubbleB.id = `msg-${id}-B`;
  bubbleB.dataset.cipher = ciphertext;
  bubbleB.innerHTML = `<div class="meta">${from} • ${time}</div><div class="body lock">Locked</div>`;
  containerB.appendChild(bubbleB);

  // auto-scroll
  containerA.scrollTop = containerA.scrollHeight;
  containerB.scrollTop = containerB.scrollHeight;
}

async function attemptDecryptAllFor(pane) {
  // pane = 'A' or 'B'
  const pwdEl = document.getElementById(pane === 'A' ? 'pwdA' : 'pwdB');
  const pwd = pwdEl.value;
  const container = document.getElementById(pane === 'A' ? 'messagesA' : 'messagesB');
  const children = Array.from(container.children);

  for (const child of children) {
    const cipher = child.dataset.cipher;
    const body = child.querySelector('.body');
    if (!cipher) continue;
    if (!pwd) {
      body.textContent = 'Locked';
      body.classList.add('lock');
      continue;
    }
    try {
      const plain = await tryDecryptMessage(cipher, pwd);
      body.textContent = plain;
      body.classList.remove('lock');
    } catch (e) {
      body.textContent = 'Locked';
      body.classList.add('lock');
    }
  }
}

// --- Event wiring ---
document.addEventListener('DOMContentLoaded', () => {
  // elements
  const sendA = document.getElementById('sendA');
  const sendB = document.getElementById('sendB');
  const clearA = document.getElementById('clearA');
  const clearB = document.getElementById('clearB');
  const inputA = document.getElementById('inputA');
  const inputB = document.getElementById('inputB');
  const pwdA = document.getElementById('pwdA');
  const pwdB = document.getElementById('pwdB');

  // send from A
  sendA.addEventListener('click', async () => {
    const txt = inputA.value.trim();
    const pw = pwdA.value;
    if (!txt) return alert('Enter a message to send from A.');
    try {
      sendA.disabled = true;
      sendA.textContent = 'Sending...';
      const ct = await encryptMessage(txt, pw);
      const msg = { id: mkId(), from: 'A', ciphertext: ct, ts: Date.now() };
      messages.push(msg);
      appendMessageToDOM(msg);
      // both panes attempt to decrypt (auto)
      await attemptDecryptAllFor('A');
      await attemptDecryptAllFor('B');
      inputA.value = '';
    } catch (err) {
      alert('Encryption failed: ' + (err.message || err));
    } finally {
      sendA.disabled = false;
      sendA.textContent = 'Send';
    }
  });

  // send from B
  sendB.addEventListener('click', async () => {
    const txt = inputB.value.trim();
    const pw = pwdB.value;
    if (!txt) return alert('Enter a message to send from B.');
    try {
      sendB.disabled = true;
      sendB.textContent = 'Sending...';
      const ct = await encryptMessage(txt, pw);
      const msg = { id: mkId(), from: 'B', ciphertext: ct, ts: Date.now() };
      messages.push(msg);
      appendMessageToDOM(msg);
      await attemptDecryptAllFor('A');
      await attemptDecryptAllFor('B');
      inputB.value = '';
    } catch (err) {
      alert('Encryption failed: ' + (err.message || err));
    } finally {
      sendB.disabled = false;
      sendB.textContent = 'Send';
    }
  });

  // clear buttons
  clearA.addEventListener('click', () => inputA.value = '');
  clearB.addEventListener('click', () => inputB.value = '');

  // whenever password changes, re-run decrypt attempts
  pwdA.addEventListener('input', () => attemptDecryptAllFor('A'));
  pwdB.addEventListener('input', () => attemptDecryptAllFor('B'));

  // initial: empty state message
  const initial = { id: mkId(), from: 'system', ciphertext: null, ts: Date.now() };
  // show small hint messages in both panes
  const hintMsg = { id: mkId(), from: 'System', ciphertext: null, ts: Date.now() };
  const containerA = document.getElementById('messagesA');
  const containerB = document.getElementById('messagesB');
  containerA.innerHTML = `<div class="msg meta">Try sending a message. Use same password to decrypt across panes.</div>`;
  containerB.innerHTML = `<div class="msg meta">Try sending a message. Use same password to decrypt across panes.</div>`;
});
