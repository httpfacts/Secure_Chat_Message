const chatBox = document.getElementById("chat-box");

async function sendMessage() {
  const msg = document.getElementById("message").value;
  const password = document.getElementById("password").value;
  if (!msg.trim() || !password) {
    alert("Enter both password and message!");
    return;
  }

  // Encrypt
  const { ciphertext, iv } = await encryptText(msg, password);

  // Show encrypted message as sent
  appendMessage("You (Encrypted): " + ciphertext, "sent");

  // Simulate received message (decrypt immediately for demo)
  const decrypted = await decryptText(ciphertext, password, iv);
  appendMessage("Friend: " + decrypted, "received");

  document.getElementById("message").value = "";
  chatBox.scrollTop = chatBox.scrollHeight;
}

function appendMessage(text, type) {
  const div = document.createElement("div");
  div.classList.add("message", type);
  div.textContent = text;
  chatBox.appendChild(div);
}
