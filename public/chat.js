const socket = io();
const chatPannel = document.getElementById("chatPannel");
const log = document.getElementById("log");
const emojiButton = document.getElementById("emojiButton");
const emojiPicker = document.getElementById("emojiPicker");
const composeBar = document.getElementById("composeBar");
const sendButton = document.getElementById("sendButton");
const attachmentButton = document.getElementById("attachmentButton");
const voiceButton = document.getElementById("voiceButton");

emojiButton.addEventListener("click", (e) => {
  e.stopPropagation();
  emojiPicker.style.display =
    emojiPicker.style.display === "none" ? "block" : "none";
});

document.addEventListener("click", (e) => {
  if (
    emojiPicker.style.display === "block" &&
    !emojiPicker.contains(e.target)
  ) {
    emojiPicker.style.display = "none";
  }
});

emojiPicker.addEventListener("emoji-click", (data) => {
  const emoji = data.detail.emoji.unicode;
  insertAtCursor(composeBar, emoji);
});

function insertAtCursor(input, text) {
  const start = input.selectionStart;
  const end = input.selectionEnd;
  const before = input.value.substring(0, start);
  const after = input.value.substring(end);
  input.value = before + text + after;
  input.selectionStart = input.selectionEnd = start + text.length;
  input.focus();
}

sendButton.addEventListener("click", () => {
  const text = composeBar.value.trim();
  if (text) {
    const msg = {
      type: "text",
      username: USERNAME,
      message: text,
      timestamp: Date.now(),
    };
    socket.emit("textMessage", msg);
    composeBar.value = "";
  }
});

composeBar.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendButton.click();
  }
});

function addMessage(msg) {
  const wrapper = document.createElement("div");
  wrapper.classList.add("chat-message");

  const bubble = document.createElement("div");
  bubble.classList.add("bubble");

  if (msg.username === USERNAME) {
    bubble.classList.add("sent");
  } else {
    bubble.classList.add("received");
  }

  if (msg.username !== USERNAME) {
    const userLabel = document.createElement("div");
    userLabel.classList.add("username");
    userLabel.textContent = msg.username;
    bubble.appendChild(userLabel);
  }

  // message content
  const content = document.createElement("div");
  content.classList.add("text");
  content.textContent = msg.message;
  bubble.appendChild(content);

  wrapper.appendChild(bubble);
  chatPannel.appendChild(wrapper);
  chatPannel.scrollTop = chatPannel.scrollHeight;
}

socket.on("textMessage", (msg) => {
  addMessage(msg);
  console.log(msg);
});
