function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

let voices = [];

function populateVoices() {
  voices = speechSynthesis.getVoices();
  const voiceSelect = document.getElementById('voiceSelect');
  voiceSelect.innerHTML = '';

  voices.forEach((voice, index) => {
    const option = document.createElement('option');
    option.value = index;
    option.textContent = `${voice.name} (${voice.lang})${voice.default ? ' — DEFAULT' : ''}`;
    voiceSelect.appendChild(option);
  });
}

speechSynthesis.onvoiceschanged = populateVoices;

// Updated speakText to accept an optional callback that fires when speaking is finished.
function speakText(text, callback) {
  const selectedIndex = document.getElementById('voiceSelect').value;
  const selectedVoice = voices[selectedIndex];
  const utterance = new SpeechSynthesisUtterance(text);
  utterance.voice = selectedVoice;
  if (callback) {
    utterance.onend = callback;
  }
  speechSynthesis.speak(utterance);
}

function sendMessage() {
  const userMessageInput = document.getElementById('userMessage');
  const messageText = userMessageInput.value;
  if (!messageText) return;

  const chatWindow = document.getElementById('chatWindow');
  const userMessageDiv = document.createElement('div');
  userMessageDiv.classList.add('message', 'user');
  userMessageDiv.textContent = "You: " + messageText;
  chatWindow.appendChild(userMessageDiv);
  chatWindow.scrollTop = chatWindow.scrollHeight;
  userMessageInput.value = '';

  const data = { message: messageText };

  fetch(CHAT_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCookie('csrftoken')
    },
    body: JSON.stringify(data)
  })
  .then(response => response.json())
  .then(data => {
    const botMessageDiv = document.createElement('div');
    botMessageDiv.classList.add('message', 'bot');
    botMessageDiv.textContent = data.response ? "Bot: " + data.response : "Error: " + data.error;
    chatWindow.appendChild(botMessageDiv);
    chatWindow.scrollTop = chatWindow.scrollHeight;

    if (document.getElementById('ttsToggle').checked && data.response) {
      // When TTS is enabled, speak the response then restart listening when finished.
      speakText(data.response, function() {
        if (typeof window.startListening === 'function') {
          window.startListening();
        }
      });
    } else {
      // Restart listening immediately if TTS is disabled.
      if (typeof window.startListening === 'function') {
        window.startListening();
      }
    }
  })
  .catch(error => {
    console.error('Error:', error);
    const errorDiv = document.createElement('div');
    errorDiv.classList.add('message', 'bot');
    errorDiv.textContent = "Error: " + error;
    chatWindow.appendChild(errorDiv);
    chatWindow.scrollTop = chatWindow.scrollHeight;
    // Optionally restart listening even if there's an error.
    if (typeof window.startListening === 'function') {
      window.startListening();
    }
  });

  userMessageInput.focus();
}

document.addEventListener('DOMContentLoaded', function () {
  const userMessageInput = document.getElementById('userMessage');
  userMessageInput.addEventListener('keydown', function (event) {
    if (event.key === 'Enter') {
      event.preventDefault();
      sendMessage();
    }
  });

  populateVoices();
});
