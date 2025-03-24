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

function speakText(text) {
  const selectedIndex = document.getElementById('voiceSelect').value;
  const selectedVoice = voices[selectedIndex];
  const utterance = new SpeechSynthesisUtterance(text);
  utterance.voice = selectedVoice;
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
      speakText(data.response);
    }
  })
  .catch(error => {
    console.error('Error:', error);
    const errorDiv = document.createElement('div');
    errorDiv.classList.add('message', 'bot');
    errorDiv.textContent = "Error: " + error;
    chatWindow.appendChild(errorDiv);
    chatWindow.scrollTop = chatWindow.scrollHeight;
  })
  .finally(() => {
    // If the mic is still active, restart recognition.
    if (window.listening && window.recognition) {
      try {
        window.recognition.start();
      } catch (e) {
        console.error(e);
      }
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
