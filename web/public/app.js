const STORAGE_KEY = 'security-kg-graph:history';
const PAGE_SIZE = 3;

const form = document.getElementById('ask-form');
const questionInput = document.getElementById('question');
const submitBtn = document.getElementById('submit-btn');
const clearBtn = document.getElementById('clear-btn');
const statusEl = document.getElementById('status');
const historyEl = document.getElementById('history');
const loadMoreBtn = document.getElementById('load-more-btn');

let history = loadHistory();
let visibleCount = PAGE_SIZE;

render();

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const question = questionInput.value.trim();
  if (!question) return;

  setLoading(true);
  showStatus('Thinking…');

  try {
    const response = await fetch('/api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    });

    if (!response.ok) {
      const data = await safeJson(response);
      throw new Error(data?.error ?? `Request failed with status ${response.status}`);
    }

    const data = await response.json();
    const entry = {
      question,
      answer: data.answer ?? '',
      cypher: data.cypher ?? '',
      results: data.results ?? [],
      cypherThinking: data.cypherThinking ?? '',
      answerThinking: data.answerThinking ?? '',
      timestamp: Date.now(),
    };
    history.unshift(entry);
    saveHistory(history);
    questionInput.value = '';
    visibleCount = PAGE_SIZE;
    render();
    hideStatus();
  } catch (err) {
    showStatus(`Error: ${err.message}`, true);
  } finally {
    setLoading(false);
  }
});

clearBtn.addEventListener('click', () => {
  if (history.length === 0) return;
  if (!confirm('Clear all saved history?')) return;
  history = [];
  saveHistory(history);
  visibleCount = PAGE_SIZE;
  render();
});

loadMoreBtn.addEventListener('click', () => {
  visibleCount += PAGE_SIZE;
  render();
});

function render() {
  historyEl.innerHTML = '';
  const visible = history.slice(0, visibleCount);
  for (const entry of visible) {
    historyEl.appendChild(renderCard(entry));
  }
  loadMoreBtn.hidden = history.length <= visibleCount;
}

function renderCard(entry) {
  const card = document.createElement('article');
  card.className = 'card';

  const question = document.createElement('div');
  question.className = 'question';
  question.textContent = entry.question;

  const answer = document.createElement('div');
  answer.className = 'answer';
  answer.textContent = entry.answer || '(no answer)';

  const details = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'Show Cypher and raw results';
  details.appendChild(summary);

  if (entry.cypher) {
    const cypher = document.createElement('pre');
    cypher.textContent = entry.cypher;
    details.appendChild(cypher);
  }

  if (entry.results && entry.results.length > 0) {
    const results = document.createElement('pre');
    results.textContent = JSON.stringify(entry.results, null, 2);
    details.appendChild(results);
  }

  card.appendChild(question);
  card.appendChild(answer);

  const thoughts = renderThoughts(entry);
  if (thoughts) card.appendChild(thoughts);

  card.appendChild(details);

  const timestamp = document.createElement('div');
  timestamp.className = 'timestamp';
  timestamp.textContent = new Date(entry.timestamp).toLocaleString();
  card.appendChild(timestamp);

  return card;
}

function renderThoughts(entry) {
  const cypherThinking = (entry.cypherThinking ?? '').trim();
  const answerThinking = (entry.answerThinking ?? '').trim();
  if (!cypherThinking && !answerThinking) return null;

  const wrapper = document.createElement('details');
  wrapper.className = 'thoughts';
  const summary = document.createElement('summary');
  summary.textContent = 'Show model thoughts';
  wrapper.appendChild(summary);

  if (cypherThinking) {
    wrapper.appendChild(renderThoughtBlock('While generating Cypher', cypherThinking));
  }
  if (answerThinking) {
    wrapper.appendChild(renderThoughtBlock('While composing the answer', answerThinking));
  }
  return wrapper;
}

function renderThoughtBlock(title, text) {
  const block = document.createElement('div');
  block.className = 'thought-block';

  const heading = document.createElement('div');
  heading.className = 'thought-heading';
  heading.textContent = title;

  const body = document.createElement('div');
  body.className = 'thought-body';
  body.textContent = text;

  block.append(heading, body);
  return block;
}

function loadHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveHistory(entries) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch (err) {
    console.warn('failed to save history:', err);
  }
}

function setLoading(loading) {
  submitBtn.disabled = loading;
  questionInput.disabled = loading;
}

function showStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle('error', isError);
  statusEl.hidden = false;
}

function hideStatus() {
  statusEl.hidden = true;
  statusEl.textContent = '';
  statusEl.classList.remove('error');
}

async function safeJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}
