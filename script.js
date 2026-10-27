import { extract_hash } from './pkg/pdf_hash_wasm.js';

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const statusEl = document.getElementById('status');
const resultEl = document.getElementById('result');
const hashOutput = document.getElementById('hashOutput');
const debugEl = document.getElementById('debug');
const copyBtn = document.getElementById('copyBtn');

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) processFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', (e) => {
  if (e.target.files[0]) processFile(e.target.files[0]);
});
copyBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(hashOutput.textContent);
  copyBtn.textContent = 'Copied!';
  setTimeout(() => copyBtn.textContent = 'Copy Hash', 1500);
});

async function processFile(file) {
  if (!file.name.toLowerCase().endsWith('.pdf')) {
    statusEl.textContent = 'Please select a PDF file.';
    return;
  }
  statusEl.textContent = 'Processing...';
  resultEl.classList.remove('show');
  hashOutput.classList.remove('error');
  debugEl.classList.remove('show');

  try {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const out = extract_hash(bytes);

    const hash = typeof out === 'string' ? out : out.hash;
    const err = typeof out === 'string' ? null : out.error;
    const dbg = typeof out === 'string' ? null : out.debug;

    if (dbg) {
      debugEl.textContent = dbg;
      debugEl.classList.add('show');
    }

    if (err || (typeof hash === 'string' && hash.startsWith('Error:'))) {
      hashOutput.textContent = err || hash;
      hashOutput.classList.add('error');
    } else {
      hashOutput.textContent = hash;
    }

    resultEl.classList.add('show');
    statusEl.textContent = 'Done - ' + file.name;
  } catch (err) {
    hashOutput.textContent = 'Error: ' + err.message;
    hashOutput.classList.add('error');
    resultEl.classList.add('show');
    statusEl.textContent = 'Processing failed.';
  }
}