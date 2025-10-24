/*
 * controller.js
 *
 * CSC309 Tutorial 8
 * 
 * Complete me
 */

const PAGE_SIZE = 5;
let nextStart = 1;
let isLoading = false;
let hasMore = true;

function getDataEl() {
  return document.getElementById('data');
}

function buildParagraph(item) {
  const wrap = document.createElement('div');
  wrap.id = `paragraph_${item.id}`;
  const p = document.createElement('p');
  p.textContent = item.content + ' ';
  const b = document.createElement('b');
  b.textContent = '(Paragraph: )';
  p.appendChild(b);
  const btn = document.createElement('button');
  btn.className = 'btn like';
  btn.textContent = `Likes: ${item.likes}`;
  wrap.appendChild(p);
  wrap.appendChild(btn);
  return wrap;
}

async function fetchPage(startNumber) {
  if (isLoading || !hasMore) return;
  isLoading = true;

  const res = await fetch(`/text?paragraph=${startNumber}`);
  const payload = await res.json();
  const container = getDataEl();
  payload.data.forEach(item => {
    container.appendChild(buildParagraph(item));
  });
  hasMore = !!payload.next;
  nextStart += PAGE_SIZE;


  if (!hasMore) {
    const endP = document.createElement('p');
    const endB = document.createElement('b');
    endB.textContent = 'You have reached the end';
    endP.appendChild(endB);
    container.appendChild(endP);
  }

  isLoading = false;
}

async function postLike(paragraphId) {
  const res = await fetch('/text/like', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ paragraph: paragraphId }),
  });
  const payload = await res.json();
  return payload.data.likes;
}

function onScroll() {
  if (!hasMore || isLoading) return;
  const atBottom = window.innerHeight + window.scrollY >= document.body.offsetHeight;
  if (atBottom) fetchPage(nextStart);
}

async function onClick(e) {
  const t = e.target;
  if (!t.classList || !t.classList.contains('like')) return;

  const wrapper = t.closest('div[id^="paragraph_"]');
  if (!wrapper) return;
  const id = Number(wrapper.id.replace('paragraph_', ''));
  const newLikes = await postLike(id);
  t.textContent = `Likes: ${newLikes}`;
}

document.addEventListener('DOMContentLoaded', () => {
  fetchPage(1);
  getDataEl().addEventListener('click', onClick);
  window.addEventListener('scroll', onScroll);
});