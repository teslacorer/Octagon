export async function apiConfig() {
  const res = await fetch('/api/config');
  return res.json();
}
export async function startScan(payload) {
  const res = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  if (!res.ok) throw new Error('Failed to start scan');
  return res.json();
}
export async function getProgress(id) {
  const res = await fetch(`/api/progress?id=${encodeURIComponent(id)}`);
  return res.json();
}
