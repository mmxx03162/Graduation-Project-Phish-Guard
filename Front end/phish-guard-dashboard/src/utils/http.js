function isAbortError(err) {
  return err?.name === 'AbortError';
}

async function readErrorBody(res) {
  const contentType = res.headers?.get?.('content-type') || '';
  try {
    if (contentType.includes('application/json')) {
      const data = await res.json();
      if (typeof data === 'string') return data;
      if (data?.detail) return String(data.detail);
      if (data?.message) return String(data.message);
      if (data?.error) return String(data.error);
      return JSON.stringify(data);
    }
    return await res.text();
  } catch {
    return '';
  }
}

export async function httpJson(url, options = {}) {
  const {
    timeoutMs = 8000,
    headers,
    ...rest
  } = options;

  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      ...rest,
      signal: controller.signal,
      mode: 'cors',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(headers || {}),
      },
    });

    if (!res.ok) {
      const body = await readErrorBody(res);
      const suffix = body ? ` — ${body}` : '';
      throw new Error(`HTTP ${res.status} ${res.statusText}${suffix}`.trim());
    }

    // Some endpoints may return 204 or empty.
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  } catch (err) {
    if (isAbortError(err)) {
      throw new Error('Connection timeout — is the backend running?');
    }
    if (String(err?.message || '').includes('Failed to fetch')) {
      throw new Error('Backend not reachable. Start Django and check CORS.');
    }
    throw err;
  } finally {
    clearTimeout(tid);
  }
}

