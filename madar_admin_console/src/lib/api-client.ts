let currentCsrfToken: string | null = null;

export function setClientCsrfToken(token: string | null) {
  currentCsrfToken = token;
}

export function getClientCsrfToken(): string | null {
  return currentCsrfToken;
}

export async function bffFetch<T = any>(
  path: string,
  options: {
    method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    body?: unknown;
  } = {},
): Promise<{ status: number; ok: boolean; data: T }> {
  const method = options.method || 'GET';
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    if (currentCsrfToken) {
      headers['X-Madar-CSRF'] = currentCsrfToken;
    }
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
  }

  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });

  const data = (await res.json().catch(() => ({}))) as T;
  if ((data as any)?.csrf_token) {
    currentCsrfToken = (data as any).csrf_token;
  }

  return {
    status: res.status,
    ok: res.ok,
    data,
  };
}
