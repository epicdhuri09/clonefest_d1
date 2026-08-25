export interface AuthUser {
  id: string;
  username: string;
}

export interface AuthResponse {
  user: AuthUser;
  token: string;
}

const API_BASE = "http://localhost:4000";
const TOKEN_KEY = "authToken";
const USER_KEY = "authUser";

function saveSession(data: AuthResponse): AuthResponse {
  localStorage.setItem(TOKEN_KEY, data.token);
  localStorage.setItem(USER_KEY, JSON.stringify(data.user));
  return data;
}

function clearSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

async function parseError(response: Response, fallback: string): Promise<string> {
  try {
    const data = await response.json();
    return data?.error || fallback;
  } catch {
    return fallback;
  }
}

export function getAuthToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser(): AuthUser | null {
  const raw = localStorage.getItem(USER_KEY);

  if (!raw) return null;

  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    clearSession();
    return null;
  }
}

export async function register(
  username: string,
  password: string,
): Promise<AuthResponse> {
  const response = await fetch(`${API_BASE}/api/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    throw new Error(
      await parseError(response, "Failed to create account."),
    );
  }

  return saveSession(await response.json());
}

export async function login(
  username: string,
  password: string,
): Promise<AuthResponse> {
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    throw new Error(
      await parseError(response, "Invalid username or password"),
    );
  }

  return saveSession(await response.json());
}

export async function getCurrentUser(): Promise<AuthUser | null> {
  const token = getAuthToken();

  if (!token) return null;

  try {
    const response = await fetch(`${API_BASE}/api/auth/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      clearSession();
      return null;
    }

    const data = await response.json();
    const user = data.user as AuthUser;

    localStorage.setItem(USER_KEY, JSON.stringify(user));
    return user;
  } catch {
    return getStoredUser();
  }
}

export async function logout(): Promise<void> {
  const token = getAuthToken();

  try {
    if (token) {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
    }
  } finally {
    clearSession();
  }
}
