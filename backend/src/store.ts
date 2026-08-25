export type RiskLevel =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export interface ShareRecord {
  id: string;
  ciphertext: string;
  iv: string;
  createdAt: string;
  expiresAt: string;
  maxViews: number;
  views: number;
  burned: boolean;
  burnToken: string;
  riskLevel: RiskLevel;
  ownerId: string;
}

export interface UserRecord {
  id: string;
  username: string;
  passwordHash: string;
  createdAt: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  createdAt: string;
  expiresAt: string;
}

const shares = new Map<string, ShareRecord>();
const users = new Map<string, UserRecord>();
const sessions = new Map<string, SessionRecord>();

export function createShare(record: ShareRecord): void {
  shares.set(record.id, record);
}

export function getShare(id: string): ShareRecord | undefined {
  return shares.get(id);
}

export function updateShare(
  id: string,
  updates: Partial<ShareRecord>,
): ShareRecord | undefined {
  const existing = shares.get(id);

  if (!existing) return undefined;

  const updated: ShareRecord = {
    ...existing,
    ...updates,
  };

  shares.set(id, updated);
  return updated;
}

export function incrementShareViews(
  id: string,
): ShareRecord | undefined {
  const existing = shares.get(id);

  if (!existing) return undefined;

  const updated: ShareRecord = {
    ...existing,
    views: existing.views + 1,
  };

  shares.set(id, updated);
  return updated;
}

export function createUser(user: UserRecord): void {
  users.set(user.id, user);
}

export function getUserById(id: string): UserRecord | undefined {
  return users.get(id);
}

export function getUserByUsername(
  username: string,
): UserRecord | undefined {
  const normalizedUsername = username.trim().toLowerCase();

  for (const user of users.values()) {
    if (user.username.toLowerCase() === normalizedUsername) {
      return user;
    }
  }

  return undefined;
}

export function createSession(session: SessionRecord): void {
  sessions.set(session.id, session);
}

export function getSession(id: string): SessionRecord | undefined {
  const session = sessions.get(id);

  if (!session) return undefined;

  if (new Date() >= new Date(session.expiresAt)) {
    sessions.delete(id);
    return undefined;
  }

  return session;
}

export function deleteSession(id: string): boolean {
  return sessions.delete(id);
}

export function getSharesByOwner(ownerId: string): ShareRecord[] {
  return Array.from(shares.values()).filter(
    (share) => share.ownerId === ownerId,
  );
}
