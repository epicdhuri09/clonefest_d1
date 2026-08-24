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

  riskLevel:
    | "LOW"
    | "MEDIUM"
    | "HIGH"
    | "CRITICAL";
}

const shares =
  new Map<string, ShareRecord>();

export function createShare(
  record: ShareRecord,
): void {
  shares.set(
    record.id,
    record,
  );
}

export function getShare(
  id: string,
): ShareRecord | undefined {
  return shares.get(id);
}

export function updateShare(
  id: string,
  updates: Partial<ShareRecord>,
): ShareRecord | undefined {
  const existing =
    shares.get(id);

  if (!existing) {
    return undefined;
  }

  const updated: ShareRecord = {
    ...existing,
    ...updates,
  };

  shares.set(
    id,
    updated,
  );

  return updated;
}

export function incrementShareViews(
  id: string,
): ShareRecord | undefined {
  const existing =
    shares.get(id);

  if (!existing) {
    return undefined;
  }

  const updated: ShareRecord = {
    ...existing,

    views:
      existing.views + 1,
  };

  shares.set(
    id,
    updated,
  );

  return updated;
}