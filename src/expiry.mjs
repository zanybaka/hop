export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

export function expiresAt(state) {
  if (state == null) return null;
  const { createdAt, absoluteDeadline, lastActivityAt = createdAt, protected: guarded, hasFiles } = state;
  return guarded || hasFiles ? Math.min(absoluteDeadline, lastActivityAt + HOUR) : absoluteDeadline;
}

export function isExpired(state, now) {
  const deadline = expiresAt(state);
  return deadline === null || now >= deadline;
}

// Consumers call this only after accepting a receipt for the current version.
export function confirmActivity(state, now) {
  if (isExpired(state, now)) return null;
  return { ...state, lastActivityAt: Math.max(state.lastActivityAt ?? state.createdAt, now) };
}
