// Tracks drafts against the last observed publication version. Transport is external.
export function createEditorState(version, content) {
  return { version, draft: content, dirty: false, replacedVersion: null, confirmedVersion: null };
}

export function editDraft(state, draft) {
  return { ...state, draft, dirty: true, confirmedVersion: null };
}

export function receiveVersion(state, version, content) {
  if (version <= state.version) return state;
  if (!state.dirty) return createEditorState(version, content);
  return { ...state, version, replacedVersion: version, confirmedVersion: null };
}

export function prepareSend(state) {
  if (state.replacedVersion !== null && state.confirmedVersion !== state.replacedVersion) {
    const confirmed = { ...state, confirmedVersion: state.replacedVersion };
    return { state: confirmed, request: null };
  }
  return { state, request: { version: state.version, content: state.draft } };
}
