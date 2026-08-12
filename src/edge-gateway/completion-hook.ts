export function runEdgeCompletionHook(hook: () => void): void {
  try {
    hook();
  } catch {
    // Completion dependencies cannot take ownership of the client response lifecycle.
  }
}

export function createOnceEdgeCompletionHook(hook: () => void): () => void {
  let completed = false;
  return () => {
    if (completed) return;
    completed = true;
    runEdgeCompletionHook(hook);
  };
}
