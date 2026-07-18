import { useEffect, useState } from 'react';

export const MAX_PREVIEW_BYTES = 4 * 1024 * 1024;

export interface ControlledPreview {
  mimeType: 'image/jpeg' | 'image/png';
  bytes: Uint8Array;
}

export function useBoundedPreview(preview: ControlledPreview | null): string | null {
  const [url, setUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!preview || preview.bytes.byteLength > MAX_PREVIEW_BYTES) {
      setUrl(null);
      return;
    }
    const next = URL.createObjectURL(
      new Blob([new Uint8Array(preview.bytes)], { type: preview.mimeType }),
    );
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [preview]);

  return url;
}
