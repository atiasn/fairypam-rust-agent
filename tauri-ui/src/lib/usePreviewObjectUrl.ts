import { useEffect, useState } from 'react';

import type { PreviewDto } from './contracts';

const MAX_PREVIEW_BYTES = 1_048_576;

export function usePreviewObjectUrl(preview?: PreviewDto): string | undefined {
  const [url, setUrl] = useState<string>();

  useEffect(() => {
    if (!preview || preview.bytes.length > MAX_PREVIEW_BYTES) {
      setUrl(undefined);
      return;
    }
    const objectUrl = URL.createObjectURL(new Blob([new Uint8Array(preview.bytes)], { type: preview.mimeType }));
    setUrl(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [preview]);

  return url;
}
