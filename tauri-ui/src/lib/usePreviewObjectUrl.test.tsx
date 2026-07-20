import { renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { usePreviewObjectUrl } from './usePreviewObjectUrl';

describe('usePreviewObjectUrl', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('revokes the previous URL on refresh and on unmount', () => {
    const create = vi.fn().mockReturnValueOnce('blob:a').mockReturnValueOnce('blob:b');
    const revoke = vi.fn();
    vi.stubGlobal('URL', { createObjectURL: create, revokeObjectURL: revoke });
    const { rerender, unmount } = renderHook(({ bytes }) => usePreviewObjectUrl({ mimeType: 'image/png', bytes }), {
      initialProps: { bytes: [1] },
    });

    rerender({ bytes: [2] });
    expect(revoke).toHaveBeenCalledWith('blob:a');
    unmount();
    expect(revoke).toHaveBeenCalledWith('blob:b');
  });
});
