import { render } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { MAX_PREVIEW_BYTES, useBoundedPreview, type ControlledPreview } from './preview';

function Preview({ value }: { value: ControlledPreview | null }) {
  const url = useBoundedPreview(value);
  return <output>{url ?? 'empty'}</output>;
}

describe('bounded preview lifecycle', () => {
  it('revokes replaced and unmounted object URLs', () => {
    const first = { mimeType: 'image/jpeg' as const, bytes: new Uint8Array([1]) };
    const second = { mimeType: 'image/png' as const, bytes: new Uint8Array([2]) };
    const view = render(<Preview value={first} />);
    view.rerender(<Preview value={second} />);
    view.unmount();
    expect(URL.revokeObjectURL).toHaveBeenCalledTimes(2);
  });

  it('rejects oversized previews before allocating a URL', () => {
    vi.mocked(URL.createObjectURL).mockClear();
    render(<Preview value={{ mimeType: 'image/jpeg', bytes: new Uint8Array(MAX_PREVIEW_BYTES + 1) }} />);
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});
