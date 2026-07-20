import { beforeEach, describe, expect, it, vi } from 'vitest';

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import { agentApi } from './agentApi';

describe('agentApi', () => {
  beforeEach(() => invoke.mockReset());

  it('uses only fixed command names and typed arguments', async () => {
    await agentApi.listTargets('signed-profile');
    await agentApi.lockTarget('signed-profile', 'candidate-1');
    await agentApi.releaseAll();

    expect(invoke).toHaveBeenNthCalledWith(1, 'list_targets', { profileId: 'signed-profile' });
    expect(invoke).toHaveBeenNthCalledWith(2, 'lock_target', {
      profileId: 'signed-profile',
      candidateId: 'candidate-1',
    });
    expect(invoke).toHaveBeenNthCalledWith(3, 'release_all');
  });
});
