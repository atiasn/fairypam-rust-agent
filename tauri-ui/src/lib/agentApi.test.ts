import { beforeEach, describe, expect, it, vi } from 'vitest';

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import { agentApi } from './agentApi';

describe('agentApi', () => {
  beforeEach(() => invoke.mockReset());

  it('uses fixed user-facing commands without command-line registration secrets', async () => {
    await agentApi.ensureLocalAgent();
    await agentApi.getLogTail(100, 'warn');
    await agentApi.startEnrollment();
    await agentApi.completeEnrollment('https://hub.test', 'one-time-code');

    expect(invoke).toHaveBeenNthCalledWith(1, 'ensure_local_agent');
    expect(invoke).toHaveBeenNthCalledWith(2, 'get_log_tail', { lines: 100, level: 'warn' });
    expect(invoke).toHaveBeenNthCalledWith(3, 'start_enrollment');
    expect(invoke).toHaveBeenNthCalledWith(4, 'complete_enrollment', {
      hub: 'https://hub.test',
      code: 'one-time-code',
    });
  });
});
