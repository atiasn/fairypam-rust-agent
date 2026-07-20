import { beforeEach, describe, expect, it, vi } from 'vitest';

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import { agentApi } from './agentApi';

describe('agentApi', () => {
  beforeEach(() => invoke.mockReset());

  it('uses fixed local Gateway commands without command-line registration secrets', async () => {
    await agentApi.ensureLocalAgent();
    await agentApi.getLogTail(100, 'warn');
    await agentApi.registerHub('https://hub.test', '0123456789abcdef');

    expect(invoke).toHaveBeenNthCalledWith(1, 'ensure_local_agent');
    expect(invoke).toHaveBeenNthCalledWith(2, 'get_log_tail', { lines: 100, level: 'warn' });
    expect(invoke).toHaveBeenNthCalledWith(3, 'register_hub', {
      hubAddress: 'https://hub.test',
      registrationCode: '0123456789abcdef',
    });
  });
});
