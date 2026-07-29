import { beforeEach, describe, expect, it, vi } from 'vitest';

const { invoke, listen } = vi.hoisted(() => ({ invoke: vi.fn(), listen: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen }));

import { agentApi } from './agentApi';

describe('agentApi', () => {
  beforeEach(() => {
    invoke.mockReset();
    listen.mockReset();
  });

  it('uses fixed local Gateway commands without command-line registration secrets', async () => {
    await agentApi.ensureLocalAgent();
    await agentApi.getLogTail(100, 'warn');
    await agentApi.registerHub('0123456789abcdef');

    expect(invoke).toHaveBeenNthCalledWith(1, 'ensure_local_agent');
    expect(invoke).toHaveBeenNthCalledWith(2, 'get_log_tail', { lines: 100, level: 'warn' });
    expect(invoke).toHaveBeenNthCalledWith(3, 'register_hub', {
      registrationCode: '0123456789abcdef',
    });
  });

  it('subscribes to the fixed activation event', async () => {
    const handler = vi.fn();
    await agentApi.onLocalAgentActivation(handler);

    expect(listen).toHaveBeenCalledWith('local-agent-activation', handler);
  });

  it('subscribes to embedded runtime failures', async () => {
    const handler = vi.fn();
    await agentApi.onEmbeddedRuntimeFailed(handler);

    expect(listen).toHaveBeenCalledWith('embedded-runtime-failed', handler);
  });

  it('subscribes to native emergency recovery', async () => {
    const handler = vi.fn();
    await agentApi.onEmergencyReset(handler);

    expect(listen).toHaveBeenCalledWith('emergency-reset', handler);
  });

  it('subscribes to rejected native emergency recovery', async () => {
    const handler = vi.fn();
    await agentApi.onEmergencyResetFailed(handler);

    expect(listen).toHaveBeenCalledWith('emergency-reset-failed', handler);
  });
});
