import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { App } from './App';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => undefined) }));

function success(command: string) {
  if (command === 'query_agent_status') return Promise.resolve({ lifecycle: 'connected', activeProfileId: null, targetLocked: false, captureActive: false });
  if (command === 'query_suite_status') return Promise.resolve({ installation: 'healthy', guardian: 'installed', controlMode: 'dry_run', update: 'idle', autostart: 'enabled', canRequestUpdate: true });
  if (command === 'query_diagnostics') return Promise.resolve({ agentVersion: '0.1.0', buildCommit: 'test', protocol: '1.0', controlConnected: false, auditEnabled: true });
  if (command === 'run_doctor') return Promise.resolve([]);
  if (command === 'list_profiles' || command === 'list_targets') return Promise.resolve([]);
  return Promise.resolve({ holds: 0, state: 'released' });
}

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><App /></QueryClientProvider>);
}

afterEach(() => invoke.mockReset());

describe('Agent UI', () => {
  it('renders loading, empty and recovery states without color-only status', async () => {
    let resolveStatus: ((value: unknown) => void) | undefined;
    invoke.mockImplementation((command: string) => command === 'query_agent_status' ? new Promise((resolve) => { resolveStatus = resolve; }) : success(command));
    renderApp();
    expect(screen.getByRole('status')).toHaveTextContent('读取中');
    await waitFor(() => expect(resolveStatus).toBeDefined());
    resolveStatus!({ lifecycle: 'connected', activeProfileId: null, targetLocked: false, captureActive: false });
    await screen.findByText('Agent 在线');
    fireEvent.click(screen.getByRole('button', { name: 'Profile 与目标' }));
    expect(await screen.findByText('没有匹配目标。')).toBeVisible();
  });

  it('shows an actionable offline failure instead of claiming startup success', async () => {
    invoke.mockRejectedValue({ code: 'agent_unavailable', message: 'offline', retryable: true });
    renderApp();
    expect(await screen.findByText('Agent 未运行或本地管道不可用')).toBeVisible();
    expect(screen.queryByText('启动成功')).not.toBeInTheDocument();
  });

  it('keeps navigation keyboard reachable', async () => {
    invoke.mockImplementation(success);
    const user = userEvent.setup();
    renderApp();
    await screen.findByText('Agent 在线');
    await user.tab();
    expect(screen.getByRole('button', { name: '首页' })).toHaveFocus();
  });

  it('renders the main control page without axe violations', async () => {
    invoke.mockImplementation(success);
    const { container } = renderApp();
    await screen.findByText('Agent 在线');
    // ponytail: jsdom cannot measure rendered contrast; leave that rule to a real GUI/browser gate.
    const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(result.violations).toEqual([]);
  });

  it('never exposes an Armed action in the wizard', async () => {
    invoke.mockImplementation(success);
    renderApp();
    await screen.findByText('Agent 在线');
    fireEvent.click(screen.getByRole('button', { name: '首次向导' }));
    await waitFor(() => expect(screen.getByRole('button', { name: '完成向导' })).toBeDisabled());
    expect(screen.queryByRole('button', { name: /Armed|武装/ })).not.toBeInTheDocument();
  });
});
