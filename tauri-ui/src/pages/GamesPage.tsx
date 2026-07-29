import { useMutation, useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';

import { agentApi } from '../lib/agentApi';
import { queryKeys } from '../lib/queryKeys';

export function GamesPage({ enabled }: { enabled: boolean }) {
  const games = useQuery({ queryKey: queryKeys.games, queryFn: agentApi.scanInstalledGames, enabled });
  const [activeProfile, setActiveProfile] = useState<string>();
  const [previewUrl, setPreviewUrl] = useState<string>();
  const [message, setMessage] = useState<string>();
  const control = useMutation({
    mutationFn: async (operation: () => Promise<string>) => operation(),
    onSuccess: (value) => setMessage(value),
    onError: () => setMessage('操作失败，请确认游戏处于前台且当前 Profile 允许此操作。'),
  });

  useEffect(() => () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
  }, [previewUrl]);

  const launch = (profileId: string) => control.mutate(async () => {
    await agentApi.launchGame(profileId);
    setActiveProfile(profileId);
    return '游戏已启动并锁定为当前目标。';
  });
  const capture = () => control.mutate(async () => {
    const preview = await agentApi.capturePreview();
    const url = URL.createObjectURL(new Blob([new Uint8Array(preview.bytes)], { type: preview.mime_type }));
    setPreviewUrl((previous) => {
      if (previous) URL.revokeObjectURL(previous);
      return url;
    });
    return `截图已更新（${preview.width} × ${preview.height}）。`;
  });
  const input = (action: 'move_forward' | 'quick_use' | 'mouse_left') =>
    control.mutate(async () => {
      await agentApi.inputProbe(action);
      return '输入探针已执行并释放。';
    });
  const close = () => control.mutate(async () => {
    await agentApi.closeGame();
    setActiveProfile(undefined);
    return '游戏已安全关闭。';
  });

  return (
    <section className="status-card" aria-labelledby="games-heading">
      <h2 id="games-heading">已发现的米哈游游戏</h2>
      {!enabled && <p role="status">正在等待后台服务就绪。</p>}
      {enabled && games.isLoading && <p>正在扫描受支持的启动器安装。</p>}
      {enabled && games.isError && <p role="status">游戏扫描失败。</p>}
      {games.data?.games.length === 0 && <p>未发现可用游戏。</p>}
      <ul className="game-list">
        {games.data?.games.map((game) => (
          <li key={game.discovery_id}>
            <strong>{game.name}</strong>{game.version ? ` ${game.version}` : ''}
            <span>已安装：{game.installed ? '是' : '否'}；支持：{game.supported ? '是' : '否'}</span>
            {game.profile_id && (
              <button disabled={control.isPending || Boolean(activeProfile)} onClick={() => launch(game.profile_id!)} type="button">
                启动并锁定
              </button>
            )}
          </li>
        ))}
      </ul>
      {activeProfile && (
        <div className="game-controls" aria-label="本地设备控制">
          <button disabled={control.isPending} onClick={capture} type="button">更新截图</button>
          <button disabled={control.isPending} onClick={() => input('move_forward')} type="button">W 前进探针</button>
          <button disabled={control.isPending} onClick={() => input('quick_use')} type="button">快速使用探针</button>
          <button disabled={control.isPending} onClick={() => input('mouse_left')} type="button">左键探针</button>
          <button disabled={control.isPending} onClick={close} type="button">关闭游戏</button>
        </div>
      )}
      {message && <p role="status">{message}</p>}
      {previewUrl && <img className="game-preview" src={previewUrl} alt="当前游戏窗口截图" />}
      <p className="notice">启动功能只会使用已识别的游戏，不会读取或显示任意程序路径。</p>
    </section>
  );
}
