import { useQuery } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';
import { queryKeys } from '../lib/queryKeys';

export function GamesPage() {
  const games = useQuery({ queryKey: queryKeys.games, queryFn: agentApi.scanInstalledGames });

  return (
    <section className="status-card" aria-labelledby="games-heading">
      <h2 id="games-heading">已发现的米哈游游戏</h2>
      {games.isLoading && <p>正在扫描受支持的启动器安装。</p>}
      {games.isError && <p role="status">游戏扫描失败。</p>}
      {games.data?.games.length === 0 && <p>未发现可用游戏。</p>}
      <ul className="game-list">
        {games.data?.games.map((game) => (
          <li key={game.discovery_id}>
            <strong>{game.name}</strong>{game.version ? ` ${game.version}` : ''}
            <span>已安装：{game.installed ? '是' : '否'}；支持：{game.supported ? '是' : '否'}</span>
          </li>
        ))}
      </ul>
      <p className="notice">启动功能只会接受已发现的 discovery_id；本界面不接收或显示任意 EXE 路径。</p>
    </section>
  );
}
