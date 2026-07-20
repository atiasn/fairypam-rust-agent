import type { UseQueryResult } from '@tanstack/react-query';

import type { Profiles } from '../lib/contracts';

type Props = {
  profiles: UseQueryResult<Profiles>;
  selectedProfileId?: string;
  onSelect: (profileId: string) => void;
};

export function ProfilesPage({ profiles, selectedProfileId, onSelect }: Props) {
  return (
    <section className="status-card" aria-labelledby="profiles-heading">
      <h2 id="profiles-heading">已签名 Profile</h2>
      {profiles.isLoading && <p>正在加载 Profile。</p>}
      {profiles.isError && <p role="alert">Profile 不可用。</p>}
      {profiles.data?.profiles.length === 0 && <p>没有可用 Profile。</p>}
      <div className="button-list">
        {profiles.data?.profiles.map((profileId) => (
          <button
            aria-pressed={selectedProfileId === profileId}
            key={profileId}
            onClick={() => onSelect(profileId)}
            type="button"
          >
            {profileId}
          </button>
        ))}
      </div>
    </section>
  );
}
