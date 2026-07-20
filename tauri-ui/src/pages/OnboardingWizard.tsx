import type { UseQueryResult } from '@tanstack/react-query';

import { WizardStep } from '../components/WizardStep';
import type { ConnectionState } from '../lib/connectionReducer';
import type { Doctor, Overview } from '../lib/contracts';

type Props = {
  connection: ConnectionState;
  canMutate: boolean;
  overview: UseQueryResult<Overview>;
  doctor: UseQueryResult<Doctor>;
};

const steps = ['安装完整性', 'Agent 与 Guardian', 'Profile', '目标', '预览', 'Core', 'DryRun', '紧急停止', '自启动'];

export function OnboardingWizard({ connection, overview, doctor }: Props) {
  const online = connection.availability === 'online';
  const profiles = doctor.data?.profiles ?? overview.data?.doctor.profiles ?? [];
  return (
    <section className="status-card" aria-labelledby="onboarding-heading">
      <p className="eyebrow">SAFE FIRST RUN</p>
      <h2 id="onboarding-heading">首次向导</h2>
      <p>完成检查只会保留 DryRun 或 Idle；不会自动 Armed、锁定目标或发送输入。</p>
      <ol className="wizard-list">
        {steps.map((step, index) => (
          <WizardStep
            detail={index < 2 ? (online ? '可继续核对' : '等待本地 Agent') : index === 2 ? `${profiles.length} 个 Profile` : '需要用户显式继续'}
            index={index + 1}
            key={step}
            label={step}
            passed={index < 2 && online}
          />
        ))}
      </ol>
    </section>
  );
}
