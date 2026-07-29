import type { Availability } from '../lib/connectionReducer';

type Props = { availability: Availability; title: string; detail: string };

const availabilityLabels: Record<Availability, string> = {
  online: '在线',
  offline: '离线',
  emergency: '保护状态',
  unknown: '正在确认',
};

export function StatusPanel({ availability, title, detail }: Props) {
  return (
    <section className="status-card" aria-labelledby="status-heading">
      <p className="eyebrow">{availabilityLabels[availability]}</p>
      <h2 id="status-heading">{title}</h2>
      <p>{detail}</p>
    </section>
  );
}
