import type { Availability } from '../lib/connectionReducer';

type Props = { availability: Availability; title: string; detail: string };

export function StatusPanel({ availability, title, detail }: Props) {
  return (
    <section className="status-card" aria-labelledby="status-heading">
      <p className="eyebrow">{availability.toUpperCase()}</p>
      <h2 id="status-heading">{title}</h2>
      <p>{detail}</p>
    </section>
  );
}
