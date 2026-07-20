type Props = { index: number; label: string; passed: boolean; detail: string };

export function WizardStep({ index, label, passed, detail }: Props) {
  return (
    <li className={passed ? 'wizard-step passed' : 'wizard-step'}>
      <strong>
        {index}. {label}
      </strong>
      <span>{passed ? '已检查' : '待检查'}：{detail}</span>
    </li>
  );
}
