import type { ReactNode } from "react";

import { type Tone } from "../lib/api";

export function toneClass(tone: Tone) {
  return `tone tone--${tone}`;
}

export function SectionHeader({ eyebrow, title, description }: { eyebrow: string; title: string; description?: string }) {
  return (
    <div className="section-header">
      <p className="section-header__eyebrow">{eyebrow}</p>
      <div>
        <h2>{title}</h2>
        {description ? <p className="section-header__description">{description}</p> : null}
      </div>
    </div>
  );
}

export function StatCard({
  label,
  value,
  meta,
  tone = "info",
}: {
  label: string;
  value: number | string;
  meta: string;
  tone?: Tone;
}) {
  return (
    <article className={`stat-card stat-card--${tone}`}>
      <span className="stat-card__label">{label}</span>
      <strong className="stat-card__value">{value}</strong>
      <span className="stat-card__meta">{meta}</span>
    </article>
  );
}

export function Badge({ tone = "info", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={toneClass(tone)}>{children}</span>;
}

export function Panel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <section className={`console-panel ${className}`.trim()}>{children}</section>;
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{body}</p>
      {action ? <div>{action}</div> : null}
    </div>
  );
}

export function FieldLabel({ htmlFor, children }: { htmlFor: string; children: ReactNode }) {
  return (
    <label className="field" htmlFor={htmlFor}>
      <span className="field__label">{children}</span>
    </label>
  );
}
