import type { ReactNode } from "react";

const NAV_ITEMS = [
  { href: "/", label: "Home" },
  { href: "/fleet", label: "Fleet" },
  { href: "/controls", label: "Controls" },
  { href: "/approvals", label: "Approvals" },
  { href: "/installers", label: "Installers" },
] as const;

type NavShellProps = {
  title: string;
  description: string;
  children: ReactNode;
  actions?: ReactNode;
};

export default function NavShell({ title, description, children, actions }: NavShellProps) {
  return (
    <div className="shell">
      <header className="shell-header">
        <div className="shell-header__copy">
          <p className="eyebrow">SHA / Security Hardening Automation</p>
          <h1>{title}</h1>
          <p className="lead">{description}</p>
        </div>
        {actions ? <div className="shell-header__actions">{actions}</div> : null}
      </header>

      <nav aria-label="Primary" className="primary-nav">
        {NAV_ITEMS.map((item) => (
          <a key={item.href} className="nav-link" href={item.href}>
            {item.label}
          </a>
        ))}
      </nav>

      <main className="shell-main">{children}</main>
    </div>
  );
}
