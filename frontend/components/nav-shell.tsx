import type { ReactNode } from "react";

const NAV_ITEMS = [
  { href: "/", label: "Home", code: "OVR" },
  { href: "/fleet", label: "Fleet", code: "FLT" },
  { href: "/controls", label: "Controls", code: "CTL" },
  { href: "/approvals", label: "Approvals", code: "APR" },
  { href: "/installers", label: "Installers", code: "PKG" },
] as const;

type NavShellProps = {
  currentPath?: string;
  title: string;
  description: string;
  children: ReactNode;
  actions?: ReactNode;
};

export default function NavShell({ currentPath = "/", title, description, children, actions }: NavShellProps) {
  return (
    <div className="shell">
      <header className="command-header">
        <div className="command-header__topline">
          <div className="brand-mark">
            <span className="brand-mark__code">SHA</span>
            <div>
              <p className="brand-mark__eyebrow">Security Hardening Automation</p>
              <p className="brand-mark__meta">operator supervised autonomy • same-origin api routing</p>
            </div>
          </div>
          <div className="command-header__badges">
            <span className="tone tone--success">Public edge</span>
            <span className="tone tone--warning">Operator supervised autonomy</span>
            <span className="tone tone--info">Dark amber containment rail</span>
          </div>
        </div>

        <div className="command-header__main">
          <div className="command-header__copy">
            <p className="command-header__eyebrow">Security control plane</p>
            <h1>{title}</h1>
            <p className="command-header__description">{description}</p>
          </div>
          {actions ? <div className="command-header__actions">{actions}</div> : null}
        </div>
      </header>

      <nav aria-label="Primary" className="primary-nav">
        {NAV_ITEMS.map((item) => {
          const isActive = currentPath === item.href;
          return (
            <a
              key={item.href}
              className="nav-link"
              data-active={isActive ? "true" : "false"}
              href={item.href}
            >
              <span aria-hidden="true" className="nav-link__code">{item.code}</span>
              <span>{item.label}</span>
            </a>
          );
        })}
      </nav>

      <main className="shell-main">{children}</main>
    </div>
  );
}
