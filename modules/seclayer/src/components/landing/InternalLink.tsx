import type { MouseEvent, ReactNode } from 'react';

// A real <a href> so a crawler can follow it and a visitor can open it in a new
// tab, that still navigates inside the app on a plain click (no page reload).
// A link to /docs#pillars opens the docs view, then scrolls to that section.
export default function InternalLink({
  href, onNavigate, className, id, children,
}: {
  href: string;
  onNavigate: (view: string, arg?: string) => void;
  className?: string;
  id?: string;
  children: ReactNode;
}) {
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    const [path, hash] = href.split('#');
    onNavigate(path === '/docs' ? 'docs' : path === '/privacy' ? 'privacy' : path === '/terms' ? 'terms' : 'landing');
    if (hash) {
      // The target view mounts on the next render; wait for it before scrolling.
      requestAnimationFrame(() => requestAnimationFrame(() => {
        document.getElementById(hash)?.scrollIntoView({ behavior: 'smooth' });
      }));
    } else {
      window.scrollTo({ top: 0 });
    }
  };
  return <a href={href} onClick={onClick} className={className} id={id}>{children}</a>;
}
