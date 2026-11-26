import { LINKS, QUICK_ANSWERS } from '../../content/siteContent.js';
import InternalLink from './InternalLink.js';

// Plain, declarative answers to the four questions people (and answer engines)
// ask first. The text comes from siteContent.ts, which is also what the static
// HTML fallback is built from.
const MORE: { label: string; href: string }[] = [
  { label: 'How PROVEN findings work', href: LINKS.evidence },
  { label: 'See pricing and credits', href: LINKS.pricing },
  { label: 'Read how each of the seven categories works', href: LINKS.pillars },
  { label: 'MCP and API setup', href: LINKS.mcp },
];

export default function QuickAnswers({ onNavigate }: { onNavigate: (view: string, arg?: string) => void }) {
  return (
    <section id="quick-answers" className="max-w-5xl mx-auto py-16 px-6 scroll-mt-20" aria-labelledby="quick-answers-title">
      <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">Quick answers</p>
      <h2 id="quick-answers-title" className="text-2xl font-bold font-mono tracking-tighter text-white mb-8">The short version</h2>
      <dl className="grid md:grid-cols-2 gap-x-10 gap-y-7">
        {QUICK_ANSWERS.map((item, i) => (
          <div key={item.q}>
            <dt className="text-white text-sm font-mono font-bold mb-2">{item.q}</dt>
            <dd className="text-[#a1a1aa] text-xs font-mono leading-relaxed">
              {item.a}{' '}
              <InternalLink href={MORE[i].href} onNavigate={onNavigate} className="text-[#22c55e] hover:underline whitespace-nowrap">
                {MORE[i].label}
              </InternalLink>
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
