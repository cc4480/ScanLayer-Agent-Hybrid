import { CATEGORY_NOTE, LINKS, WHAT_WE_TEST } from '../../content/siteContent.js';
import InternalLink from './InternalLink.js';

export default function WhatWeTest({ onNavigate }: { onNavigate: (view: string, arg?: string) => void }) {
  return (
    <section id="what-we-test" className="max-w-5xl mx-auto py-16 px-6 scroll-mt-20 border-t border-[#27272a]" aria-labelledby="what-we-test-title">
      <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">What we test</p>
      <h2 id="what-we-test-title" className="text-2xl font-bold font-mono tracking-tighter text-white mb-3">Seven AppSec categories</h2>
      <p className="text-[#a1a1aa] text-xs font-mono leading-relaxed max-w-3xl mb-8">
        {CATEGORY_NOTE}{' '}
        <InternalLink href={LINKS.pillars} onNavigate={onNavigate} className="text-[#22c55e] hover:underline">
          Read how each category works
        </InternalLink>.
      </p>
      <ul className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {WHAT_WE_TEST.map((c) => (
          <li key={c.key} className="bg-[#0c0c0e] border border-[#27272a] rounded-lg p-5">
            <div className="flex items-baseline justify-between gap-3 mb-2">
              <h3 className="text-white text-xs font-mono font-bold">{c.key} <span className="text-[#71717a] font-normal">{c.name}</span></h3>
            </div>
            <p className="text-[9px] font-mono uppercase tracking-wider text-[#52525b] mb-3">{c.mode}</p>
            <p className="text-[#a1a1aa] text-xs font-mono leading-relaxed">{c.what}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}
