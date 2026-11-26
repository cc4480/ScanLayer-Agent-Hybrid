import { HOW_IT_WORKS } from '../../content/siteContent.js';

// A real sequence, so the numbers mean something: each step needs the last one.
// Same four steps as the HowTo structured data in index.html.
export default function HowItWorks() {
  return (
    <section id="how-it-works" className="max-w-5xl mx-auto py-16 px-6 scroll-mt-20 border-t border-[#27272a]" aria-labelledby="how-it-works-title">
      <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">How it works</p>
      <h2 id="how-it-works-title" className="text-2xl font-bold font-mono tracking-tighter text-white mb-8">From URL to fix in four steps</h2>
      <ol className="grid md:grid-cols-2 gap-x-10 gap-y-7">
        {HOW_IT_WORKS.map((s, i) => (
          <li key={s.name} className="flex gap-4">
            <span className="shrink-0 w-7 h-7 rounded-full border border-[#22c55e]/40 text-[#22c55e] font-mono text-xs flex items-center justify-center" aria-hidden="true">{i + 1}</span>
            <div>
              <h3 className="text-white text-sm font-mono font-bold mb-1">{s.name}</h3>
              <p className="text-[#a1a1aa] text-xs font-mono leading-relaxed">{s.text}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
