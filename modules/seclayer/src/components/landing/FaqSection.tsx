import { useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { FAQS, LINKS } from '../../content/siteContent.js';

export default function FaqSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  return (
    <div id="faq" className="max-w-4xl mx-auto py-24 px-6 scroll-mt-20">
      <div className="text-center mb-12">
        <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">Frequently Asked Questions</p>
        <h2 className="text-3xl font-mono tracking-tighter font-bold text-white">What people ask before their first scan</h2>
        <p className="text-[#a1a1aa] text-xs font-mono mt-3 max-w-md mx-auto">
          Read the full <a href={LINKS.docs} className="text-[#22c55e] hover:underline">Documentation</a> for how each scan module actually works.
        </p>
      </div>

      <div className="space-y-3">
        {FAQS.map((item, i) => {
          const open = openIndex === i;
          return (
            <div key={item.q} className="bg-[#0c0c0e] border border-[#27272a] rounded-lg overflow-hidden">
              <button
                onClick={() => setOpenIndex(open ? null : i)}
                className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left cursor-pointer hover:bg-black/30 transition-colors"
                aria-expanded={open}
              >
                <span className="text-white text-xs sm:text-sm font-mono font-bold">{item.q}</span>
                <ChevronDown className={`w-4 h-4 text-[#52525b] shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden="true" />
              </button>
              {open && (
                <div className="px-5 pb-5 pt-0 animate-fade-in">
                  <p className="text-[#a1a1aa] text-xs font-mono leading-relaxed">{item.a}</p>
                </div>
              )}
            </div>
          );
        })}
      </div>

    </div>
  );
}
