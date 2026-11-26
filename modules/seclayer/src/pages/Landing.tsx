import HeroSection from '../components/landing/HeroSection.js';
import PricingSection from '../components/landing/PricingSection.js';
import McpSection from '../components/landing/McpSection.js';
import SampleReportSection from '../components/landing/SampleReportSection.js';
import FaqSection from '../components/landing/FaqSection.js';
import QuickAnswers from '../components/landing/QuickAnswers.js';
import HowItWorks from '../components/landing/HowItWorks.js';
import WhatWeTest from '../components/landing/WhatWeTest.js';
import InternalLink from '../components/landing/InternalLink.js';

interface LandingProps {
  onStartTrial: (initialUrl: string) => void;
  onNavigate: (view: string, arg?: string) => void;
  onSelectPack: (packName: 'single' | 'pack5' | 'pack20') => void;
  freeMode: boolean;
}

export default function Landing({ onStartTrial, onNavigate, onSelectPack, freeMode }: LandingProps) {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] selection:bg-[#22c55e]/30 selection:text-[#22c55e]">
      <HeroSection onStartTrial={onStartTrial} />
      <QuickAnswers onNavigate={onNavigate} />
      <HowItWorks />
      <WhatWeTest onNavigate={onNavigate} />
      <PricingSection onSelectPack={onSelectPack} freeMode={freeMode} />
      <McpSection onNavigate={onNavigate} />
      <SampleReportSection />
      <FaqSection />

      {/* Footer */}
      <footer className="border-t border-[#27272a] bg-[#0c0c0e] py-12 text-[#a1a1aa] text-xs font-mono text-center">
        <div className="max-w-7xl mx-auto px-6 space-y-4">
          <p className="text-[11px]">Domain: <strong className="text-white">seclayer.app</strong></p>
          <nav className="flex items-center justify-center gap-4 text-[11px]" aria-label="Legal">
            <InternalLink href="/docs" onNavigate={onNavigate} className="text-[#52525b] hover:text-[#22c55e] transition-colors cursor-pointer">Docs</InternalLink>
            <span className="text-[#27272a]" aria-hidden="true">•</span>
            <InternalLink href="/privacy" onNavigate={onNavigate} className="text-[#52525b] hover:text-[#22c55e] transition-colors cursor-pointer" id="footer-privacy">Privacy Policy</InternalLink>
            <span className="text-[#27272a]" aria-hidden="true">•</span>
            <InternalLink href="/terms" onNavigate={onNavigate} className="text-[#52525b] hover:text-[#22c55e] transition-colors cursor-pointer" id="footer-terms">Terms of Service</InternalLink>
          </nav>
          <p className="text-[#52525b]">© 2026 Seclayer Penetration Technologies. All rights reserved. Support: hello@seclayer.app</p>
        </div>
      </footer>
    </div>
  );
}
