import type { Plugin } from 'vite';
import { renderFallbackHtml, renderFaqJsonLd } from './src/content/staticHtml.js';

export const FALLBACK_MARKER = '<!--STATIC_FALLBACK-->';
export const FAQ_MARKER = '<!--FAQ_JSONLD-->';

// Fills the two markers in index.html with content built from siteContent.ts,
// so crawlers that do not run JavaScript get the same text a visitor sees.
export function staticFallback(): Plugin {
  return {
    name: 'seclayer-static-fallback',
    transformIndexHtml: {
      order: 'pre',
      handler(html: string) {
        return html.replace(FALLBACK_MARKER, renderFallbackHtml()).replace(FAQ_MARKER, renderFaqJsonLd());
      },
    },
  };
}
