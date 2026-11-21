// Receipt builder shared by the red-team modules. Quotes the exact matched text with a window
// of surrounding response so the finding proves itself. Request headers are never included.

export function buildEvidence({ method, attackUrl, status, contentType, body, matchIndex, quote, why, demonstration }) {
  const start = Math.max(0, matchIndex - 160)
  const end = matchIndex + quote.length + 160
  return {
    method,
    attackUrl,
    status,
    contentType,
    quote,
    excerpt: body.slice(start, end),
    why,
    demonstration,
  }
}
