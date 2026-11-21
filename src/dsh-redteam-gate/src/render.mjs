// Output renderer shared by every red-team tool. defineTool (dsh core/tools) requires output.render: without it the
// tool call returns "output.render failed: userRender is not a function" and the result is lost.
// Contract: render(args, value) -> [{ type: 'text', text }].
export function renderText(_args, value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  return [{ type: 'text', text: text ?? '' }]
}
