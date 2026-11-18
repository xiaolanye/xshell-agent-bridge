const SAFETY_MODES = new Set(['safe', 'normal', 'full']);

export function parseSafetyMode(value = 'safe') {
  if (!SAFETY_MODES.has(value)) {
    throw new Error('XSHELL_SAFETY_MODE must be one of: safe, normal, full.');
  }
  return value;
}
