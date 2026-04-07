// ── Rückwärtskompatibilität ──────────────────────────────────────────
//
// Dieses Modul existiert nur damit bestehende Imports wie
// `import { api } from '../services/api'` weiterhin funktionieren.
// Die eigentliche Implementierung liegt in `./api/index.ts`.

export { api } from './api/index';
