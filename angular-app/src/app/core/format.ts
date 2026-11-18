const ACRONYMS = new Set(['GDPR', 'HIPAA', 'PHI', 'PII', 'II', 'PCI', 'DSS', 'ID', 'IBAN', 'DOB', 'US', 'SSN', 'UK', 'CCPA', 'GLBA', 'LGPD',
  'PDPA', 'PIPL', 'APPI', 'DPDP', 'POPIA', 'NRIC', 'VAT', 'EU', 'APAC', 'MEA', 'LATAM', 'SIN', 'PAN', 'CPF', 'NINO', 'DNI', 'TFN', 'RRN', 'EPRIVACY', 'CAN', 'SPAM', 'TCPA', 'FK']);

/** The erasure trigger applies under GDPR, CCPA, LGPD and every other deletion right, so it is not labelled GDPR-only. */
export function triggerLabel(code: string | null | undefined): string {
  return code === 'GDPR_ERASURE_REQUEST' ? 'Erasure request' : pretty(code);
}

/** "GDPR_ERASURE_REQUEST" -> "GDPR erasure request", "SOLVENCY_II" -> "Solvency II" */
export function pretty(code: string | null | undefined): string {
  if (!code) return '';
  return code
    .split('_')
    .map((w, i) => (ACRONYMS.has(w) ? w : i === 0 ? w.charAt(0) + w.slice(1).toLowerCase() : w.toLowerCase()))
    .join(' ');
}

export function retention(days: number | null | undefined): string {
  if (!days) return '';
  if (days % 365 === 0) return `${days / 365} year${days === 365 ? '' : 's'}`;
  return `${days} days`;
}

export function pct(v: number | null | undefined, digits = 0): string {
  return v === null || v === undefined ? '—' : `${(v * 100).toFixed(digits)}%`;
}

/** Colour tone for any status word, used as the badge class `s-<tone>`. */
export function tone(status: string | null | undefined): string {
  switch ((status ?? '').toUpperCase()) {
    case 'ACTIVE': case 'AUTO': case 'EXECUTED': case 'COMPLETED': case 'CONNECTED': case 'RESOLVED': case 'PLAN_READY':
    case 'MASKED_VIEW': case 'IN_PLACE': case 'ANONYMISED': case 'VERIFIED':
      return 'green';
    case 'NEEDS_REVIEW': case 'DRAFT': case 'PROPOSED': case 'RUNNING': case 'QUEUED': case 'CANDIDATES_FOUND': case 'SUBMITTED':
      return 'orange';
    case 'OPEN': case 'FAILED': case 'BLOCKED': case 'DELETE':
      return 'red';
    case 'APPROVED': case 'CONFIRMED': case 'ANONYMIZE': case 'ANONYMIZE_ROOT':
      return 'blue';
    case 'RETAIN': case 'HELD': case 'COVERED':
      return 'purple';
    case 'ARCHIVE': case 'ARCHIVED':
      return 'teal';
    default:
      return 'gray'; // LOW, REJECTED, RETIRED, NONE, NO_MATCH, RELEASED ...
  }
}
