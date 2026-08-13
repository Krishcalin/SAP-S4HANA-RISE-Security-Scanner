/*
 * Whether a currency figure is the customer's, and one place that decides it.
 *
 * THE DEFECT THIS CLOSES
 * The offline reports refuse to print a currency total the customer did not
 * price: modules/report_generator.py and modules/pdf_report.py both branch on
 * `loss_model.applied` and render a "no currency figure is presented" panel
 * instead. The console never got that guard. `loss_model` was stored, put on the
 * wire, and read by nothing — five screens printed the illustrative $1bn
 * manufacturer's losses under the customer's name.
 *
 * The worst instance was the screen built to prevent exactly this: /crq renders
 * "nothing here is a benchmark, an industry average, or a number we invented"
 * unconditionally, and with no saved revision the Recompute button priced the
 * catalogue's illustrative company and showed it directly beneath that sentence.
 *
 * WHY THIS IS A MODULE AND NOT A CONDITIONAL IN EACH SCREEN
 * The previous three defects fixed in this codebase were all siblings of an
 * earlier fix that had been applied in one place and not looked past — a
 * percentage deleted from the deck but not the console, a flag repaired but not
 * the one beside it. Five copies of this rule would be five chances to fix four.
 * There is one predicate, and every screen calls it.
 */
import type { CrqPortfolio, CrqQuantifyResult } from '../api/types'

/**
 * Anything that might carry the provenance of a currency figure.
 *
 * Deliberately loose: the flag arrives as `loss_model` on a quantify response and
 * as `detail.loss_model` on a stored row, and a screen should not have to know
 * which shape it holds in order to ask an honest question.
 */
export interface MaybePriced {
  loss_model?: { applied?: boolean } | null
  detail?: { loss_model?: { applied?: boolean } | null } | null
}

/**
 * True only when the figures came from the customer's own answers.
 *
 * UNKNOWN COUNTS AS UNPRICED, and that is the whole point. A row written before
 * this field existed has no `loss_model`, and the honest reading of "we have no
 * record of where this number came from" is not "it was the customer's". Every
 * historical crq_result in the reference deployment predates it.
 */
export function isPriced(source: MaybePriced | null | undefined): boolean {
  if (!source) return false
  const direct = source.loss_model
  if (direct && typeof direct.applied === 'boolean') return direct.applied
  const nested = source.detail?.loss_model
  if (nested && typeof nested.applied === 'boolean') return nested.applied
  return false
}

/** The sentence every screen uses, so they cannot drift into disagreeing. */
export const UNPRICED_HEADLINE =
  'No currency figure is presented for this landscape.'

export const UNPRICED_BODY =
  'The model ran and matched scenarios to your findings, but nobody has told it '
  + 'what an hour of SAP downtime costs you, how many personal records you hold, '
  + 'or what a payment run is worth. The shipped catalogue is calibrated to an '
  + 'illustrative $1bn manufacturer, and printing that company’s losses under '
  + 'your name would be a fabrication rather than an estimate.'

export const UNPRICED_ACTION =
  'Supply your figures on the risk quantification screen and every currency '
  + 'figure here becomes arithmetic on them, with the working shown.'

/**
 * What to show in place of a figure. An em dash, not a zero.
 *
 * `money(0)` renders "$0", which is a claim — that the exposure was computed and
 * came to nothing. Unpriced is the absence of a computation, and the two must not
 * look alike anywhere.
 */
export const UNPRICED_CELL = '—'

/** Convenience for a stored portfolio row, which is the commonest shape. */
export function portfolioIsPriced(p: CrqPortfolio | null | undefined): boolean {
  return isPriced(p as MaybePriced | null | undefined)
}

/** Convenience for a live quantify response. */
export function resultIsPriced(r: CrqQuantifyResult | null | undefined): boolean {
  return isPriced(r as MaybePriced | null | undefined)
}
