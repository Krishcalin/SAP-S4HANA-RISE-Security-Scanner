using { acme.bookshop as db } from '../db/schema';

// Protected from annotations.cds, not here. A parser that required the
// annotation to be inline would report this service as unprotected.
service ReportingService {
  entity Revenue as projection on db.Revenue;

  // A FinanceAuditor may see orders. Nothing here says they may see the bank
  // details hanging off them, and `Payments` says they may not — but the
  // restriction on Payments is never evaluated on `Orders?$expand=payment`.
  entity Orders  as projection on db.Orders;
}
