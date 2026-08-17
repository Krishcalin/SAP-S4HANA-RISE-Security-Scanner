using { acme.bookshop as db } from '../db/schema';

// Protected from annotations.cds, not here. A parser that required the
// annotation to be inline would report this service as unprotected.
service ReportingService {
  entity Revenue as projection on db.Revenue;
}
