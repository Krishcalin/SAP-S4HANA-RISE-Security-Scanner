using { CatalogService } from './catalog-service';
using { ReportingService } from './reporting-service';

// Entity-level rules applied from a separate file — the common CAP layout, and
// the reason a parser that only reads inline annotations misses half of them.
annotate CatalogService.Books with @(restrict: [
  { grant: 'READ' },
  { grant: 'WRITE', to: 'Vendor' }
]);

annotate CatalogService.Authors with @(restrict: [
  { grant: 'READ', to: 'authenticated-user' }
]);

annotate ReportingService with @(requires: 'FinanceAuditor');
