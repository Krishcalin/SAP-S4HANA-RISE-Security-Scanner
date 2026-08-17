using { acme.bookshop as db } from '../db/schema';

/**
 * Public browsing surface. Restricted to authenticated users only —
 * the entity-level rules live in annotations.cds.
 */
@(requires: 'authenticated-user')
service CatalogService {
  entity Books   as projection on db.Books;
  entity Authors as projection on db.Authors;
}

// Vendors maintain their own titles. Note the URL in this comment is not a
// comment terminator problem: https://acme.example/docs//vendor-rules
@requires: 'Vendor'
service VendorService {
  entity MyBooks as projection on db.Books;

  @restrict: [
    { grant: 'READ',  to: 'Vendor', where: (createdBy = $user) },
    { grant: 'WRITE', to: 'Vendor' }
  ]
  entity Drafts as projection on db.Drafts;
}

/* An internal service, not exposed through any protocol adapter. */
@protocol: 'none'
service ReplicationService {
  entity Queue as projection on db.Queue;
}

service AdminService {
  entity Books     as projection on db.Books;
  entity Orders    as projection on db.Orders;
  entity Payments  as projection on db.Payments;
  entity Customers as projection on db.Customers;
}
