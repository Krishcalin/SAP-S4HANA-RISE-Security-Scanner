namespace acme.bookshop;

using { cuid, managed } from '@sap/cds/common';

entity Books : cuid, managed {
  title  : String(200);
  stock  : Integer;
  price  : Decimal(9,2);
}

entity Authors : cuid { name : String(120); }
entity Drafts  : cuid, managed { title : String(200); }

// The navigation graph. An order belongs to a customer and owns a payment, and
// both of those carry data the order itself does not — which is the whole point
// of the $expand exposure: the caller is authorized against Orders and reads
// Payments.
entity Orders : cuid, managed {
  total    : Decimal(11,2);
  customer : Association to Customers;
  payment  : Composition of Payments;
}

entity Customers : cuid {
  @PersonalData.IsPotentiallyPersonal
  email  : String(255);
  orders : Association to many Orders on orders.customer = $self;
}

// Restricted deliberately, and restricted in the place a developer would put
// it. The restriction is real; what the runtime does with it on a navigation
// path is the subject of CAPX-CDS-004.
@(requires: 'Treasury')
entity Payments : cuid, managed {
  @PersonalData.IsPotentiallySensitive
  iban : String(34);
}

entity Queue   : cuid { payload : LargeString; }
entity Revenue : cuid { period : String(7); amount : Decimal(13,2); }
