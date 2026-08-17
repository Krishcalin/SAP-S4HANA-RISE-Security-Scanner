namespace acme.bookshop;

using { cuid, managed } from '@sap/cds/common';

entity Books : cuid, managed {
  title  : String(200);
  stock  : Integer;
  price  : Decimal(9,2);
}

entity Authors : cuid { name : String(120); }
entity Drafts  : cuid, managed { title : String(200); }
entity Orders  : cuid, managed { total : Decimal(11,2); }
entity Payments: cuid, managed { iban : String(34); }
entity Queue   : cuid { payload : LargeString; }
entity Revenue : cuid { period : String(7); amount : Decimal(13,2); }
