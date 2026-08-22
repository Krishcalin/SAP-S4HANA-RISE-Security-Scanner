namespace acme.orders;

entity Orders {
  key ID        : UUID;
      supplier  : Association to Suppliers;
      amount    : Decimal(15,2);
      iban      : String(34);
      approvedBy: String(60);
}

entity Suppliers {
  key ID       : UUID;
      name     : String(120);
      bankKey  : String(15);
      account  : String(34);
}

entity Catalogue {
  key ID   : UUID;
      title: String(120);
}
