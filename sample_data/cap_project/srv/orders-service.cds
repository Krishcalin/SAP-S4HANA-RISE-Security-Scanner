using { acme.orders as db } from '../db/schema';

service OrdersService @(path: '/orders') {

  // No @requires at service or entity level: the service is reachable by any
  // authenticated user, and Orders carries the bank details below.
  entity Orders as projection on db.Orders;

  @readonly
  entity Suppliers as projection on db.Suppliers;

  // Explicitly opened to unauthenticated callers.
  @(requires: 'any')
  entity PublicCatalogue as projection on db.Catalogue;

  action approvePayment(order: String, amount: Decimal) returns Boolean;
}
