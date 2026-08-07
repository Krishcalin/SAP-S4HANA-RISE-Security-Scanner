@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'Vendor master exposure'
define view entity ZI_VendorOpen as select from lfa1 {
  key lifnr,
      name1,
      stcd1
}
