@AccessControl.authorizationCheck: #CHECK
@EndUserText.label: 'Vendor master'
define view entity ZI_Vendor as select from lfa1 {
  key lifnr,
      name1
}
