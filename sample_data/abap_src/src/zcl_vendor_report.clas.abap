CLASS zcl_vendor_report DEFINITION PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    METHODS run IMPORTING iv_where TYPE string
                          iv_table TYPE string
                RETURNING VALUE(rt_data) TYPE REF TO data.
    METHODS export_bank IMPORTING iv_lifnr TYPE lifnr.
ENDCLASS.

CLASS zcl_vendor_report IMPLEMENTATION.

  METHOD run.
    DATA lr_data TYPE REF TO data.
    FIELD-SYMBOLS <lt_tab> TYPE STANDARD TABLE.

    " Dynamic WHERE built from a caller-supplied string, and a dynamic FROM
    " beside it. Neither value is validated anywhere in this class.
    CREATE DATA lr_data TYPE STANDARD TABLE OF (iv_table).
    ASSIGN lr_data->* TO <lt_tab>.

    SELECT * FROM (iv_table)
      INTO TABLE <lt_tab>
      WHERE (iv_where).

    rt_data = lr_data.
  ENDMETHOD.

  METHOD export_bank.
    DATA lv_pass TYPE string.
    DATA lt_bank TYPE TABLE OF lfbk.

    " No AUTHORITY-CHECK anywhere before reading vendor bank details.
    SELECT * FROM lfbk INTO TABLE lt_bank WHERE lifnr = iv_lifnr.

    " Hard-coded credential for the downstream transfer.
    lv_pass = 'Wint3r2026!'.
    CALL FUNCTION 'ZBANK_TRANSFER'
      EXPORTING
        iv_user     = 'RFC_BATCH'
        iv_password = lv_pass.
  ENDMETHOD.

ENDCLASS.
