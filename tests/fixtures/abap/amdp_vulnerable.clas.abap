CLASS zcl_amdp_bad DEFINITION PUBLIC.
  PUBLIC SECTION.
    INTERFACES if_amdp_marker_hdb.
    METHODS get_orders IMPORTING iv_filter TYPE string.
ENDCLASS.

CLASS zcl_amdp_bad IMPLEMENTATION.
  METHOD get_orders BY DATABASE PROCEDURE FOR HDB LANGUAGE SQLSCRIPT.
    lt_out = APPLY_FILTER( i_orders, iv_filter );
    EXECUTE IMMEDIATE 'SELECT * FROM vbak WHERE vbeln = ''' || iv_filter || '''';
  ENDMETHOD.
ENDCLASS.
