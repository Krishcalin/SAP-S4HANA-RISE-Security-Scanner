CLASS zcl_amdp_good DEFINITION PUBLIC.
  PUBLIC SECTION.
    METHODS get_orders IMPORTING iv_vbeln TYPE vbeln.
ENDCLASS.

CLASS zcl_amdp_good IMPLEMENTATION.
  METHOD get_orders.
    AUTHORITY-CHECK OBJECT 'V_VBAK_VKO' ID 'ACTVT' FIELD '03'.
    IF sy-subrc <> 0.
      MESSAGE 'Not authorised' TYPE 'E'.
    ENDIF.
    SELECT * FROM vbak INTO TABLE @DATA(lt_orders) WHERE vbeln = @iv_vbeln.
  ENDMETHOD.
ENDCLASS.
