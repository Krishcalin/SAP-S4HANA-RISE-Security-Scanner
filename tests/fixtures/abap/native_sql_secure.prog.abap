REPORT z_native_good.
START-OF-SELECTION.
  AUTHORITY-CHECK OBJECT 'M_MATE_MAT' ID 'ACTVT' FIELD '03'.
  IF sy-subrc <> 0.
    MESSAGE 'Not authorised' TYPE 'E'.
  ENDIF.
  SELECT matnr FROM mara INTO TABLE @DATA(lt_mat) WHERE matnr = @p_matnr.
