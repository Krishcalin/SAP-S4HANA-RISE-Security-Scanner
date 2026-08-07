REPORT z_misc_good.
START-OF-SELECTION.
  cl_http_client=>create_by_destination(
    EXPORTING destination = 'ZVENDOR_API'
    IMPORTING client      = DATA(lo_client) ).
  SELECT single name1 FROM lfa1 INTO @DATA(lv_name) WHERE lifnr = @p_lifnr.
