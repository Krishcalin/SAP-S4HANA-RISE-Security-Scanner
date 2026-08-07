REPORT z_misc_bad.
DATA lv_url TYPE string.
START-OF-SELECTION.
  lv_url = request->get_form_field( 'target' ).
  cl_http_client=>create_by_url( url = lv_url IMPORTING client = DATA(lo_client) ).

  DATA(lo_ixml) = cl_ixml=>create( ).
  DATA(lo_stream) = lo_ixml->create_stream_factory( )->create_stream_for_string( lv_xml ).

  TEST-SEAM read_config.
    lv_cfg = zcl_config=>get( ).
  END-TEST-SEAM.
