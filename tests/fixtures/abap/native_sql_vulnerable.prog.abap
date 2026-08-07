REPORT z_native_bad.
DATA lv_stmt TYPE string.
START-OF-SELECTION.
  lv_stmt = |SELECT * FROM mara WHERE matnr = '{ p_matnr }'|.
  EXEC SQL.
    SELECT matnr INTO :lv_matnr FROM mara
  ENDEXEC.
  DATA(lo_sql) = NEW cl_sql_statement( ).
  lo_sql->execute_query( lv_stmt ).
