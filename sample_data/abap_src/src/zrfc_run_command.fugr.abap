FUNCTION zrfc_run_command.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     VALUE(IV_COMMAND) TYPE  STRING
*"     VALUE(IV_HOST) TYPE  STRING OPTIONAL
*"  EXPORTING
*"     VALUE(EV_RC) TYPE  SY-SUBRC
*"----------------------------------------------------------------------

  DATA lt_out TYPE TABLE OF btcxpm.

* RFC-enabled and reachable remotely. There is no AUTHORITY-CHECK in this
* function module at all, and the operating-system command is assembled from
* the caller's own string.
  CALL FUNCTION 'SXPG_COMMAND_EXECUTE'
    EXPORTING
      commandname                = 'ZOSCMD'
      additional_parameters      = iv_command
      operatingsystem            = sy-opsys
      targetsystem               = iv_host
    TABLES
      exec_protocol              = lt_out
    EXCEPTIONS
      OTHERS                     = 1.

  ev_rc = sy-subrc.

ENDFUNCTION.
