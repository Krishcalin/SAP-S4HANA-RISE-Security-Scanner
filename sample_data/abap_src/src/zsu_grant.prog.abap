REPORT zsu_grant.

PARAMETERS: p_user TYPE xubname,
            p_prof TYPE xuprofile DEFAULT 'SAP_ALL'.

START-OF-SELECTION.

* AUTHORITY-CHECK is present but its result is never examined: SY-SUBRC is
* overwritten by the SELECT below before anything reads it.
  AUTHORITY-CHECK OBJECT 'S_USER_GRP'
    ID 'CLASS' DUMMY
    ID 'ACTVT' FIELD '02'.

  SELECT SINGLE bname FROM usr02 INTO @DATA(lv_bname) WHERE bname = @p_user.
  IF sy-subrc = 0.
    CALL FUNCTION 'SUSR_USER_PROFILES_ASSIGN'
      EXPORTING
        username = p_user
        profile  = p_prof.
    WRITE: / 'granted', p_prof, 'to', p_user.
  ENDIF.
