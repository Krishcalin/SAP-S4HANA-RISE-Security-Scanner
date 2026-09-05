* Taint that crosses a procedure boundary.
*
* Every sink below is reached by data the caller controls, and every one of them
* is one PERFORM or one method call away from its source. This is the ordinary
* shape of custom ABAP: the selection screen is read in one place and the work is
* done in a subroutine, because that is what every ABAP style guide asks for.
*
* An analyser that resets at ENDFORM sees three procedures that each begin with a
* clean slate and rates all of these the same as a hard-coded query.
REPORT z_interproc_bad.

PARAMETERS: p_carr TYPE string,
            p_tab  TYPE string.

START-OF-SELECTION.
* 1. Positional USING. The classic.
  PERFORM run_query USING p_carr.

* 2. Two hops. The middle FORM does nothing but pass it on, which is what a
*    "helper" layer looks like in practice.
  PERFORM outer USING p_tab.

* 3. Through an object. The value is handed to a method as a named parameter.
  DATA(lo_worker) = NEW zcl_interproc_worker( ).
  lo_worker->run( iv_where = p_carr ).

FORM run_query USING iv_carrid TYPE string.
* SINK: the WHERE clause is the caller's selection-screen field.
  SELECT * FROM sflight INTO TABLE @DATA(lt_a) WHERE (iv_carrid).
ENDFORM.

FORM outer USING iv_pass TYPE string.
  PERFORM inner USING iv_pass.
ENDFORM.

FORM inner USING iv_name TYPE string.
* SINK: a dynamic table name, two calls away from the selection screen.
  SELECT * FROM (iv_name) INTO TABLE @DATA(lt_b).
ENDFORM.

* A FORM whose parameter NOBODY feeds from a tainted value. It must not be
* confirmed just because it shares a shape with the ones above — an analyser
* that taints every formal parameter is not an analyser.
FORM housekeeping USING iv_fixed TYPE string.
  SELECT * FROM (iv_fixed) INTO TABLE @DATA(lt_c).
ENDFORM.

START-OF-SELECTION.
  PERFORM housekeeping USING 'SFLIGHT'.

* A FORM nothing in this file calls. "No caller visible" is not evidence of
* safety even for a FORM — it means we did not find one, and an external PERFORM
* would live in the calling program rather than here.
FORM orphan USING iv_orphan TYPE string.
  SELECT * FROM (iv_orphan) INTO TABLE @DATA(lt_f).
ENDFORM.

CLASS zcl_interproc_worker DEFINITION.
  PUBLIC SECTION.
    METHODS run IMPORTING iv_where TYPE string.
    METHODS safe_run IMPORTING iv_where TYPE string.
* Every call to this one INSIDE THIS FILE passes a literal. That still proves
* nothing: it is a public method, and whatever imports the class can call it with
* anything at all.
    METHODS literal_fed IMPORTING iv_lit TYPE string.
ENDCLASS.

CLASS zcl_interproc_worker IMPLEMENTATION.
  METHOD run.
* SINK: reached through a method parameter.
    SELECT * FROM sflight INTO TABLE @DATA(lt_d) WHERE (iv_where).
  ENDMETHOD.

  METHOD safe_run.
* Same shape, and nothing in this file calls it at all.
    SELECT * FROM sflight INTO TABLE @DATA(lt_e) WHERE (iv_where).
  ENDMETHOD.

  METHOD literal_fed.
    SELECT * FROM sflight INTO TABLE @DATA(lt_g) WHERE (iv_lit).
  ENDMETHOD.
ENDCLASS.

START-OF-SELECTION.
  lo_worker->literal_fed( iv_lit = 'CARRID = ''LH''' ).
