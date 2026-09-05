*&---------------------------------------------------------------------*
*& The caller half. Every call below crosses a file boundary, which is what a
*& per-artefact graph cannot see and what makes a trace on the callee's sink
*& stop at its own METHOD header with nothing to point at.
*&---------------------------------------------------------------------*
CLASS zcl_tree_caller DEFINITION PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    METHODS drive IMPORTING iv_user_input TYPE string.
ENDCLASS.

CLASS zcl_tree_caller IMPLEMENTATION.

  METHOD drive.
* The receiver's class is declared here, so the call resolves to
* zcl_tree_worker~by_public_tainted and not to every method named
* `by_public_tainted` in the estate.
    DATA lo_worker TYPE REF TO zcl_tree_worker.
    CREATE OBJECT lo_worker.

    lo_worker->by_public_tainted( iv_where = iv_user_input ).
    lo_worker->by_public_literal( iv_where = 'CARRID EQ X' ).

* Resolved through NEW rather than a declaration.
    DATA(lo_second) = NEW zcl_tree_worker( ).
    lo_second->entry( iv_seed = iv_user_input ).
  ENDMETHOD.

ENDCLASS.
