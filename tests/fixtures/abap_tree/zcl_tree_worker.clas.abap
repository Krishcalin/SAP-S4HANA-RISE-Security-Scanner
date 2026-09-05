*&---------------------------------------------------------------------*
*& The callee half of a two-file tree. Nothing in THIS file calls
*& `by_public_tainted`, `by_public_literal` or `never_called` — a per-artefact
*& call graph therefore has no evidence about any of them, which is the ordinary
*& state of class-based ABAP and the reason a whole-tree graph exists.
*&---------------------------------------------------------------------*
CLASS zcl_tree_worker DEFINITION PUBLIC FINAL CREATE PUBLIC.

  PUBLIC SECTION.
* Called from the other file with a value off the selection screen.
    METHODS by_public_tainted IMPORTING iv_where TYPE string.
* Called from the other file, and only ever with a literal. Still not clearable:
* PUBLIC means anything that imports this class can call it, including code that
* was never in the export.
    METHODS by_public_literal IMPORTING iv_where TYPE string.
* Nothing in the whole tree calls it.
    METHODS never_called IMPORTING iv_where TYPE string.
    METHODS entry IMPORTING iv_seed TYPE string.

  PRIVATE SECTION.
* PRIVATE. ABAP guarantees every caller is inside this class, so the callers we
* can see are all the callers there are.
    METHODS priv_literal IMPORTING iv_tab TYPE string.
    METHODS priv_tainted IMPORTING iv_tab TYPE string.

ENDCLASS.

CLASS zcl_tree_worker IMPLEMENTATION.

  METHOD entry.
    me->priv_literal( iv_tab = 'SFLIGHT' ).
    me->priv_tainted( iv_tab = iv_seed ).
  ENDMETHOD.

  METHOD by_public_tainted.
    SELECT * FROM sflight INTO TABLE @DATA(lt_a) WHERE (iv_where).
  ENDMETHOD.

  METHOD by_public_literal.
    SELECT * FROM sflight INTO TABLE @DATA(lt_b) WHERE (iv_where).
  ENDMETHOD.

  METHOD never_called.
    SELECT * FROM sflight INTO TABLE @DATA(lt_c) WHERE (iv_where).
  ENDMETHOD.

  METHOD priv_literal.
    SELECT * FROM (iv_tab) INTO TABLE @DATA(lt_d).
  ENDMETHOD.

  METHOD priv_tainted.
    SELECT * FROM (iv_tab) INTO TABLE @DATA(lt_e).
  ENDMETHOD.

ENDCLASS.
