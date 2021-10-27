*&---------------------------------------------------------------------*
*& Report ZSTRUST
*&---------------------------------------------------------------------*
*& Auto Root CA Updater
*&---------------------------------------------------------------------*
REPORT zstrust.

DATA: lo_strust TYPE REF TO zcl_strust,
      lt_sourcs TYPE vrm_values,
      lv_sourc  TYPE vrm_value,
      lv_source TYPE string.

PARAMETERS : p_sourc TYPE char20 AS LISTBOX VISIBLE LENGTH 20.

INITIALIZATION.

  DATA(lt_list) = zcl_strust=>get_sources(  ).
  LOOP AT lt_list INTO lv_sourc-key.
    lv_sourc-text = lv_sourc-key.
    APPEND lv_sourc TO lt_sourcs.
  ENDLOOP.
  CALL FUNCTION 'VRM_SET_VALUES'
    EXPORTING
      id              = 'P_SOURC'
      values          = lt_sourcs
    EXCEPTIONS
      id_illegal_name = 1
      OTHERS          = 2.

START-OF-SELECTION.

  lv_source = p_sourc.
  CREATE OBJECT lo_strust EXPORTING i_source = lv_source.

  lo_strust->update( ).
