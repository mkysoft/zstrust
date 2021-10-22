*&---------------------------------------------------------------------*
*& Report ZSTRUST
*&---------------------------------------------------------------------*
*&
*&---------------------------------------------------------------------*
REPORT zstrust.

DATA: lo_strust TYPE REF TO zcl_strust.

CREATE OBJECT lo_strust EXPORTING i_source = zcl_strust=>c_mozilla.

lo_strust->update( ).
