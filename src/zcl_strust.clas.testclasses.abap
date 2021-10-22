CLASS ltcl_zcl_strust DEFINITION FINAL FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS.

  PRIVATE SECTION.
    METHODS:
      parse_pem_file FOR TESTING RAISING cx_static_check.
ENDCLASS.


class ltcl_ZCL_STRUST implementation.

  METHOD parse_pem_file.
    DATA: lv_pem  TYPE xstring,
          lv_spem TYPE string.

    CONCATENATE
                '-----BEGIN CERTIFICATE-----'  cl_abap_char_utilities=>cr_lf
                'MI' cl_abap_char_utilities=>cr_lf
                'A1' cl_abap_char_utilities=>cr_lf
                'kg==' cl_abap_char_utilities=>cr_lf
                '-----END CERTIFICATE-----' cl_abap_char_utilities=>cr_lf
                '-----BEGIN CERTIFICATE-----' cl_abap_char_utilities=>cr_lf
                'MI' cl_abap_char_utilities=>cr_lf
                'A1' cl_abap_char_utilities=>cr_lf
                'kg==' cl_abap_char_utilities=>cr_lf
                '-----END CERTIFICATE-----'
            INTO lv_spem.

    CALL FUNCTION 'SCMS_STRING_TO_XSTRING'
      EXPORTING
        text   = lv_spem
      IMPORTING
        buffer = lv_pem.

    DATA(lo_strust) = NEW zcl_strust(  ).
    DATA(lt_certs) = lo_strust->parse_pem_file( lv_pem ).
    cl_abap_unit_assert=>assert_equals( msg = '3 certificate expected!' exp = 2 act = lines( lt_certs ) ).
  ENDMETHOD.

endclass.
