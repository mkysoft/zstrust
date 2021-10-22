CLASS zcl_strust DEFINITION
  public
  final
  create public .

  PUBLIC SECTION.

    TYPES:
      BEGIN OF st_cert,
        raw                    TYPE xstring,
        subject                TYPE string,
        issuer                 TYPE string,
        serialno               TYPE string,
        fingerprint            TYPE strustfingerprintsha1,
        subject_key_identifier TYPE strustsubjectkeyid,
        public_key_fingerprint TYPE strustpkfingerprint,
        valid_to               TYPE strustvalidto,
        email_address          TYPE strustemail,
        exits                  type abap_bool.
    TYPES: END OF st_cert .
    TYPES:
      tt_certs TYPE STANDARD TABLE OF st_cert WITH DEFAULT KEY .

    CONSTANTS c_mozilla TYPE string VALUE 'MOZILLA' ##NO_TEXT.

    METHODS update .
    METHODS constructor
      IMPORTING
        !i_source TYPE string DEFAULT c_mozilla .
    METHODS parse_pem_file
      IMPORTING
        VALUE(i_pem)   TYPE xstring
      RETURNING
        VALUE(r_certs) TYPE tt_certs .
PROTECTED SECTION.
  PRIVATE SECTION.

    DATA g_source TYPE string .
    DATA g_clpse TYPE REF TO cl_abap_pse .
    DATA g_cas   TYPE cl_abap_pse=>t_cert_struct.

    METHODS get_ca_from_mozilla
      RETURNING
        VALUE(r_certs) TYPE tt_certs .
    METHODS check
      IMPORTING
        !i_enddate  TYPE datum
        !i_serialno TYPE string
      RAISING
        cx_trex_http .
ENDCLASS.



CLASS ZCL_STRUST IMPLEMENTATION.


  METHOD check.
    IF i_enddate LT sy-datum.
      "error
    ENDIF.
    TRY.
        CALL METHOD g_clpse->get_trusted_certificates
          IMPORTING
            et_certificate_list_typed = g_cas.
        READ TABLE g_cas WITH KEY serial_no = i_serialno TRANSPORTING NO FIELDS.
        CHECK sy-subrc IS NOT INITIAL.
        cx_trex_http=>create( ).
      CATCH cx_abap_pse.
        "error
    ENDTRY.
  ENDMETHOD.


  METHOD constructor.
    g_source = i_source.
    TRY.
        CREATE OBJECT g_clpse
          EXPORTING
            iv_context     = 'SSLC'
            iv_application = 'DFAULT'. " DFAULT,ANONYM
      CATCH cx_abap_pse.
    ENDTRY.
  ENDMETHOD.


  METHOD get_ca_from_mozilla.
    CONSTANTS: c_url       TYPE string VALUE 'https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites',
               c_ca_end    TYPE datum VALUE '20311011',
               c_ca_serial TYPE string VALUE '06D8D904D5584346F68A2FA754227EC4'.
    DATA: lo_client TYPE REF TO if_http_client,
          lv_subrc  TYPE sysubrc,
          lv_certs  TYPE xstring,
          lv_code   TYPE i,
          lv_reason TYPE string.

    check( i_enddate = c_ca_end i_serialno = c_ca_serial ).

    cl_http_client=>create_by_url( EXPORTING url = c_url IMPORTING client = lo_client ).
    lo_client->request->set_method( if_http_request=>co_request_method_get  ).
    CALL METHOD lo_client->send
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3
        http_invalid_timeout       = 4
        OTHERS                     = 5.
    CHECK sy-subrc IS INITIAL.

    CALL METHOD lo_client->receive
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3.

*    CHECK sy-subrc IS INITIAL.

    CALL METHOD lo_client->response->get_status
      IMPORTING
        code   = lv_code
        reason = lv_reason.

    IF lv_code NE 200.
      lo_client->get_last_error( IMPORTING code = lv_subrc ).
      IF lv_subrc NE 200.
        "add error
      ENDIF.
    ENDIF.

    lv_certs = lo_client->response->get_data( ).
    r_certs = parse_pem_file( lv_certs ).

  ENDMETHOD.


  METHOD parse_pem_file.

    CONSTANTS: c_begincert TYPE xstring VALUE '2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D',
               c_endcert   TYPE xstring VALUE '2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D'.
    DATA: lv_subrc TYPE sysubrc,
          lv_cert  TYPE xstring,
          ls_cert  TYPE st_cert,
          lv_start TYPE i,
          lv_end   TYPE i,
          lv_pos   TYPE i,
          lv_len   TYPE i.

    SEARCH i_pem FOR c_begincert IN BYTE MODE.
    "check error
    lv_start = sy-fdpos.
    SEARCH i_pem FOR c_endcert IN BYTE MODE.
    lv_end = sy-fdpos.
    WHILE lv_start LT lv_end.
      lv_len = xstrlen( c_begincert ).
      ADD lv_len TO lv_start.
      lv_len = lv_end - lv_start.

      lv_cert = i_pem+lv_start(lv_len).
*      REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>cr_lf IN lv_cert WITH '' IN BYTE MODE.
      ls_cert-raw = lv_cert.
      APPEND ls_cert TO r_certs.

      lv_pos = lv_end + xstrlen( c_endcert ).
      SHIFT i_pem BY lv_pos  PLACES IN BYTE MODE.

      CLEAR: lv_start, lv_end.
      SEARCH i_pem FOR c_begincert IN BYTE MODE.
      CHECK sy-subrc IS INITIAL.
      lv_start = sy-fdpos.
      SEARCH i_pem FOR c_endcert IN BYTE MODE.
      CHECK sy-subrc IS INITIAL.
      lv_end = sy-fdpos.
    ENDWHILE.
  ENDMETHOD.


  METHOD update.
    DATA: lt_certs TYPE tt_certs,
          lv_cert  LIKE LINE OF lt_certs,
          lv_ok    TYPE abap_bool.

    " get root certificates
    lt_certs = get_ca_from_mozilla( ).
    LOOP AT lt_certs INTO lv_cert.

      TRY.
          CALL METHOD cl_abap_pse=>parse_certificate
            EXPORTING
              iv_certificite            = lv_cert-raw
            IMPORTING
              ev_subject                = lv_cert-subject
              ev_issuer                 = lv_cert-issuer
              ev_serialno               = lv_cert-serialno
              ev_fingerprint            = lv_cert-fingerprint
              ev_subject_key_identifier = lv_cert-subject_key_identifier
              ev_public_key_fingerprint = lv_cert-public_key_fingerprint
              ev_valid_to               = lv_cert-valid_to
              ev_email_address          = lv_cert-email_address.
        CATCH cx_abap_pse.
          "error
      ENDTRY.
      REPLACE ALL OCCURRENCES OF ':' IN lv_cert-serialno WITH ''.
      READ TABLE g_cas WITH KEY serial_no = lv_cert-serialno TRANSPORTING NO FIELDS.
      IF sy-subrc IS INITIAL.
        lv_cert-exits = abap_true.
      ENDIF.
      MODIFY lt_certs FROM lv_cert.
    ENDLOOP.

    " add root certificates
    LOOP AT lt_certs INTO lv_cert WHERE exits = abap_false.
      TRY.
          g_clpse->add_trusted_certificate( iv_certificate = lv_cert-raw ).
          lv_ok = abap_true.
        CATCH cx_abap_pse INTO DATA(lx_abap_pse).
          CHECK lx_abap_pse IS INITIAL.
          "error
      ENDTRY.
    ENDLOOP.

    CHECK lv_ok IS NOT INITIAL.
    TRY.
        g_clpse->save( ).
      CATCH cx_abap_pse INTO DATA(lx_save).
        CHECK lx_save IS INITIAL.
        "error
    ENDTRY.

  ENDMETHOD.
ENDCLASS.
