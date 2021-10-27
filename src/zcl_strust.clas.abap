class ZCL_STRUST definition
  public
  final
  create public .

public section.

  types:
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
        exits                  TYPE abap_bool.
    TYPES: END OF st_cert .
  types:
    tt_certs TYPE STANDARD TABLE OF st_cert WITH DEFAULT KEY .
  types:
    tt_list  TYPE STANDARD TABLE OF string WITH DEFAULT KEY .

  constants C_MOZILLA type STRING value 'MOZILLA' ##NO_TEXT.

  methods UPDATE .
  methods CONSTRUCTOR
    importing
      !I_SOURCE type STRING default C_MOZILLA .
  methods PARSE_PEM_FILE
    importing
      value(I_PEM) type XSTRING
    returning
      value(R_CERTS) type TT_CERTS .
  class-methods GET_SOURCES
    returning
      value(R_SOURCES) type TT_LIST .
PROTECTED SECTION.
private section.

  data G_SOURCE type STRING .
  data G_CLPSE type ref to CL_ABAP_PSE .
  data G_CAS type TT_CERTS .

  methods GET_CA_FROM_MOZILLA
    returning
      value(R_CERTS) type TT_CERTS .
  methods CHECK
    importing
      !I_ENDDATE type DATUM
      !I_SERIALNO type STRING
      !I_ISSUER type STRING
    raising
      CX_TREX_HTTP .
ENDCLASS.



CLASS ZCL_STRUST IMPLEMENTATION.


  METHOD check.
    IF i_enddate LT sy-datum.
      "error
    ENDIF.
    TRY.
        READ TABLE g_cas WITH KEY serialno = i_serialno issuer = i_issuer TRANSPORTING NO FIELDS.
        CHECK sy-subrc IS NOT INITIAL.
        RAISE EXCEPTION cx_trex_http=>create( ).
      CATCH cx_abap_pse.
        "error
    ENDTRY.
  ENDMETHOD.


  METHOD constructor.
    DATA: lt_certs TYPE ssfbintab,
          lv_cert  TYPE st_cert,
          lv_bin   TYPE xstring.

    g_source = i_source.
    TRY.
        CREATE OBJECT g_clpse
          EXPORTING
            iv_context     = 'SSLC'
            iv_application = 'DFAULT'. " DFAULT,ANONYM

        CALL METHOD g_clpse->get_trusted_certificates
          IMPORTING
            et_certificate_list = lt_certs.

        LOOP AT lt_certs INTO lv_bin.
          CLEAR lv_cert.
          lv_cert-raw = lv_bin.
          CALL METHOD cl_abap_pse=>parse_certificate
            EXPORTING
              iv_certificite            = lv_bin
            IMPORTING
              ev_subject                = lv_cert-subject
              ev_issuer                 = lv_cert-issuer
              ev_serialno               = lv_cert-serialno
              ev_fingerprint            = lv_cert-fingerprint
              ev_subject_key_identifier = lv_cert-subject_key_identifier
              ev_public_key_fingerprint = lv_cert-public_key_fingerprint
              ev_valid_to               = lv_cert-valid_to
              ev_email_address          = lv_cert-email_address.
          APPEND lv_cert TO g_cas.
        ENDLOOP.
      CATCH cx_abap_pse.
    ENDTRY.
  ENDMETHOD.


  METHOD get_ca_from_mozilla.
    CONSTANTS: c_url       TYPE string VALUE 'https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites',
               c_ca_end    TYPE datum VALUE '20311011',
               c_ca_issuer TYPE string VALUE 'CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US',
               c_ca_serial TYPE string VALUE '08:3B:E0:56:90:42:46:B1:A1:75:6A:C9:59:91:C7:4A'.
    DATA: lo_client TYPE REF TO if_http_client,
          lv_subrc  TYPE sysubrc,
          lv_certs  TYPE xstring,
          lv_code   TYPE i,
          lv_reason TYPE string.

    check( i_enddate = c_ca_end i_serialno = c_ca_serial i_issuer = c_ca_issuer ).

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


  METHOD get_sources.
    APPEND c_mozilla TO r_sources.
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
    CONSTANTS: c_delimeter TYPE string VALUE ',  '.
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
      " check certificate exists in pse
      READ TABLE g_cas WITH KEY serialno = lv_cert-serialno issuer = lv_cert-issuer TRANSPORTING NO FIELDS.
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
