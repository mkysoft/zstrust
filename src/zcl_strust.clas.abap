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
      !I_SOURCE type STRING default C_MOZILLA
      !I_APPLIC type SSFAPPLSSL default 'DFAULT'.
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
  data M_APPLIC type SSFAPPLSSL .

  methods ADD_MOZILLA_URL_CERT .
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


  method ADD_MOZILLA_URL_CERT.
    data: lv_cert_str TYPE string,
          lv_cert TYPE xstring.

  lv_cert_str = '-----BEGIN CERTIFICATE-----' &&
                'MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh' &&
                'MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3' &&
                'd3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH' &&
                'MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT' &&
                'MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j' &&
                'b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG' &&
                '9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI' &&
                '2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx' &&
                '1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ' &&
                'q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz' &&
                'tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ' &&
                'vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP' &&
                'BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV' &&
                '5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY' &&
                '1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4' &&
                'NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG' &&
                'Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91' &&
                '8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe' &&
                'pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl' &&
                'MrY=' &&
                '-----END CERTIFICATE-----'.

  cl_abap_codepage=>convert_to(
    EXPORTING
      source   = lv_cert_str
      codepage = 'UTF-8'
    RECEIVING
      result   = lv_cert
  ).
  try.
      g_clpse->add_trusted_certificate( iv_certificate = lv_cert ).
      g_clpse->save( ).
  catch cx_abap_pse.
    MESSAGE 'Mozilla store certificate couldn''t saved' TYPE 'E'.
  ENDTRY.
  endmethod.


  METHOD check.
    IF i_enddate LT sy-datum.
      MESSAGE 'Invalid certificate enddate' TYPE 'E'.
    ENDIF.
    READ TABLE g_cas WITH KEY serialno = i_serialno issuer = i_issuer TRANSPORTING NO FIELDS.
    CHECK sy-subrc IS NOT INITIAL.
    MESSAGE 'Certifate couldn''t find' TYPE 'E'.
  ENDMETHOD.


  METHOD constructor.
    DATA: lt_certs TYPE ssfbintab,
          lv_cert  TYPE st_cert,
          lv_bin   TYPE xstring.

    g_source = i_source.
    M_APPLIC = I_APPLIC.
    TRY.
        CREATE OBJECT g_clpse
          EXPORTING
            iv_context     = 'SSLC'
            iv_application = I_APPLIC.

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
        MESSAGE 'SSL Client Identity couldn''t open' TYPE 'E'.
    ENDTRY.
  ENDMETHOD.


  METHOD get_ca_from_mozilla.
    CONSTANTS: c_url       TYPE string VALUE 'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites',
               c_ca_end    TYPE datum VALUE '20380115',
               c_ca_issuer TYPE string VALUE 'CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US',
               c_ca_serial TYPE string VALUE '03:3A:F1:E6:A7:11:A9:A0:BB:28:64:B1:1D:09:FA:E5'.
    DATA: lo_client TYPE REF TO if_http_client,
          lv_subrc  TYPE sysubrc,
          lv_certs  TYPE xstring,
          lv_code   TYPE i,
          lv_reason TYPE string.


    READ TABLE g_cas WITH KEY serialno = c_ca_serial issuer = c_ca_issuer TRANSPORTING NO FIELDS.
    if sy-subrc is not INITIAL.
      me->add_mozilla_url_cert( ).
    endif.

    cl_http_client=>create_by_url(
      EXPORTING
        url    = c_url
        ssl_id = M_APPLIC
      IMPORTING client = lo_client
    ).
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

    CALL METHOD lo_client->response->get_status
      IMPORTING
        code   = lv_code
        reason = lv_reason.

    IF lv_code NE 200.
      lo_client->get_last_error( IMPORTING code = lv_subrc ).
      IF lv_subrc NE 200.
        MESSAGE 'Couldn''t download certificates from web' type 'E'.
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


  method update.
    constants: c_delimeter type string value ',  '.
    data: lt_certs type tt_certs,
          lv_cert  like line of lt_certs,
          lv_ok    type abap_bool.

    " get root certificates
    lt_certs = get_ca_from_mozilla( ).
    loop at lt_certs into lv_cert.

      try.
          call method cl_abap_pse=>parse_certificate
            exporting
              iv_certificite            = lv_cert-raw
            importing
              ev_subject                = lv_cert-subject
              ev_issuer                 = lv_cert-issuer
              ev_serialno               = lv_cert-serialno
              ev_fingerprint            = lv_cert-fingerprint
              ev_subject_key_identifier = lv_cert-subject_key_identifier
              ev_public_key_fingerprint = lv_cert-public_key_fingerprint
              ev_valid_to               = lv_cert-valid_to
              ev_email_address          = lv_cert-email_address.
        catch cx_abap_pse.
          "error
      endtry.
      " check certificate exists in pse
      read table g_cas with key serialno = lv_cert-serialno issuer = lv_cert-issuer transporting no fields.
      if sy-subrc is initial.
        lv_cert-exits = abap_true.
      endif.
      modify lt_certs from lv_cert.
    endloop.

    " add root certificates
    loop at lt_certs into lv_cert where exits = abap_false.
      try.
          g_clpse->add_trusted_certificate( iv_certificate = lv_cert-raw ).
          lv_ok = abap_true.
        catch cx_abap_pse into data(lx_abap_pse).
          check lx_abap_pse is initial.
          message 'A certificate couldn''t added to store' type 'W'.
      endtry.
    endloop.

    check lv_ok is not initial.
    try.
        g_clpse->save( ).
      catch cx_abap_pse into data(lx_save).
        check lx_save is initial.
        message 'Certificate store couldn''t saved' type 'E'.
    endtry.

  endmethod.
ENDCLASS.
