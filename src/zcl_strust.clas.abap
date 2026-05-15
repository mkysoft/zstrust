class zcl_strust definition
  public
  final
  create public .

  public section.

    types:
      begin of st_cert,
        raw                    type xstring,
        subject                type string,
        issuer                 type string,
        serialno               type string,
        fingerprint            type strustfingerprintsha1,
        subject_key_identifier type strustsubjectkeyid,
        public_key_fingerprint type strustpkfingerprint,
        valid_to               type strustvalidto,
        email_address          type strustemail,
        exits                  type abap_bool.
    types: end of st_cert .
    types:
      tt_certs type standard table of st_cert with default key .
    types:
      tt_list  type standard table of string with default key .

    constants c_mozilla type string value 'MOZILLA' ##NO_TEXT.

    methods update .
    methods constructor
      importing
        !i_source type string default c_mozilla
        !i_applic type ssfapplssl default 'DFAULT'.
    methods parse_pem_file
      importing
        value(i_pem)   type xstring
      returning
        value(r_certs) type tt_certs .
    class-methods get_sources
      returning
        value(r_sources) type tt_list .
  protected section.
  private section.

    data g_source type string .
    data g_clpse type ref to cl_abap_pse .
    data g_cas type tt_certs .
    data m_applic type ssfapplssl .

    methods get_mozilla_url_ca .
    methods get_mozilla_ca_list
      returning
        value(r_certs) type tt_certs .
    methods check
      importing
        !i_enddate  type datum
        !i_serialno type string
        !i_issuer   type string
      raising
        cx_trex_http .
endclass.



class zcl_strust implementation.


  method get_mozilla_url_ca.
    data: lv_cert_str type string,
          lv_cert     type xstring.

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
      exporting
        source   = lv_cert_str
        codepage = 'UTF-8'
      receiving
        result   = lv_cert
    ).
    try.
        g_clpse->add_trusted_certificate( iv_certificate = lv_cert ).
        g_clpse->save( ).
      catch cx_abap_pse.
        message 'Mozilla store certificate couldn''t saved' type 'E'.
    endtry.
  endmethod.


  method check.
    if i_enddate lt sy-datum.
      message 'Invalid certificate enddate' type 'E'.
    endif.
    read table g_cas with key serialno = i_serialno issuer = i_issuer transporting no fields.
    check sy-subrc is not initial.
    message 'Certifate couldn''t find' type 'E'.
  endmethod.


  method constructor.
    data: lt_certs type ssfbintab,
          lv_cert  type st_cert,
          lv_bin   type xstring.

    g_source = i_source.
    m_applic = i_applic.
    try.
        create object g_clpse
          exporting
            iv_context     = 'SSLC'
            iv_application = i_applic.

        call method g_clpse->get_trusted_certificates
          importing
            et_certificate_list = lt_certs.

        loop at lt_certs into lv_bin.
          clear lv_cert.
          lv_cert-raw = lv_bin.
          call method cl_abap_pse=>parse_certificate
            exporting
              iv_certificite            = lv_bin
            importing
              ev_subject                = lv_cert-subject
              ev_issuer                 = lv_cert-issuer
              ev_serialno               = lv_cert-serialno
              ev_fingerprint            = lv_cert-fingerprint
              ev_subject_key_identifier = lv_cert-subject_key_identifier
              ev_public_key_fingerprint = lv_cert-public_key_fingerprint
              ev_valid_to               = lv_cert-valid_to
              ev_email_address          = lv_cert-email_address.
          append lv_cert to g_cas.
        endloop.
      catch cx_abap_pse.
        message 'SSL Client Identity couldn''t open' type 'E'.
    endtry.
  endmethod.


  method get_mozilla_ca_list.
    constants: c_url       type string value 'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites',
               c_ca_end    type datum value '20380115',
               c_ca_issuer type string value 'CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US',
               c_ca_serial type string value '03:3A:F1:E6:A7:11:A9:A0:BB:28:64:B1:1D:09:FA:E5'.
    data: lo_client type ref to if_http_client,
          lv_subrc  type sysubrc,
          lv_certs  type xstring,
          lv_code   type i,
          lv_reason type string.


    read table g_cas with key serialno = c_ca_serial issuer = c_ca_issuer transporting no fields.
    if sy-subrc is not initial.
      me->get_mozilla_url_ca( ).
    endif.

    cl_http_client=>create_by_url(
      exporting
        url    = c_url
        ssl_id = m_applic
      importing client = lo_client
    ).
    lo_client->request->set_method( if_http_request=>co_request_method_get  ).
    call method lo_client->send
      exceptions
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3
        http_invalid_timeout       = 4
        others                     = 5.
    check sy-subrc is initial.

    call method lo_client->receive
      exceptions
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3.

    call method lo_client->response->get_status
      importing
        code   = lv_code
        reason = lv_reason.

    if lv_code ne 200.
      lo_client->get_last_error( importing code = lv_subrc ).
      if lv_subrc ne 200.
        message 'Couldn''t download certificates from web' type 'E'.
      endif.
    endif.

    lv_certs = lo_client->response->get_data( ).
    r_certs = parse_pem_file( lv_certs ).

  endmethod.


  method get_sources.
    append c_mozilla to r_sources.
  endmethod.


  method parse_pem_file.

    constants: c_begincert type xstring value '2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D',
               c_endcert   type xstring value '2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D'.
    data: lv_subrc type sysubrc,
          lv_cert  type xstring,
          ls_cert  type st_cert,
          lv_start type i,
          lv_end   type i,
          lv_pos   type i,
          lv_len   type i.

    search i_pem for c_begincert in byte mode.
    "check error
    lv_start = sy-fdpos.
    search i_pem for c_endcert in byte mode.
    lv_end = sy-fdpos.
    while lv_start lt lv_end.
      lv_len = xstrlen( c_begincert ).
      add lv_len to lv_start.
      lv_len = lv_end - lv_start.

      lv_cert = i_pem+lv_start(lv_len).
*      REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>cr_lf IN lv_cert WITH '' IN BYTE MODE.
      ls_cert-raw = lv_cert.
      append ls_cert to r_certs.

      lv_pos = lv_end + xstrlen( c_endcert ).
      shift i_pem by lv_pos  places in byte mode.

      clear: lv_start, lv_end.
      search i_pem for c_begincert in byte mode.
      check sy-subrc is initial.
      lv_start = sy-fdpos.
      search i_pem for c_endcert in byte mode.
      check sy-subrc is initial.
      lv_end = sy-fdpos.
    endwhile.
  endmethod.


  method update.
    constants: c_delimeter type string value ',  '.
    data: lt_certs type tt_certs,
          lv_cert  like line of lt_certs,
          lv_ok    type abap_bool.

    " get root certificates
    lt_certs = get_mozilla_ca_list( ).
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
endclass.
