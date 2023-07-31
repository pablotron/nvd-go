package cpe

import (
  "reflect"
  "testing"
)

func TestParseName(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp []string // expected CPE name components
  } {
    { "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*", []string { "o", "microsoft", "windows", "10", "*", "*", "*", "*", "*", "*", "*" } },

    // 100 random names from testdata/responses/cpes-2023.json.gz
    { "cpe:2.3:a:ibm:tivoli_management_framework:-:*:*:*:*:*:*:*", []string { "a", "ibm", "tivoli_management_framework", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:informix_dynamic_database_server:7.3:*:*:*:*:*:*:*", []string { "a", "ibm", "informix_dynamic_database_server", "7.3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.3\\(6e\\):*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.3\\(6e\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ons_15327:4.0\\(2\\):*:*:*:*:*:*:*", []string { "o", "cisco", "ons_15327", "4.0\\(2\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:messaging:1.11:*:*:*:*:*:*:*", []string { "a", "ca", "messaging", "1.11", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:3com:3cp4144:-:*:*:*:*:*:*:*", []string { "h", "3com", "3cp4144", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:catos:7.2\\(2\\):*:*:*:*:*:*:*", []string { "o", "cisco", "catos", "7.2\\(2\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:inkscape:inkscape:0.40:*:*:*:*:*:*:*", []string { "a", "inkscape", "inkscape", "0.40", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:cpio:2.6:*:*:*:*:*:*:*", []string { "a", "gnu", "cpio", "2.6", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:matt_johnston:dropbear_ssh_server:0.31:*:*:*:*:*:*:*", []string { "a", "matt_johnston", "dropbear_ssh_server", "0.31", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:nonstop_seeview_server_gateway:d44.02:*:*:*:*:*:*:*", []string { "a", "hp", "nonstop_seeview_server_gateway", "d44.02", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:hp:tru64:5.0a:*:*:*:*:*:*:*", []string { "o", "hp", "tru64", "5.0a", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:security_agent:3:*:*:*:*:*:*:*", []string { "a", "cisco", "security_agent", "3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.2\\(15.1\\)s:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.2\\(15.1\\)s", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:compaq:insight_manager_lc:1.50a:*:*:*:*:*:*:*", []string { "a", "compaq", "insight_manager_lc", "1.50a", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:adobe:coldfusion:7.0.1:*:*:*:*:*:*:*", []string { "a", "adobe", "coldfusion", "7.0.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:rarlab:winrar:-:*:*:*:*:*:*:*", []string { "a", "rarlab", "winrar", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:sun:sunpci_ii_driver_software:-:*:*:*:*:*:*:*", []string { "a", "sun", "sunpci_ii_driver_software", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:lunascape:lunascape:4.1.1:*:*:*:*:*:*:*", []string { "a", "lunascape", "lunascape", "4.1.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:mandrakesoft:mandrake_linux:7.3:*:*:*:*:*:*:*", []string { "o", "mandrakesoft", "mandrake_linux", "7.3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:http_server:2.0.47:*:*:*:*:*:*:*", []string { "a", "ibm", "http_server", "2.0.47", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:brightstor_enterprise_backup_agent:-:*:sql:*:*:*:*:*", []string { "a", "ca", "brightstor_enterprise_backup_agent", "-", "*", "sql", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:application_and_content_networking_software:4.2:*:*:*:*:*:*:*", []string { "a", "cisco", "application_and_content_networking_software", "4.2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:compaq:system_healthcheck:3.0:*:*:*:*:*:*:*", []string { "a", "compaq", "system_healthcheck", "3.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:hp:integrated_lights_out:1.27a:*:*:*:*:*:*:*", []string { "h", "hp", "integrated_lights_out", "1.27a", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:isc:bind:8.2.3:*:*:*:*:*:*:*", []string { "a", "isc", "bind", "8.2.3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:informix_web_datablade:3.5:*:*:*:*:*:*:*", []string { "a", "ibm", "informix_web_datablade", "3.5", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:symantec:powerquest_deploycenter:-:*:*:*:*:*:*:*", []string { "a", "symantec", "powerquest_deploycenter", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.2\\(15\\)mc1:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.2\\(15\\)mc1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:yahoo:messenger:-:*:*:*:*:*:*:*", []string { "a", "yahoo", "messenger", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:brightstor_san_manager:11.1:*:*:*:*:*:*:*", []string { "a", "ca", "brightstor_san_manager", "11.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:emacs:-:*:*:*:*:*:*:*", []string { "a", "gnu", "emacs", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:roxio:sonic_recordnow:-:*:*:*:*:*:*:*", []string { "a", "roxio", "sonic_recordnow", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:lotus_domino_server:5.0.9:*:*:*:*:*:*:*", []string { "a", "ibm", "lotus_domino_server", "5.0.9", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apache:tomcat:6.0.7:*:*:*:*:*:*:*", []string { "a", "apache", "tomcat", "6.0.7", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:unified_personal_communicator:-:*:*:*:*:*:*:*", []string { "a", "cisco", "unified_personal_communicator", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:samba-tng:samba-tng:-:*:*:*:*:*:*:*", []string { "a", "samba-tng", "samba-tng", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:unicenter_asset_management:3.2:sp2:*:*:*:*:*:*", []string { "a", "ca", "unicenter_asset_management", "3.2", "sp2", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:unified_communications_manager:5.1\\(1\\):*:*:*:*:*:*:*", []string { "a", "cisco", "unified_communications_manager", "5.1\\(1\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apache:axis:-:*:*:*:*:*:*:*", []string { "a", "apache", "axis", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:nec:ix1011:-:*:*:*:*:*:*:*", []string { "h", "nec", "ix1011", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.0\\(5\\)s:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.0\\(5\\)s", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:screen:3.9.9:*:*:*:*:*:*:*", []string { "a", "gnu", "screen", "3.9.9", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.4.17:*:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.4.17", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ati:control_panel:-:*:*:*:*:*:*:*", []string { "a", "ati", "control_panel", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.6.13:rc6:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.6.13", "rc6", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:cache_engine_550:2.2.0:*:*:*:*:*:*:*", []string { "h", "cisco", "cache_engine_550", "2.2.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:freebsd:freebsd:2.2.3:*:*:*:*:*:*:*", []string { "o", "freebsd", "freebsd", "2.2.3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.0\\(2\\)xg:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.0\\(2\\)xg", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:hp:digital_sender_9200c:-:*:*:*:*:*:*:*", []string { "h", "hp", "digital_sender_9200c", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:aix_enetwork_firewall:-:*:*:*:*:*:*:*", []string { "a", "ibm", "aix_enetwork_firewall", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:mailman:2.0.13:*:*:*:*:*:*:*", []string { "a", "gnu", "mailman", "2.0.13", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.1\\(10.5\\)ec:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.1\\(10.5\\)ec", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:emc:powerpath:3.0.5:*:*:*:*:*:*:*", []string { "a", "emc", "powerpath", "3.0.5", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:mandrakesoft:mandrake_linux:8.0:*:*:*:*:*:*:*", []string { "o", "mandrakesoft", "mandrake_linux", "8.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:adobe:acrobat_reader:5.0.11:*:*:*:*:*:*:*", []string { "a", "adobe", "acrobat_reader", "5.0.11", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:iss:realsecure_desktop:3.6ecg:*:*:*:*:*:*:*", []string { "a", "iss", "realsecure_desktop", "3.6ecg", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.2.10:*:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.2.10", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:iss:proventia_a_series_xpu:22.10:*:*:*:*:*:*:*", []string { "h", "iss", "proventia_a_series_xpu", "22.10", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.1\\(12\\):*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.1\\(12\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:catos:3.2\\(1b\\):*:*:*:*:*:*:*", []string { "o", "cisco", "catos", "3.2\\(1b\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:11.1\\(36\\)ca2:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "11.1\\(36\\)ca2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.0da:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.0da", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:idevspot:phphostbot:1.06:*:*:*:*:*:*:*", []string { "a", "idevspot", "phphostbot", "1.06", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.0\\(15\\)s7:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.0\\(15\\)s7", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:gnubiff:1.0.10:*:*:*:*:*:*:*", []string { "a", "gnu", "gnubiff", "1.0.10", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.5.17:*:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.5.17", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:secure_intrusion_detection_system:-:*:*:*:*:*:*:*", []string { "a", "cisco", "secure_intrusion_detection_system", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:imagemagick:imagemagick:6.3.2.0:*:*:*:*:*:*:*", []string { "a", "imagemagick", "imagemagick", "6.3.2.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:guard_ddos_mitigation_appliance:5.1\\(5\\):*:*:*:*:*:*:*", []string { "h", "cisco", "guard_ddos_mitigation_appliance", "5.1\\(5\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:microsoft:producer:-:*:*:*:*:*:*:*", []string { "a", "microsoft", "producer", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.1xh:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.1xh", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.3xd:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.3xd", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:websphere_application_server:6.0.0.1:*:*:*:*:*:*:*", []string { "a", "ibm", "websphere_application_server", "6.0.0.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:wget:1.5.3:*:*:*:*:*:*:*", []string { "a", "gnu", "wget", "1.5.3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:pix_firewall:4.4:*:*:*:*:*:*:*", []string { "o", "cisco", "pix_firewall", "4.4", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:catalyst_7600_ws-svc-nam-1:3.1\\(1a\\):*:*:*:*:*:*:*", []string { "h", "cisco", "catalyst_7600_ws-svc-nam-1", "3.1\\(1a\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cs-cart:cs-cart:1.3.0:*:*:*:*:*:*:*", []string { "a", "cs-cart", "cs-cart", "1.3.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:catalyst_2926gl:-:*:*:*:*:*:*:*", []string { "h", "cisco", "catalyst_2926gl", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:ibm:ds4100:-:*:*:*:*:*:*:*", []string { "h", "ibm", "ds4100", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:gdb:-:*:*:*:*:*:*:*", []string { "a", "gnu", "gdb", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:gnubiff:1.0.5:*:*:*:*:*:*:*", []string { "a", "gnu", "gnubiff", "1.0.5", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apple:claris_emailer:-:*:*:*:*:*:*:*", []string { "a", "apple", "claris_emailer", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:vpn_3005_concentrator:4.7.2:*:*:*:*:*:*:*", []string { "o", "cisco", "vpn_3005_concentrator", "4.7.2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:avaya:ip_agent:-:*:*:*:*:*:*:*", []string { "a", "avaya", "ip_agent", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:11.1\\(5\\):*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "11.1\\(5\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:db2_universal_database:8.1.5:*:*:*:*:*:*:*", []string { "a", "ibm", "db2_universal_database", "8.1.5", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:unicenter_serviceplus_service_desk:-:*:*:*:*:*:*:*", []string { "a", "ca", "unicenter_serviceplus_service_desk", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:sybase:replication_server:-:*:*:*:*:*:*:*", []string { "a", "sybase", "replication_server", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:isc:bind:8.2.2:p1:*:*:*:*:*:*", []string { "a", "isc", "bind", "8.2.2", "p1", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:juniper:junos_j:6.3:*:*:*:*:*:*:*", []string { "o", "juniper", "junos_j", "6.3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.2\\(13\\)ja1:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.2\\(13\\)ja1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:vpn_3000_concentrator:4.0:*:*:*:*:*:*:*", []string { "o", "cisco", "vpn_3000_concentrator", "4.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:brightstor_arcserve_backup:-:*:windows:*:*:*:*:*", []string { "a", "ca", "brightstor_arcserve_backup", "-", "*", "windows", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:etrust_ez_antivirus:-:*:*:*:*:*:*:*", []string { "a", "ca", "etrust_ez_antivirus", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:sun:storage_automated_diagnostic_environment:-:*:*:*:*:*:*:*", []string { "a", "sun", "storage_automated_diagnostic_environment", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:checkpoint:firewall-1:4.1_build_41439:*:*:*:*:*:*:*", []string { "a", "checkpoint", "firewall-1", "4.1_build_41439", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:catos:2.4\\(1\\):*:*:*:*:*:*:*", []string { "o", "cisco", "catos", "2.4\\(1\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apache:tomcat:4.1.36:*:*:*:*:*:*:*", []string { "a", "apache", "tomcat", "4.1.36", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.3\\(11\\)yw:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.3\\(11\\)yw", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:webns:5.0_2.005s:*:*:*:*:*:*:*", []string { "a", "cisco", "webns", "5.0_2.005s", "*", "*", "*", "*", "*", "*", "*" } },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      // parse name
      name, err := ParseName(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // cast to slice and compare against expected value
      got := []string(*name)
      if !reflect.DeepEqual(got, test.exp) {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }
    })
  }
}

func TestNameString(t *testing.T) {
  passTests := []string {
    "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",

    // 100 random names from testdata/responses/cpes-2023.json.gz
    "cpe:2.3:a:ibm:tivoli_management_framework:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:informix_dynamic_database_server:7.3:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.3\\(6e\\):*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ons_15327:4.0\\(2\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:messaging:1.11:*:*:*:*:*:*:*",
    "cpe:2.3:h:3com:3cp4144:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:catos:7.2\\(2\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:inkscape:inkscape:0.40:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:cpio:2.6:*:*:*:*:*:*:*",
    "cpe:2.3:a:matt_johnston:dropbear_ssh_server:0.31:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:nonstop_seeview_server_gateway:d44.02:*:*:*:*:*:*:*",
    "cpe:2.3:o:hp:tru64:5.0a:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:security_agent:3:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.2\\(15.1\\)s:*:*:*:*:*:*:*",
    "cpe:2.3:a:compaq:insight_manager_lc:1.50a:*:*:*:*:*:*:*",
    "cpe:2.3:a:adobe:coldfusion:7.0.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:rarlab:winrar:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:sun:sunpci_ii_driver_software:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:lunascape:lunascape:4.1.1:*:*:*:*:*:*:*",
    "cpe:2.3:o:mandrakesoft:mandrake_linux:7.3:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:http_server:2.0.47:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:brightstor_enterprise_backup_agent:-:*:sql:*:*:*:*:*",
    "cpe:2.3:a:cisco:application_and_content_networking_software:4.2:*:*:*:*:*:*:*",
    "cpe:2.3:a:compaq:system_healthcheck:3.0:*:*:*:*:*:*:*",
    "cpe:2.3:h:hp:integrated_lights_out:1.27a:*:*:*:*:*:*:*",
    "cpe:2.3:a:isc:bind:8.2.3:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:informix_web_datablade:3.5:*:*:*:*:*:*:*",
    "cpe:2.3:a:symantec:powerquest_deploycenter:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.2\\(15\\)mc1:*:*:*:*:*:*:*",
    "cpe:2.3:a:yahoo:messenger:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:brightstor_san_manager:11.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:emacs:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:roxio:sonic_recordnow:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:lotus_domino_server:5.0.9:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:tomcat:6.0.7:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:unified_personal_communicator:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:samba-tng:samba-tng:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:unicenter_asset_management:3.2:sp2:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:unified_communications_manager:5.1\\(1\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:axis:-:*:*:*:*:*:*:*",
    "cpe:2.3:h:nec:ix1011:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.0\\(5\\)s:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:screen:3.9.9:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.4.17:*:*:*:*:*:*:*",
    "cpe:2.3:a:ati:control_panel:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.6.13:rc6:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:cache_engine_550:2.2.0:*:*:*:*:*:*:*",
    "cpe:2.3:o:freebsd:freebsd:2.2.3:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.0\\(2\\)xg:*:*:*:*:*:*:*",
    "cpe:2.3:h:hp:digital_sender_9200c:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:aix_enetwork_firewall:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:mailman:2.0.13:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.1\\(10.5\\)ec:*:*:*:*:*:*:*",
    "cpe:2.3:a:emc:powerpath:3.0.5:*:*:*:*:*:*:*",
    "cpe:2.3:o:mandrakesoft:mandrake_linux:8.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:adobe:acrobat_reader:5.0.11:*:*:*:*:*:*:*",
    "cpe:2.3:a:iss:realsecure_desktop:3.6ecg:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.2.10:*:*:*:*:*:*:*",
    "cpe:2.3:h:iss:proventia_a_series_xpu:22.10:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.1\\(12\\):*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:catos:3.2\\(1b\\):*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:11.1\\(36\\)ca2:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.0da:*:*:*:*:*:*:*",
    "cpe:2.3:a:idevspot:phphostbot:1.06:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.0\\(15\\)s7:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:gnubiff:1.0.10:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.5.17:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:secure_intrusion_detection_system:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:imagemagick:imagemagick:6.3.2.0:*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:guard_ddos_mitigation_appliance:5.1\\(5\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:microsoft:producer:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.1xh:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.3xd:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:websphere_application_server:6.0.0.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:wget:1.5.3:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:pix_firewall:4.4:*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:catalyst_7600_ws-svc-nam-1:3.1\\(1a\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:cs-cart:cs-cart:1.3.0:*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:catalyst_2926gl:-:*:*:*:*:*:*:*",
    "cpe:2.3:h:ibm:ds4100:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:gdb:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:gnubiff:1.0.5:*:*:*:*:*:*:*",
    "cpe:2.3:a:apple:claris_emailer:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:vpn_3005_concentrator:4.7.2:*:*:*:*:*:*:*",
    "cpe:2.3:a:avaya:ip_agent:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:11.1\\(5\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:db2_universal_database:8.1.5:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:unicenter_serviceplus_service_desk:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:sybase:replication_server:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:isc:bind:8.2.2:p1:*:*:*:*:*:*",
    "cpe:2.3:o:juniper:junos_j:6.3:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.2\\(13\\)ja1:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:vpn_3000_concentrator:4.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:brightstor_arcserve_backup:-:*:windows:*:*:*:*:*",
    "cpe:2.3:a:ca:etrust_ez_antivirus:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:sun:storage_automated_diagnostic_environment:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:checkpoint:firewall-1:4.1_build_41439:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:catos:2.4\\(1\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:tomcat:4.1.36:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.3\\(11\\)yw:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:webns:5.0_2.005s:*:*:*:*:*:*:*",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      // parse name
      name, err := ParseName(test)
      if err != nil {
        t.Fatal(err)
      }

      // compare string
      got := name.String()
      exp := test
      if got != exp {
        t.Fatalf("got %s, exp %s", got, exp)
      }
    })
  }
}
