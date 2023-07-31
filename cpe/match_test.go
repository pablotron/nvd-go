package cpe

import (
  "reflect"
  "testing"
)

func TestParseMatch(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp []string // expected components
  } {
    { "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*", []string { "o", "microsoft", "windows", "10", "*", "*", "*", "*", "*", "*", "*" } },

    // 100 random names from testdata/responses/cpes-2023.json.gz
    { "cpe:2.3:o:cisco:ios:11.1\\(13\\)ca:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "11.1\\(13\\)ca", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ons_15327:4.0\\(2\\):*:*:*:*:*:*:*", []string { "o", "cisco", "ons_15327", "4.0\\(2\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:adobe:coldfusion:7.0:*:*:*:*:*:*:*", []string { "a", "adobe", "coldfusion", "7.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.1db:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.1db", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:iss:realsecure_network:7.0:*:*:*:*:*:*:*", []string { "a", "iss", "realsecure_network", "7.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:building_broadband_service_manager:-:*:*:*:*:*:*:*", []string { "h", "cisco", "building_broadband_service_manager", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:libc:-:*:*:*:*:*:*:*", []string { "a", "gnu", "libc", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:unicenter_asset_management:3.2:sp2:*:*:*:*:*:*", []string { "a", "ca", "unicenter_asset_management", "3.2", "sp2", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:axis:2400_video_server:2.31:*:*:*:*:*:*:*", []string { "h", "axis", "2400_video_server", "2.31", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:lotus_domino_inotes_client:-:*:*:*:*:*:*:*", []string { "a", "ibm", "lotus_domino_inotes_client", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:ibm:aix:4.1.1:*:*:*:*:*:*:*", []string { "o", "ibm", "aix", "4.1.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:sun:javamail:-:*:*:*:*:*:*:*", []string { "a", "sun", "javamail", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:iss:realsecure_desktop:3.6:*:*:*:*:*:*:*", []string { "a", "iss", "realsecure_desktop", "3.6", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:juniper:netscreen_screenos:4.0.0:*:*:*:*:*:*:*", []string { "o", "juniper", "netscreen_screenos", "4.0.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:juniper:netscreen_remote_security_client:8.0:*:*:*:*:*:*:*", []string { "a", "juniper", "netscreen_remote_security_client", "8.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:openview_network_node_manager:5.01:*:*:*:*:*:*:*", []string { "a", "hp", "openview_network_node_manager", "5.01", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:secure_web_server_for_tru64:6.3.0:*:*:*:*:*:*:*", []string { "a", "hp", "secure_web_server_for_tru64", "6.3.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.1\\(13\\)ew4:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.1\\(13\\)ew4", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.0\\(1\\)w:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.0\\(1\\)w", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.2cy:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.2cy", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.6.15.11:*:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.6.15.11", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gentoo:glibc:2.5:r3:*:*:*:*:*:*", []string { "a", "gentoo", "glibc", "2.5", "r3", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.1\\(13\\)ea1:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.1\\(13\\)ea1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apple:claris_emailer:2.0v2:*:*:*:*:*:*:*", []string { "a", "apple", "claris_emailer", "2.0v2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.2\\(17d\\)sxb7:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.2\\(17d\\)sxb7", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:bea:weblogic_workshop:8.1:sp3:*:*:*:*:*:*", []string { "a", "bea", "weblogic_workshop", "8.1", "sp3", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:gnutls:1.0.21:*:*:*:*:*:*:*", []string { "a", "gnu", "gnutls", "1.0.21", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:avocent:kvm:-:*:*:*:*:*:*:*", []string { "h", "avocent", "kvm", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:digium:asterisk:1.2.22:*:*:*:*:*:*:*", []string { "a", "digium", "asterisk", "1.2.22", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.2zm:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.2zm", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:rsa:ace_server:-:*:*:*:*:*:*:*", []string { "a", "rsa", "ace_server", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:mailman:2.1b1:*:*:*:*:*:*:*", []string { "a", "gnu", "mailman", "2.1b1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:bmc:software_control-m_agent:6.1.03:*:*:*:*:*:*:*", []string { "a", "bmc", "software_control-m_agent", "6.1.03", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.6.13.2:*:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.6.13.2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.2\\(8\\)tpc10a:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.2\\(8\\)tpc10a", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:unicenter_management_portal:3.1:*:*:*:*:*:*:*", []string { "a", "ca", "unicenter_management_portal", "3.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:enterasys:netsight_inventory_manager:-:*:*:*:*:*:*:*", []string { "a", "enterasys", "netsight_inventory_manager", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:unified_communications_manager:5.1\\(2\\):*:*:*:*:*:*:*", []string { "a", "cisco", "unified_communications_manager", "5.1\\(2\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:adobe:pagemaker:6.5:*:*:*:*:*:*:*", []string { "a", "adobe", "pagemaker", "6.5", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:bea:weblogic_server:8.1:sp3:express:*:*:*:*:*", []string { "a", "bea", "weblogic_server", "8.1", "sp3", "express", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.2\\(25\\)ey2:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.2\\(25\\)ey2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:cluster_object_manager:a.01.03:*:*:*:*:*:*:*", []string { "a", "hp", "cluster_object_manager", "a.01.03", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:gnump3d:2.9.7:*:*:*:*:*:*:*", []string { "a", "gnu", "gnump3d", "2.9.7", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:cluster_object_manager:b.01.04:*:*:*:*:*:*:*", []string { "a", "hp", "cluster_object_manager", "b.01.04", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:itechnology_igateway:4.0.050126:*:*:*:*:*:*:*", []string { "a", "ca", "itechnology_igateway", "4.0.050126", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.5.25:*:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.5.25", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:macromedia:flash_player:4.0_r12:*:*:*:*:*:*:*", []string { "a", "macromedia", "flash_player", "4.0_r12", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:mgx_8230:1.2.11:*:*:*:*:*:*:*", []string { "o", "cisco", "mgx_8230", "1.2.11", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:cns_network_registrar:6.1.1.3:*:*:*:*:*:*:*", []string { "a", "cisco", "cns_network_registrar", "6.1.1.3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:parallel_environment:4.1:*:*:*:*:*:*:*", []string { "a", "ibm", "parallel_environment", "4.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:3com:3c13754:-:*:*:*:*:*:*:*", []string { "h", "3com", "3c13754", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:wireless_lan_solution_engine:2.10:*:*:*:*:*:*:*", []string { "a", "cisco", "wireless_lan_solution_engine", "2.10", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:imagemagick:imagemagick:6.0.6.1:*:*:*:*:*:*:*", []string { "a", "imagemagick", "imagemagick", "6.0.6.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ca:desktop_management_suite:11.0:*:*:*:*:*:*:*", []string { "a", "ca", "desktop_management_suite", "11.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:zebra:0.93b:*:*:*:*:*:*:*", []string { "a", "gnu", "zebra", "0.93b", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:rational_clearquest:6.15:*:*:*:*:*:*:*", []string { "a", "ibm", "rational_clearquest", "6.15", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:serviceguard:a.11.15.00:*:*:*:*:*:*:*", []string { "a", "hp", "serviceguard", "a.11.15.00", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:juniper:junos:6.2:*:*:*:*:*:*:*", []string { "o", "juniper", "junos", "6.2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.0\\(20\\)sp:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.0\\(20\\)sp", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:juniper:netscreen_screenos:3.0.3:*:*:*:*:*:*:*", []string { "o", "juniper", "netscreen_screenos", "3.0.3", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:nonstop_seeview_server_gateway:g06.18:*:*:*:*:*:*:*", []string { "a", "hp", "nonstop_seeview_server_gateway", "g06.18", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:google:toolbar:1.1.53:*:*:*:*:*:*:*", []string { "a", "google", "toolbar", "1.1.53", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.4.34.1:*:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.4.34.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:openview_emanate_snmp_agent:14.2:*:*:*:*:*:*:*", []string { "a", "hp", "openview_emanate_snmp_agent", "14.2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:e107:e107:0.7.6:*:*:*:*:*:*:*", []string { "a", "e107", "e107", "0.7.6", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:lotus_domino_server:5.0.9:*:*:*:*:*:*:*", []string { "a", "ibm", "lotus_domino_server", "5.0.9", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:catalyst_12xx_supervisor_software:4.29:*:*:*:*:*:*:*", []string { "a", "cisco", "catalyst_12xx_supervisor_software", "4.29", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:f5:big-ip:4.0:*:*:*:*:*:*:*", []string { "a", "f5", "big-ip", "4.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apache:spamassassin:3.0.1:*:*:*:*:*:*:*", []string { "a", "apache", "spamassassin", "3.0.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.3\\(11\\)xl:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.3\\(11\\)xl", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:lotus_notes:5.0.5:*:*:*:*:*:*:*", []string { "a", "ibm", "lotus_notes", "5.0.5", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:c5000rsm:-:*:*:*:*:*:*:*", []string { "h", "cisco", "c5000rsm", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:gnu:gnutls:1.2.0:*:*:*:*:*:*:*", []string { "a", "gnu", "gnutls", "1.2.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:ibm:lotus_domino_server:6.5.1:*:*:*:*:*:*:*", []string { "a", "ibm", "lotus_domino_server", "6.5.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:linux:linux_kernel:2.4.0:test1:*:*:*:*:*:*", []string { "o", "linux", "linux_kernel", "2.4.0", "test1", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.0\\(23\\)sz:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.0\\(23\\)sz", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:bea:jrockit:-:*:*:*:*:*:*:*", []string { "a", "bea", "jrockit", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:clean_access:-:*:*:*:*:*:*:*", []string { "h", "cisco", "clean_access", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:novell:ichain:-:*:*:*:*:*:*:*", []string { "a", "novell", "ichain", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.4\\(3a\\):*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.4\\(3a\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:compaq:tru64:5.0f:*:*:*:*:*:*:*", []string { "o", "compaq", "tru64", "5.0f", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:catalyst_2900:lre_xl:*:*:*:*:*:*:*", []string { "h", "cisco", "catalyst_2900", "lre_xl", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:f5:firepass_4300:-:*:*:*:*:*:*:*", []string { "h", "f5", "firepass_4300", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:rssreader:rssreader:-:*:*:*:*:*:*:*", []string { "a", "rssreader", "rssreader", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:nonstop_seeview_server_gateway:d48.01:*:*:*:*:*:*:*", []string { "a", "hp", "nonstop_seeview_server_gateway", "d48.01", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:axis:panorama_ptz_camera:2.39:*:*:*:*:*:*:*", []string { "h", "axis", "panorama_ptz_camera", "2.39", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:e107:e107:0.7:*:*:*:*:*:*:*", []string { "a", "e107", "e107", "0.7", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apache:cocoon:2.1.2:*:*:*:*:*:*:*", []string { "a", "apache", "cocoon", "2.1.2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.0\\(21\\)s5a:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.0\\(21\\)s5a", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.3\\(11\\)yk:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.3\\(11\\)yk", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:isc:bind:8.1.2:*:*:*:*:*:*:*", []string { "a", "isc", "bind", "8.1.2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:catos:6.3\\(6\\):*:*:*:*:*:*:*", []string { "o", "cisco", "catos", "6.3\\(6\\)", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:unified_ip_conference_station_7935:-:*:*:*:*:*:*:*", []string { "h", "cisco", "unified_ip_conference_station_7935", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apple:safari:1.0:beta:*:*:*:*:*:*", []string { "a", "apple", "safari", "1.0", "beta", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:cisco:cache_engine_570:2.4.0:*:*:*:*:*:*:*", []string { "h", "cisco", "cache_engine_570", "2.4.0", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:cisco:ids_device_manager:3.1.1:*:*:*:*:*:*:*", []string { "a", "cisco", "ids_device_manager", "3.1.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:apple:darwin_streaming_server:4.1.2:*:*:*:*:*:*:*", []string { "a", "apple", "darwin_streaming_server", "4.1.2", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:a:hp:mercury_loadrunner_agent:8.1:*:*:*:*:*:*:*", []string { "a", "hp", "mercury_loadrunner_agent", "8.1", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:hp:laserjet_4000n:-:*:*:*:*:*:*:*", []string { "h", "hp", "laserjet_4000n", "-", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:o:cisco:ios:12.1\\(8b\\)e18:*:*:*:*:*:*:*", []string { "o", "cisco", "ios", "12.1\\(8b\\)e18", "*", "*", "*", "*", "*", "*", "*" } },
    { "cpe:2.3:h:3com:tippingpoint_ips_1200e:-:*:*:*:*:*:*:*", []string { "h", "3com", "tippingpoint_ips_1200e", "-", "*", "*", "*", "*", "*", "*", "*" } },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      // parse match string
      ms, err := ParseMatch(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // cast to slice and compare against expected value
      got := []string(*ms)
      if !reflect.DeepEqual(got, test.exp) {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }
    })
  }
}

func TestMatchString(t *testing.T) {
  passTests := []string {
    "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",

    // 100 random names from testdata/responses/cpes-2023.json.gz
    "cpe:2.3:o:cisco:ios:11.1\\(13\\)ca:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ons_15327:4.0\\(2\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:adobe:coldfusion:7.0:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.1db:*:*:*:*:*:*:*",
    "cpe:2.3:a:iss:realsecure_network:7.0:*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:building_broadband_service_manager:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:libc:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:unicenter_asset_management:3.2:sp2:*:*:*:*:*:*",
    "cpe:2.3:h:axis:2400_video_server:2.31:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:lotus_domino_inotes_client:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:ibm:aix:4.1.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:sun:javamail:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:iss:realsecure_desktop:3.6:*:*:*:*:*:*:*",
    "cpe:2.3:o:juniper:netscreen_screenos:4.0.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:juniper:netscreen_remote_security_client:8.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:openview_network_node_manager:5.01:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:secure_web_server_for_tru64:6.3.0:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.1\\(13\\)ew4:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.0\\(1\\)w:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.2cy:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.6.15.11:*:*:*:*:*:*:*",
    "cpe:2.3:a:gentoo:glibc:2.5:r3:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.1\\(13\\)ea1:*:*:*:*:*:*:*",
    "cpe:2.3:a:apple:claris_emailer:2.0v2:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.2\\(17d\\)sxb7:*:*:*:*:*:*:*",
    "cpe:2.3:a:bea:weblogic_workshop:8.1:sp3:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:gnutls:1.0.21:*:*:*:*:*:*:*",
    "cpe:2.3:h:avocent:kvm:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:digium:asterisk:1.2.22:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.2zm:*:*:*:*:*:*:*",
    "cpe:2.3:a:rsa:ace_server:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:mailman:2.1b1:*:*:*:*:*:*:*",
    "cpe:2.3:a:bmc:software_control-m_agent:6.1.03:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.6.13.2:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.2\\(8\\)tpc10a:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:unicenter_management_portal:3.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:enterasys:netsight_inventory_manager:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:unified_communications_manager:5.1\\(2\\):*:*:*:*:*:*:*",
    "cpe:2.3:a:adobe:pagemaker:6.5:*:*:*:*:*:*:*",
    "cpe:2.3:a:bea:weblogic_server:8.1:sp3:express:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.2\\(25\\)ey2:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:cluster_object_manager:a.01.03:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:gnump3d:2.9.7:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:cluster_object_manager:b.01.04:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:itechnology_igateway:4.0.050126:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.5.25:*:*:*:*:*:*:*",
    "cpe:2.3:a:macromedia:flash_player:4.0_r12:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:mgx_8230:1.2.11:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:cns_network_registrar:6.1.1.3:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:parallel_environment:4.1:*:*:*:*:*:*:*",
    "cpe:2.3:h:3com:3c13754:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:wireless_lan_solution_engine:2.10:*:*:*:*:*:*:*",
    "cpe:2.3:a:imagemagick:imagemagick:6.0.6.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:ca:desktop_management_suite:11.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:zebra:0.93b:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:rational_clearquest:6.15:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:serviceguard:a.11.15.00:*:*:*:*:*:*:*",
    "cpe:2.3:o:juniper:junos:6.2:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.0\\(20\\)sp:*:*:*:*:*:*:*",
    "cpe:2.3:o:juniper:netscreen_screenos:3.0.3:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:nonstop_seeview_server_gateway:g06.18:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:toolbar:1.1.53:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.4.34.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:openview_emanate_snmp_agent:14.2:*:*:*:*:*:*:*",
    "cpe:2.3:a:e107:e107:0.7.6:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:lotus_domino_server:5.0.9:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:catalyst_12xx_supervisor_software:4.29:*:*:*:*:*:*:*",
    "cpe:2.3:a:f5:big-ip:4.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:spamassassin:3.0.1:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.3\\(11\\)xl:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:lotus_notes:5.0.5:*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:c5000rsm:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:gnu:gnutls:1.2.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:lotus_domino_server:6.5.1:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:2.4.0:test1:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.0\\(23\\)sz:*:*:*:*:*:*:*",
    "cpe:2.3:a:bea:jrockit:-:*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:clean_access:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:novell:ichain:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.4\\(3a\\):*:*:*:*:*:*:*",
    "cpe:2.3:o:compaq:tru64:5.0f:*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:catalyst_2900:lre_xl:*:*:*:*:*:*:*",
    "cpe:2.3:h:f5:firepass_4300:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:rssreader:rssreader:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:nonstop_seeview_server_gateway:d48.01:*:*:*:*:*:*:*",
    "cpe:2.3:h:axis:panorama_ptz_camera:2.39:*:*:*:*:*:*:*",
    "cpe:2.3:a:e107:e107:0.7:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:cocoon:2.1.2:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.0\\(21\\)s5a:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.3\\(11\\)yk:*:*:*:*:*:*:*",
    "cpe:2.3:a:isc:bind:8.1.2:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:catos:6.3\\(6\\):*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:unified_ip_conference_station_7935:-:*:*:*:*:*:*:*",
    "cpe:2.3:a:apple:safari:1.0:beta:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:cache_engine_570:2.4.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:cisco:ids_device_manager:3.1.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:apple:darwin_streaming_server:4.1.2:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:mercury_loadrunner_agent:8.1:*:*:*:*:*:*:*",
    "cpe:2.3:h:hp:laserjet_4000n:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.1\\(8b\\)e18:*:*:*:*:*:*:*",
    "cpe:2.3:h:3com:tippingpoint_ips_1200e:-:*:*:*:*:*:*:*",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      // parse match string
      ms, err := ParseMatch(test)
      if err != nil {
        t.Fatal(err)
      }

      // compare string
      got := ms.String()
      exp := test
      if got != exp {
        t.Fatalf("got %s, exp %s", got, test)
      }
    })
  }
}
