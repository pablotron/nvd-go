# CVSS Vector Calculator

Example of using the NVD CVE search API.

Calculate scores of CVSS vectors given as command-line arguments and
write the results to standard output in CSV format.

## Example

Get CVSS version and scores for three vectors:

    go run cvss-calc.go "AV:N/AC:L/Au:N/C:N/I:N/A:C" "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:C" "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:R"
    vector,version,base score,temporal score,environmental score
    AV:N/AC:L/Au:N/C:N/I:N/A:C,2.0,7.8,n/a,n/a
    CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:C,3.0,7.3,7.3,n/a
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/RC:R,3.1,7.3,7.1,n/a
