#!/usr/bin/perl -w

use strict;
use Getopt::Long;

my $cluster = "abattery";
my $security_zone = "default";
my $app_name = "";
my $secret_name = "";
my $cn = "";

Getopt::Long::Configure("permute", "pass_through");
if (!GetOptions(
    "app-name=s" => \$app_name,
    "secret-name=s" => \$secret_name,
    "cn=s" => \$cn,
    "cluster=s" => \$cluster,
    "security-zone=s" => \$security_zone)) {
    usage();
}

check_arg($app_name, "app-name");
check_arg($secret_name, "secret-name");
check_arg($cn, "cn");

my $collection = "abattery_app_secrets_".$cluster."_zone_".$security_zone;
my $definition = "ab_app_".$app_name."_secname_".$secret_name;

print "Creating definition.\n";
my $cmd = << "END_STRING";
echo "<?xml version='1.0' ?>
<definition type='ssl_cert'>
<option name='cn'>$cn</option>
<option name='ec'>secp256r1</option>
<refresh_period>15 years</refresh_period>
<expire_period>15 years</expire_period>
<delete_period>15 years</delete_period>
</definition>" | /a/bin/k3c xmlreq --socket=/a/alterd/kmi3_restful_sock \\
--method=PUT --path=/definition/Col=$collection/Def=$definition
END_STRING
run($cmd);

print "Modifying definition.\n";
$cmd = << "END_STRING";
echo "<?xml version='1.0' ?>
<definition>
<auto_generate>true</auto_generate>
</definition>" | /a/bin/k3c xmlreq --socket=/a/alterd/kmi3_restful_sock \\
--method=POST --path=/definition/Col=$collection/Def=$definition
END_STRING
run($cmd);

print "\nkdc_ca signing acl for collection:\n";
$cmd = "/a/bin/k3c definition kdc_ca kdc_ca | grep -A1 signacl:$collection";
run($cmd);

# run and output shell command, exit if error
sub run {
    my ( $cmd ) = @_;
    print "Running: $cmd\n";
    system($cmd);
    my $rc = $?;
    if ($rc) {
        print("Error running command.  Exiting.\n");
        exit 1;
    }
    return $?;
}

sub check_arg {
    my ($arg, $name) = @_;
    if (length $arg == 0) {
        print "No $name specified";
        usage();
    }
}

sub usage {
    print
"
Usage: prov_ab_ssl_cert.pl [options]
    --app-name app_name
    --secret-name sec_name
    --cn cn
    [--cluster cluster]
    [--security_zone sec_zone]
";
    exit 1;
}
