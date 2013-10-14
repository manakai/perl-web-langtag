use strict;
use warnings;
use JSON;
use Data::Dumper;

local $/ = undef;
my $data = JSON->new->utf8->decode (scalar <>);
my $full = $ENV{FULL};

unless ($full) {
  delete $data->{extension};
  delete $data->{extheader};
  delete $data->{_ext_file_date};
  for (values %$data) {
    next unless ref $_ eq 'HASH';
    for my $subtag (values %$_) {
      next unless ref $subtag eq 'HASH';
      delete $subtag->{_added};
      delete $subtag->{_macro};
      delete $subtag->{Comments};
      delete $subtag->{Description};
      delete $subtag->{Scope};
    }
  }
}

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Purity = 1;
my $value = Dumper $data;
if ($full) {
  $value =~ s/\$VAR1\b/\$Web::LangTag::RegistryFull/g;
} else {
  $value =~ s/\$VAR1\b/\$Web::LangTag::Registry/g;
}

print $value;
print "1;\n";

## License: Public Domain.
