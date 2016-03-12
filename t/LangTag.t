use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps', 'modules', '*', 'lib')->stringify;
use Test::X1;
use Test::More;
use Test::Differences;
use Test::HTCT::Parser;
use Web::LangTag;

my $data_path = path (__FILE__)->parent->parent->child ('t_deps', 'tests', 'langtags');

for_each_test ($_, {
  1766 => {is_list => 1},
  3066 => {is_list => 1},
  4646 => {is_list => 1},
  5646 => {is_list => 1},
}, sub {
  my $test = shift;
  my $lt = Web::LangTag->new;
  
  test {
    my $c = shift;
    our @errors = ();
    my $onerror = sub {
      my %opt = @_;
      push @errors, join ';',
          $opt{type},
          defined $opt{text} ? $opt{text} : '',
          defined $opt{value} ? $opt{value} : '',
          $opt{level};
    }; # $onerror
    $lt->onerror ($onerror);
    
    {
      local @errors;

      my $parsed = $lt->parse_rfc4646_tag
          ($test->{data}->[0]);
      my $result = $lt->check_rfc4646_parsed_tag
          ($parsed);
      
      my $expected = $test->{4646};
      if ($expected) {
        eq_or_diff join ("\n", sort {$a cmp $b} @errors),
            join ("\n", sort {$a cmp $b} @{$expected->[0]}),
            '_parse ' . $test->{data}->[0];
        is !$result->{well_formed},
            !! grep { $_ eq 'ill-formed' } @{$expected->[1] or []};
        is !$result->{valid},
            !! grep { $_ eq 'ill-formed' or $_ eq 'invalid' } @{$expected->[1] or []};
      } else {
        warn qq[No test item: "$test->{data}->[0]];
      }
    }

    {
      local @errors;
      
      my $parsed = $lt->parse_rfc5646_tag
          ($test->{data}->[0]);
      my $result = $lt->check_rfc5646_parsed_tag
          ($parsed);

      my $expected = $test->{5646} || $test->{4646};
      if ($expected) {
        eq_or_diff join ("\n", sort {$a cmp $b} @errors),
            join ("\n", sort {$a cmp $b} @{$expected->[0]}),
            '_parse ' . $test->{data}->[0];
        is !$result->{well_formed},
            !! grep { $_ eq 'ill-formed' } @{$expected->[1]};
        is !$result->{valid},
            !! grep { $_ eq 'ill-formed' or $_ eq 'invalid' } @{$expected->[1]};

        my $canon = $lt->canonicalize_rfc5646_tag
            ($test->{data}->[0]);
        is $canon, ($test->{canon5646} || $test->{data})->[0];

        my $extlang = $lt->to_extlang_form_rfc5646_tag
            ($test->{data}->[0]);
        is $extlang, ($test->{extlang5646} || $test->{canon5646} || $test->{data})->[0];
      }
    }

    {
      local @errors;
      
      my $result = $lt->check_rfc3066_tag
          ($test->{data}->[0]);

      my $expected = $test->{3066} || [['']];
      if ($expected) {
        eq_or_diff join ("\n", sort {$a cmp $b} @errors),
            join ("\n", sort {$a cmp $b} @{$expected->[0]}),
            '_check3066 ' . $test->{data}->[0];
      }
    }

    {
      local @errors;
      
      my $result = $lt->check_rfc1766_tag
          ($test->{data}->[0]);

      my $expected = $test->{1766} || $test->{3066} || [['']];
      if ($expected) {
        eq_or_diff join ("\n", sort {$a cmp $b} @errors),
            join ("\n", sort {$a cmp $b} @{$expected->[0]}),
            '_check1766 ' . $test->{data}->[0];
      }
    }
    done $c;
  } name => 'basic';
}) for map { $data_path->child ($_)->stringify } qw[
  validity-core-1.dat
];

for_each_test ($_, {
  4646 => {is_list => 1},
  5646 => {is_list => 1},
}, sub {
  my $test = shift;
  my $lt = Web::LangTag->new;
  
  test {
    my $c = shift;
    our @errors = ();
    my $onerror = sub {
      my %opt = @_;
      push @errors, join ';',
          $opt{type},
          defined $opt{text} ? $opt{text} : '',
          defined $opt{value} ? $opt{value} : '',
          $opt{level};
    }; # $onerror
    $lt->onerror ($onerror);
    
    {
      local @errors;

      my $parsed = $lt->parse_rfc4646_tag
          ($test->{data}->[0]);
      my $result = $lt->check_rfc4646_parsed_tag
          ($parsed);
      
      my $expected = $test->{4646};
      if ($expected) {
        eq_or_diff join ("\n", sort {$a cmp $b} @errors),
            join ("\n", sort {$a cmp $b} @{$expected->[0]}),
            '_parse ' . $test->{data}->[0];
        is !$result->{well_formed},
            !! grep { $_ eq 'ill-formed' } @{$expected->[1] or []};
        is !$result->{valid},
            !! grep { $_ eq 'ill-formed' or $_ eq 'invalid' } @{$expected->[1] or []};
      } else {
        warn qq[No test item: "$test->{data}->[0]];
      }
    }

    {
      local @errors;
      
      my $parsed = $lt->parse_rfc5646_tag
          ($test->{data}->[0]);
      my $result = $lt->check_rfc5646_parsed_tag
          ($parsed);

      my $expected = $test->{5646} || $test->{4646};
      if ($expected) {
        eq_or_diff join ("\n", sort {$a cmp $b} @errors),
            join ("\n", sort {$a cmp $b} @{$expected->[0]}),
            '_parse ' . $test->{data}->[0];
        is !$result->{well_formed},
            !! grep { $_ eq 'ill-formed' } @{$expected->[1]};
        is !$result->{valid},
            !! grep { $_ eq 'ill-formed' or $_ eq 'invalid' } @{$expected->[1]};

        my $canon = $lt->canonicalize_rfc5646_tag
            ($test->{data}->[0]);
        is $canon, ($test->{canon5646} || $test->{data})->[0];

        my $extlang = $lt->to_extlang_form_rfc5646_tag
            ($test->{data}->[0]);
        is $extlang, ($test->{extlang5646} || $test->{canon5646} || $test->{data})->[0];
      }
    }
    done $c;
  } name => 'ext';
}) for map { $data_path->child ($_)->stringify } qw[
  validity-u-1.dat validity-t-1.dat
];

test {
  my $c = shift;
  my $parsed1 = Web::LangTag->new->parse_rfc4646_tag ('zh-min-nan');
  eq_or_diff $parsed1, {
    language => 'zh',
    extlang => [qw(min nan)],
    variant => [],
    illegal => [],
    privateuse => [],
    extension => [],
  };

  my $parsed2 = Web::LangTag->new->parse_rfc5646_tag ('zh-min-nan');
  eq_or_diff $parsed2, {
    extlang => [],
    variant => [],
    illegal => [],
    privateuse => [],
    extension => [],
    grandfathered => 'zh-min-nan',
  };

  my $parsed3 = Web::LangTag->new->parse_tag ('zh-min-nan');
  eq_or_diff $parsed3, {
    extlang => [],
    variant => [],
    illegal => [],
    privateuse => [],
    extension => [],
    grandfathered => 'zh-min-nan',
  };

  my $error3 = 0;
  my $lt = Web::LangTag->new;
  $lt->onerror (sub { $error3++ });
  my $result3 = $lt->check_parsed_tag ($parsed3);
  eq_or_diff $result3, {well_formed => 1, valid => 1};
  is $error3, 1;
  done $c;
} n => 5, name => 'zh-min-nan';

for my $test (
  ['en-u-ab', [qw[u ab]], [[], [qw[ab]]]],
  ['en-u-ab-cde-fgh', [qw[u ab cde fgh]], [[], [qw[ab cde fgh]]]],
  ['en-u-ab-cd', [qw[u ab cd]], [[], [qw[ab]], [qw[cd]]]],
  ['en-u-ab-cde-ab', [qw[u ab cde ab]], [[], [qw[ab cde]], [qw[ab]]]],
  ['en-u-ab-12-xyz-AB', [qw[u ab 12 xyz AB]], [[], [qw[ab]], [qw[12 xyz]], [qw[AB]]]],
  ['en-u-abc', [qw[u abc]], [[qw[abc]]]],
  ['en-u-abc-def', [qw[u abc def]], [[qw[abc def]]]],
  ['en-u-abc-12', [qw[u abc 12]], [[qw[abc]], [qw[12]]]],
  ['en-U-abc', [qw[U abc]], [[qw[abc]]]],
  ['en-u-1ab', [qw[u 1ab]], [[qw[1ab]]]],
) {
  test {
    my $c = shift;
    my $parsed = Web::LangTag->new->parse_rfc5646_tag ($test->[0]);
    eq_or_diff $parsed, {
      language => 'en',
      extlang => [],
      variant => [],
      illegal => [],
      privateuse => [],
      extension => [$test->[1]],
      u => $test->[2],
    };
    done $c;
  } n => 1, name => 'u extension';
}

for my $test (
  ['', ''],
  ['ja', 'ja'],
  ['ja-jp', 'ja-JP'],
  ['ja-JP', 'ja-JP'],
  ['en-CA-x-ca', 'en-CA-x-ca'],
  ['sgn-BE-FR', 'sgn-BE-FR'],
  ['az-Latn-x-latn', 'az-Latn-x-latn'],
  ['in-in', 'in-IN'],
  ["\x{0130}n-\x{0130}n", "\x{0130}n-\x{0130}N"],
  ["\x{0131}n-\x{0131}n", "\x{0131}n-\x{0131}N"],
  ['ja-latn-jp-u-ja-JP-Latn' => 'ja-Latn-JP-u-ja-jp-latn'],
  ['ja-latn-jp-i-ja-JP-Latn' => 'ja-Latn-JP-i-ja-JP-Latn'],
  ['ja-latn-jp-x-ja-JP-Latn' => 'ja-Latn-JP-x-ja-JP-Latn'],
) {
  test {
    my $c = shift;
    is +Web::LangTag->new->normalize_rfc5646_tag ($test->[0]), $test->[1];
    is +Web::LangTag->new->normalize_tag ($test->[0]), $test->[1];
    done $c;
  } n => 2, name => 'normalize';
}

test {
  my $c = shift;
  is +Web::LangTag->new->canonicalize_tag ('zh-min-nan'), 'nan';
  is +Web::LangTag->new->to_extlang_form_tag ('zh-min-nan'), 'zh-nan';
  done $c;
} n => 2, name => 'canonicalize';

for my $test (
     [undef, undef, 1],
     ['*', undef, 1],
     ['', undef, 1],
     ['', '', 1],
     ['*', '', 1],
     ['', undef, 1],
     ['ja', 'ja', 1],
     ['JA', 'ja', 1],
     ['ja', 'JA', 1],
     ['InValid', 'invalid', 1],
     ['ja-jp', 'ja', 0],
     ['ja', 'ja-jp', 1],
     ['jajp', 'ja', 0],
     ['ja', 'jajp', 0],
     ['ja-', 'jajp', 0],
     ['ja-', 'ja-jp', 0],
     ['ja-', 'ja--', 1],
     ['ja-j', 'ja-jp', 0],
     ['ja-', 'ja-', 1],
     ['de-ch', 'de-ch-1996', 1],
     ['de-ch', 'de-CH-1996', 1],
     ['de-ch', 'de-ch', 1],
     ['de-ch', 'de-ch-1901-x-hoge', 1],
     ['de-ch', 'de-zh-1996', 0],
     ['de-ch', 'de-Latn-ch', 0],
     ['de-ch', 'de', 0],
     ['de-ch', 'x-de-ch', 0],
     ['de', 'de-ch-1996', 1],
     ['de', 'de-ch', 1],
     ['x-hoge', 'de-ch', 0],
     ['x-hoge', 'x-hoge', 1],
     ['x-hoge', 'x-hoge-fuga', 1],
     ['x-hoge', 'en-x-hoge-fuga', 0],
     ['x', 'x-hoge-fuga', 1],
     ['x-', 'x-hoge-fuga', 0],
) {
  test {
    my $c = shift;
    is !!Web::LangTag->new->basic_filtering_range ($test->[0], $test->[1]),
       !!$test->[2];
    is !!Web::LangTag->new->basic_filtering_rfc4647_range ($test->[0], $test->[1]),
       !!$test->[2];
    is !!Web::LangTag->new->match_rfc3066_range ($test->[0], $test->[1]),
       !!$test->[2];
    done $c;
  } n => 3, name => 'basic filtering range';
}

for my $test (
     [undef, undef, 1],
     ['*', undef, 1],
     ['', undef, 1],
     ['', '', 1],
     ['*', '', 1],
     ['', undef, 1],
     ['ja', 'ja', 1],
     ['JA', 'ja', 1],
     ['ja', 'JA', 1],
     ['InValid', 'invalid', 1],
     ['ja-jp', 'ja', 0],
     ['ja', 'ja-jp', 1],
     ['jajp', 'ja', 0],
     ['ja', 'jajp', 0],
     ['ja-', 'jajp', 0],
     ['ja-', 'ja-jp', 0],
     ['ja-', 'ja--', 1],
     ['ja-j', 'ja-jp', 0],
     ['ja-', 'ja-', 1],
     ['de-ch', 'de-ch-1996', 1],
     ['de-ch', 'de-CH-1996', 1],
     ['de-ch', 'de-ch', 1],
     ['de-ch', 'de-ch-1901-x-hoge', 1],
     ['de-ch', 'de-zh-1996', 0],
     ['de-ch', 'de-Latn-ch', 1],
     ['de-ch', 'de', 0],
     ['de-ch', 'x-de-ch', 0],
     ['de', 'de-ch-1996', 1],
     ['de', 'de-ch', 1],
     ['x-hoge', 'de-ch', 0],
     ['x-hoge', 'x-hoge', 1],
     ['x-hoge', 'x-hoge-fuga', 1],
     ['x-hoge', 'en-x-hoge-fuga', 0],
     ['x', 'x-hoge-fuga', 1],
     ['x-', 'x-hoge-fuga', 0],
     ['de-DE', 'de-de', 1],
     ['de-DE', 'de-De', 1],
     ['de-DE', 'de-DE', 1],
     ['de-DE', 'de-Latn-DE', 1],
     ['de-DE', 'de-Latf-DE', 1],
     ['de-DE', 'de-DE-x-goethe', 1],
     ['de-DE', 'de-Latn-DE-1996', 1],
     ['de-DE', 'de-Deva-DE', 1],
     ['de-DE', 'de', 0],
     ['de-DE', 'de-x-DE', 0],
     ['de-DE', 'de-Deva', 0],
     ['ja-*', 'ja', 1],
     ['ja-*', 'ja-jp', 1],
     ['ja-*', 'ja-x-hoge', 1],
     ['ja-*-*', 'ja', 1],
     ['ja-*-*', 'ja-jp', 1],
     ['ja-*-*', 'ja-x-hoge', 1],
     ['ja-*-*-jp', 'ja-jp', 1],
     ['ja-*-*-jp', 'ja-latn-jp', 1],
     ['ja-*-*-jp', 'ja-latn-us', 0],
     ['*-*-jp', 'ja-latn-jp', 1],
     ['*-*-jp', 'ja-latn-us', 0],
     ['*-*-jp', 'ja-jp', 1],
     ['*-*-jp', 'ja-us', 0],
     ['*-jp', 'ja-latn-jp', 1],
     ['*-jp', 'ja-latn-us', 0],
     ['*', 'ja-latn-jp', 1],
     ['*', 'ja-latn-us', 1],
     ['*-x', 'ja-x-latn', 1],
     ['*-y', 'ja-x-latn', 0],
     ['x', 'ja-x-latn', 0],
     ['x', 'x-latn', 1],
     ['latn', 'x-latn', 0],
) {
  test {
    my $c = shift;
    is !!Web::LangTag->new->extended_filtering_range ($test->[0], $test->[1]),
       !!$test->[2];
    is !!Web::LangTag->new->extended_filtering_rfc4647_range ($test->[0], $test->[1]),
       !!$test->[2];
    done $c;
  } n => 2, name => 'extended filtering range';
}

for my $method (qw(
  tag_registry_data_rfc4646
  tag_registry_data_rfc5646
  tag_registry_data
)) {
  test {
    my $c = shift;
    my $ja = Web::LangTag->new->$method (language => 'ja');
    ok !$ja->{_canon};
    is $ja->{_added}, '2005-10-16';
    is $ja->{_suppress}, 'jpan';
    ok !$ja->{_deprecated};
    ok !$ja->{_preferred};
    ok !$ja->{Prefix};
    eq_or_diff $ja->{Description}, ['Japanese'];
    
    my $us = Web::LangTag->new->$method (region => 'us');
    is $us->{_canon}, '_uppercase';
    is $us->{_added}, '2005-10-16';
    ok !$us->{_suppress};
    ok !$us->{_deprecated};
    ok !$us->{_preferred};
    ok !$us->{Prefix};
    eq_or_diff $us->{Description}, ['United States'];
    
    my $not_registered = Web::LangTag->new->$method (script => 123);
    is $not_registered, undef;
    
    my $no_type = Web::LangTag->new->$method (bad => 'ja');
    is $no_type, undef;
    
    my $grandfathered = Web::LangTag->new->$method (grandfathered => 'i-ami');
    ok $grandfathered->{_deprecated};
    is $grandfathered->{_preferred}, 'ami';
    
    my $redundant = Web::LangTag->new->$method (redundant => 'zh-yue');
    ok $redundant->{_deprecated};
    is $redundant->{_preferred}, 'yue';
    done $c;
  } n => 20, name => $method;
}

run_tests;

## License: Public Domain.
