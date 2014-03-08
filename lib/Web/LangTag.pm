package Web::LangTag;
use strict;
use warnings;
our $VERSION = '7.0';

sub new ($) {
  return bless {}, $_[0];
} # new

my $Levels = {
  langtag_fact => 'm',
  must => 'm',
  should => 's',
  good => 'w',

  warn => 'w',
  info => 'i',
};

sub onerror ($;$) {
  if (@_ > 1) {
    $_[0]->{onerror} = $_[1];
  }
  return $_[0]->{onerror} ||= sub {
    my %args = @_;
    warn sprintf "%s: %s%s (%s)\n",
        $args{value},
        $args{type},
        (defined $args{text} ? ' ' . $args{text} : ''),
        $args{level};
  };
} # onerror

## Versioning flags
# $self->{RFC5646}
# $self->{RFC1766}

my $Grandfathered5646 = {map { $_ => 1 } qw(
  en-gb-oed i-ami i-bnn i-default i-enochian i-hak i-klingon i-lux
  i-mingo i-navajo i-pwn i-tao i-tay i-tsu sgn-be-fr sgn-be-nl sgn-ch-de
  art-lojban cel-gaulish no-bok no-nyn zh-guoyu zh-hakka zh-min
  zh-min-nan zh-xiang
)};

# ------ Parsing ------

*parse_tag = \&parse_rfc5646_tag;

sub parse_rfc5646_tag ($$) {
  local $_[0]->{RFC5646} = 1;
  return shift->parse_rfc4646_tag (@_);
} # parse_rfc5646_tag

# Compat
*parse_rfc4646_langtag = \&parse_rfc4646_tag;

## NOTE: This method, with appropriate $onerror handler, is a
## "well-formed" processor [RFC 4646].
sub parse_rfc4646_tag ($$) {
  my ($self, $tag) = @_;

  my @tag = split /-/, $tag, -1;

  my %r = (
    language => (@tag ? shift @tag : ''),
    extlang => [],
    variant => [],
    extension => [],
    privateuse => [],
    illegal => [],
  );

  my $tag_l = $tag;
  $tag_l =~ tr/A-Z/a-z/;

  if ($self->{RFC5646} and $Grandfathered5646->{$tag_l}) {
    return {
      extlang => [],
      variant => [],
      extension => [],
      privateuse => [],
      grandfathered => $tag,
      illegal => [],      
    };
  }

  my $grandfathered = !$self->{RFC5646} && $tag =~ /\A[A-Za-z]{1,3}(?>-[A-Za-z0-9]{2,8}){1,2}\z/;

  if ($r{language} and $r{language} =~ /\A[A-Za-z]+\z/) {
    if (length $r{language} == 1) {
      if ($r{language} =~ /\A[Xx]\z/) {
        unshift @tag, $r{language};
        delete $r{language};
      } else {
        if ($grandfathered) {
          $r{grandfathered} = $tag;
          delete $r{language};
          return \%r;
        } else {
          ## NOTE: Well-formed processor MUST check whether a tag
          ## conforms to the ABNF (RFC 4646 2.2.9.), SHOULD be
          ## canonical and to be canonical, it has to be well-formed
          ## (RFC 4646 4.4. 1.), "Private ues subtags, like other
          ## subtags, MUST conform to the format and content
          ## cnstraints in the ABNF." (RFC 4646 4.5.)
          $self->onerror->(type => 'langtag:language:syntax',
                     value => $r{language},
                     level => $Levels->{must});
        }
      }
    } elsif (length $r{language} <= 3) {
      while (@tag and $tag[0] =~ /\A[A-Za-z]{3}\z/ and @{$r{extlang}} < 3) {
        push @{$r{extlang}}, shift @tag;
      }
    } elsif (length $r{language} <= 8) {
      #
    } else {
      ## NOTE: Well-formed processor MUST check whether a tag conforms
      ## to the ABNF (RFC 4646 2.2.9.), SHOULD be canonical and to be
      ## canonical, it has to be well-formed (RFC 4646 4.4. 1.)
      ## "Private ues subtags, like other subtags, MUST conform to the
      ## format and content cnstraints in the ABNF." (RFC 4646 4.5.)
      $self->onerror->(type => 'langtag:language:syntax',
                 value => $r{language},
                 level => $Levels->{must});
    }
  } else {
    ## NOTE: Well-formed processor MUST check whether a tag conforms
    ## to the ABNF (RFC 4646 2.2.9.), SHOULD be canonical and to be
    ## canonical, it has to be well-formed (RFC 4646 4.4. 1.),
    ## "Private ues subtags, like other subtags, MUST conform to the
    ## format and content cnstraints in the ABNF." (RFC 4646 4.5.)
    $self->onerror->(type => 'langtag:language:syntax',
               value => $r{language},
               level => $Levels->{must});
  }

  if (defined $r{language}) {
    if (@tag and $tag[0] =~ /\A[A-Za-z]{4}\z/) {
      $r{script} = shift @tag;
    }
    
    if (@tag and $tag[0] =~ /\A(?>[A-Za-z]{2}|[0-9]{3})\z/) {
      $r{region} = shift @tag;
    }
    
    while (@tag and
           $tag[0] =~
               /\A(?>[A-Za-z][A-Za-z0-9]{4,7}|[0-9][A-Za-z0-9]{3,7})\z/) {
      push @{$r{variant}}, shift @tag;
    }

    my %has_extension;
    while (@tag >= 2 and $tag[0] =~ /\A[A-WYZa-wyz0-9]\z/ and
           $tag[1] =~ /\A[A-Za-z0-9]{2,8}\z/) {
      my $exttag = $tag[0];
      $exttag =~ tr/A-Z/a-z/;
      if ($has_extension{$exttag}++) {
        ## NOTE: Well-formed processor MUST check (RFC 4646 2.2.9.)
        ## and MUST and MUST NOT (RFC 4646 2.2.6. 4.), , SHOULD be
        ## canonical and to be canonical, it has to be well-formed
        ## (RFC 4646 4.4. 1.)
        $self->onerror->(type => 'langtag:extension:duplication',
                   value => $tag[0],
                   level => $Levels->{must});
      }
      my $ext = [shift @tag => shift @tag];
      while (@tag and $tag[0] =~ /\A[A-Za-z0-9]{2,8}\z/) {
        push @$ext, shift @tag;
      }
      push @{$r{extension}}, $ext;

      ## RFC 6067 / UTS #35
      if ($exttag eq 'u' and $has_extension{$exttag} == 1) {
        $r{u} = [[]];
        my $key = undef;
        my %has_attribute;
        my %has_key;
        for my $i (1..$#$ext) {
          if (2 == length $ext->[$i]) {
            $key = $ext->[$i];
            $key =~ tr/A-Z/a-z/;
            if ($has_key{$key}) {
              $self->onerror->(type => 'langtag:extension:u:key:duplication',
                         value => $key,
                         level => $Levels->{must}); ## RFC 6067
            }
            $has_key{$key}++;
            push @{$r{u}}, [$ext->[$i]];
          } else {
            if (not defined $key) {
              my $attr = $ext->[$i];
              $attr =~ tr/A-Z/a-z/;
              if ($has_attribute{$attr}) {
                $self->onerror->(type => 'langtag:extension:u:attr:duplication',
                           value => $attr,
                           level => $Levels->{langtag_fact}); ## RFC 6067
              }
              $has_attribute{$attr}++;
            }
            push @{$r{u}->[-1]}, $ext->[$i];
          }
        }
      } # 'u'

      if ($exttag eq 't' and $has_extension{$exttag} == 1) {
        $r{t} = [undef];
        my $field = undef;
        my %has_field;
        for my $i (1..$#$ext) {
          if ($ext->[$i] =~ /\A[A-Za-z][0-9]\z/) {
            $field = $ext->[$i];
            $field =~ tr/A-Z/a-z/;
            if ($has_field{$field}++) {
              $self->onerror->(type => 'langtag:extension:t:field:duplication',
                               value => $field,
                               level => $Levels->{must}); ## RFC 6497
            }
            push @{$r{t}}, [$ext->[$i]];
            next;
          }
          push @{$r{t}->[-1] ||= []}, $ext->[$i];
        }
        if (defined $r{t}->[0]) {
          $r{t}->[0] = $self->parse_rfc4646_tag (join '-', @{$r{t}->[0]});
        }
      } # 't'
    }
  }

  if (@tag >= 2 and $tag[0] =~ /\A[Xx]\z/) {
    for (@tag) {
      unless (/\A[A-Za-z0-9]{1,8}\z/) {
        ## NOTE: MUST (RFC 4646 2.2.7.), Well-formed processor MUST
        ## check whether a tag conforms to the ABNF (RFC 4646 2.2.9.),
        ## "Private ues subtags, like other subtags, MUST conform to
        ## the format and content cnstraints in the ABNF." (RFC 4646
        ## 4.5.)
        $self->onerror->(type => 'langtag:privateuse:syntax',
                   value => $_,
                   level => $Levels->{must});
      }
    }
    @{$r{privateuse}} = @tag;
    @tag = ();
  }

  if (@tag) {
    if ($grandfathered) {
      return {
              extlang => [],
              variant => [],
              extension => [],
              privateuse => [],
              grandfathered => $tag,
              illegal => [],      
             };
    } else {
      ## NOTE: Violation to the syntax/prose (RFC 4646 2.1.,
      ## fact-level)

      ## NOTE: "Variants starting with a letter MUST be at least five
      ## character long" (RFC 4646 2.1., Note, RFC 4646 2.2.5.)

      ## NOTE: "Sequence of private use and extension subtags MUST
      ## occur at the end of the sequence of subtags and MUST NOT be
      ## interspersed with subtags" (RFC 4646 2.2.)

      ## NOTE: "An extension MUST follow at least a primary language
      ## subtag." (RFC 4646 2.2.6. 3.)

      ## NOTE: "Extension subtag MUST meet all of the requirements for
      ## the content and format of subtags" (RFC 4646 2.2.6. 5.) and
      ## "MUST be from two to eight characters long and consist solely
      ## of letters or digits, with each subtag separated by a signle
      ## '-'" (RFC 4646 2.2.6. 7.) and "singleton MUST be followed by
      ## at least one extension subtag" (RFC 4646 2.2.6. 8.)

      ## NOTE: "Private use subtags MUST conform to the format and
      ## content constraints" (RFC 4646 2.2.7. 2.)

      ## NOTE: There are other "MUST"s that would cover some of cases
      ## that fall into this error.  I'm not sure that those
      ## requirements as a whole covers all the cases that would fall
      ## into this error...  I wonder if the spec simply said that any
      ## language tag MUST conform to the ABNF syntax...

      ## NOTE: Well-formed processor MUST check whether a tag conforms
      ## to the ABNF (RFC 4646 2.2.9.), SHOULD be canonical and to be
      ## canonical, it has to be well-formed (RFC 4646 4.4. 1.)
      ## "Private ues subtags, like other subtags, MUST conform to the
      ## format and content cnstraints in the ABNF." (RFC 4646 4.5.)
      for (@tag) {
        $self->onerror->(type => 'langtag:illegal',
                   value => $_,
                   level => $Levels->{must});
      }
      push @{$r{illegal}}, @tag;
    }
  }

  return \%r;
} # parse_rfc4646_tag

sub serialize_parsed_tag ($$) {
  my $tag_o = $_[1];
  if (defined $tag_o->{grandfathered}) {
    return $tag_o->{grandfathered};
  } else {
    return join '-',
        (defined $tag_o->{language} ? ($tag_o->{language}) : ()),
        @{$tag_o->{extlang}},
        (defined $tag_o->{script} ? ($tag_o->{script}) : ()),
        (defined $tag_o->{region} ? ($tag_o->{region}) : ()),
        @{$tag_o->{variant}},
        (map { @$_ } @{$tag_o->{extension}}),
        @{$tag_o->{privateuse}},
        @{$tag_o->{illegal}};
  }
} # serialize_parsed_tag

# ------ Conformance checking ------

*check_parsed_tag = \&check_rfc5646_parsed_tag;

sub check_rfc5646_parsed_tag ($$) {
  local $_[0]->{RFC5646} = 1;
  return shift->check_rfc4646_parsed_tag (@_);
} # check_rfc5646_parsed_tag

# Compat
*check_rfc4646_langtag = \&check_rfc4646_parsed_tag;

## NOTE: This method, with appropriate $self->onerror handler, is intended
## to be a "validating" processor of language tags, as defined in RFC
## 4646, if an output of the |parse_rfc4646_tag| method is inputed.
sub check_rfc4646_parsed_tag ($$;%) {
  my ($self, $tag_o, %args) = @_;

  my $result = {well_formed => !@{$tag_o->{illegal}}, valid => 1};
  if (defined $tag_o->{language}) {
    delete $result->{well_formed}
        unless $tag_o->{language} =~ /\A[A-Za-z]{2,8}\z/;
  }
  delete $result->{well_formed}
      if grep { not /\A[A-Za-z0-9]{1,8}\z/ } @{$tag_o->{privateuse}};
  delete $result->{valid} unless $result->{well_formed};

  require Web::LangTag::_List;
  our $Registry;

  my $tag_s = $tag_o->{grandfathered};
  $tag_s = $self->serialize_parsed_tag ($tag_o) unless defined $tag_s;
  my $tag_s_orig = $tag_s;
  $tag_s =~ tr/A-Z/a-z/;

  my $check_case = $args{ignore_case} ? sub { } : sub ($$$) {
    my ($type, $actual, $expected) = @_;
    
    $expected ||= '_lowercase';
    if ($expected eq '_lowercase' and $actual !~ /[A-Z]/) {
      #
    } elsif ($expected eq '_uppercase' and $actual !~ /[a-z]/) {
      #
    } elsif ($expected eq '_titlecase' and
             substr ($actual, 0, 1) !~ /[a-z]/ and
             substr ($actual, 1) !~ /[A-Z]/) {
      #
    } elsif ($expected eq $actual and
             $expected !~ /^_/) {
      #
    } else {
      ## NOTE: RECOMMENDED (RFC 4646 2.1.)
      $self->onerror->(type => 'langtag:'.$type.':case',
                 value => $actual,
                 level => $Levels->{should});
    }
  }; # $check_case

  my $check_deprecated = sub ($$$) {
    my ($type, $actual, $def) = @_;

    ## NOTE: Record of 'Preferred-Value' MUST have 'Deprecated' field.
    ## (RFC 4646 3.1.)

    ## NOTE: Transitive relationships are resolved in the
    ## "mklangreg.pl".

    if ($def->{_deprecated}) {
      ## NOTE: Validating processors SHOULD NOT generate (RFC 4646
      ## 3.1., RFC 4646 4.4. Note; Why only validating processors?)
      ## and the value in the 'Preferred-Value', if any, is STRONGLY
      ## RECOMMENDED (RFC 4646 3.1.), 'Preferred-Value' SHOULD be used
      ## (RFC 4646 4.1. 3.), A tag SHOULD be canonical, to be
      ## canonical a region subtag SHOULD use Preferred-Value (RFC
      ## 4646 4.4. 2.), and to be canonical a redundant or
      ## grandfathered tag MUST use Preferred-Value (RFC 4646
      ## 4.4. 3.), and to be canonical other subtags MUST be canonical
      ## (RFC 4646 4.4. 4.).
      $self->onerror->(type => 'langtag:'.$type.':deprecated',
                 text => $def->{_preferred}, # might be undef
                 value => $actual,
                 level => $Levels->{should});
    } elsif ($self->{RFC5646} and $def->{_preferred}) {
      ## RFC 5646 2.2.2.
      $self->onerror->(type => 'langtag:'.$type.':preferred',
                 text => $def->{_preferred},
                 value => $actual,
                 level => $Levels->{should});
    }
  }; # $check_deprecated
                        
  if ($Registry->{grandfathered}->{$tag_s}) {
    ## NOTE: This is a registered grandfathered tag.

    ## NOTE: Some grandfathered tags conform to the new syntax (so
    ## that $tag_o->{grandfathered} is undef) but still not
    ## grandfathered, since extended langauge is currently not
    ## registered at all.

    $check_case->('grandfathered', $tag_s_orig,
                  $Registry->{grandfathered}->{$tag_s}->{_canon});
    $check_deprecated->('grandfathered', $tag_s_orig,
                        $Registry->{grandfathered}->{$tag_s});

    if ($self->{RFC5646} and $tag_s eq 'i-default') {
      ## RFC 5646 4.1.
      $self->onerror->(type => 'langtag:grandfathered:i-default',
                 value => $tag_o->{grandfathered},
                 level => $Levels->{should});
    }
  } elsif (defined $tag_o->{grandfathered}) {
    ## NOTE: The language tag does conform to the |grandfathered|
    ## syntax, but it is not a registered tag.  Though it might be
    ## valid under the RFC 3066's rule, it is not valid according to
    ## RFC 4646.

    ## NOTE: RFC 4646 2.9. ("validating" processor MUST check)
    $self->onerror->(type => 'langtag:grandfathered:invalid',
               value => $tag_o->{grandfathered},
               level => $Levels->{langtag_fact});
    delete $result->{valid};
  } else {
    ## NOTE: We ignore illegal subtags for the purpose of validation
    ## in this case.

    if ($Registry->{redundant}->{$tag_s}) {
      ## NOTE: This is a registered redundant tag.

      ## NOTE: We assume that the consistency of the registry is kept,
      ## such that any subtag of a registered redundant tag is valid,
      ## and therefore we don't have to check the validness of subtags
      ## and 'Preferred-Value' and 'Deprecated' field values and casing
      ## in the 'Tag' field are synced with those of the subtags.
      
      $check_case->('redundant', $tag_s_orig,
                    $Registry->{redundant}->{$tag_s}->{_canon});      
      $check_deprecated->('redundant', $tag_s_orig,
                          $Registry->{redundant}->{$tag_s});      
    }

    {
      ## NOTE: We don't raise non-recommended-case error for invalid
      ## tags (with no strong preference; we might change the behavior
      ## if it seems better).

      my $lang = $tag_o->{language};
      if (defined $tag_o->{language}) {
        $lang =~ tr/A-Z/a-z/;
        if ($Registry->{language}->{$lang}) {
          ## NOTE: This is a registered language subtag.
          
          $check_case->('language', $tag_o->{language},
                        $Registry->{language}->{$lang}->{_canon});
          $check_deprecated->('language', $tag_o->{language},
                              $Registry->{language}->{$lang});

          if ($lang =~ /\Aq[a-t][a-z]\z/) {
            $self->onerror->(type => 'langtag:language:private',
                       value => $tag_o->{language},
                       level => $Levels->{warn});
          } elsif ($lang eq 'und') {
            ## NOTE: SHOULD NOT (RFC 4646 4.1. 4.)
            $self->onerror->(type => 'langtag:language:und',
                       level => $Levels->{should});
          } elsif ($lang eq 'mul') {
            ## NOTE: SHOULD NOT (RFC 4646 4.1. 5.)
            $self->onerror->(type => 'langtag:language:mul',
                       level => $Levels->{should});
          } elsif ($lang eq 'mis') {
            ## NOTE: SHOULD NOT (RFC 5646 4.1.)
            $self->onerror->(type => 'langtag:language:mis',
                       level => $Levels->{should})
                if $self->{RFC5646};
          }
        } else {
          ## NOTE: RFC 4646 2.9. ("validating" processor MUST check)
          ## NOTE: Strictly speaking, RFC 4646 2.9. speaks for "language
          ## subtag[s]" and what is that is unclear.  From the context,
          ## we assume that it referes to primary and extended language
          ## subtags.
          $self->onerror->(type => 'langtag:language:invalid',
                     value => $tag_o->{language},
                     level => $self->{RFC5646} ? $Levels->{must} : $Levels->{langtag_fact});
          delete $result->{valid};
        }
      } else {
        ## NOTE: If $tag_o is an output of the method
        ## |parse_rfc4646_tag|, then @{$tag_o->{privateuse}} is true
        ## in this case.  If $tag_o is not an output of that method,
        ## then it might not be true, but we don't support such a
        ## case.
        
        $lang = ''; # for later use.
      }
      
      my $i_extlang = 0;
      for my $extlang_orig (@{$tag_o->{extlang}}) {
        if ($self->{RFC5646} and $i_extlang) {
          ## RFC 5646 2.2.2.
          $self->onerror->(type => 'langtag:extlang:invalid',
                     value => $extlang_orig,
                     level => $Levels->{must});
          delete $result->{valid};
          next;
        }

        my $extlang = $extlang_orig;
        $extlang =~ tr/A-Z/a-z/;
        if ($Registry->{extlang}->{$extlang}) {
          ## NOTE: This is a registered extended language subtag.
          
          my $prefixes = $Registry->{extlang}->{$extlang}->{Prefix};
          if ($prefixes and defined $prefixes->[0]) {
            ## NOTE: There is exactly one prefix (RFC 4646 2.2.2.).
            if ($tag_s =~ /^\Q$prefixes->[0]\E-/) {
              #
            } else {
              ## NOTE: RFC 4646 2.2.2. (MUST), RFC 4646
              ## 2.9. ("validating" processor MUST check), RFC 4646
              ## 4.1. (SHOULD)
              $self->onerror->(type => 'langtag:extlang:prefix',
                               text => $prefixes->[0],
                               value => $extlang,
                               level => $Levels->{must});
              delete $result->{valid} unless $self->{RFC5646};
            }
          }

          $check_case->('extlang', $extlang_orig,
                        $Registry->{extlang}->{$extlang}->{_canon});
          $check_deprecated->('extlang', $extlang_orig,
                              $Registry->{extlang}->{$extlang});
        } else {
          ## NOTE: RFC 4646 2.9. ("validating" processor MUST check)
          ## NOTE: Strictly speaking, RFC 4646 2.9. speaks for "language
          ## subtag[s]" and what is that is unclear.  From the context,
          ## we assume that it referes to primary and extended language
          ## subtags.
          $self->onerror->(type => 'langtag:extlang:invalid',
                     value => $extlang_orig,
                     level => $self->{RFC5646}
                         ? $Levels->{must} : $Levels->{langtag_fact});
          delete $result->{valid};
        }
        $i_extlang++;
      } # extlang
      
      if (defined $tag_o->{script}) {
        my $script = $tag_o->{script};
        $script =~ tr/A-Z/a-z/;
        if ($Registry->{script}->{$script}) {
          ## NOTE: This is a registered script subtag.
          
          $check_case->('script', $tag_o->{script},
                        $Registry->{script}->{$script}->{_canon});
          $check_deprecated->('script', $tag_o->{script},
                              $Registry->{script}->{$script});

          ## NOTE: RFC 4646 2.2.3. "SHOULD be omitted (1) when it adds
          ## no distinguishing value to the tag or (2) when
          ## ... Suppress-Script".  (1) is semantic requirement that
          ## we cannot check against.  SHOULD NOT (RFC 4646 3.1.),
          ## SHOULD (RFC 4646 4.1.) "SHOULD NOT be used to form
          ## language tags unless the script adds some distinguishing
          ## information to the tag" (RFC 4646 4.1. 2.)
          if ($Registry->{language}->{$lang} and
              defined $Registry->{language}->{$lang}->{_suppress} and
              $Registry->{language}->{$lang}->{_suppress} eq $script) {
            $self->onerror->(type => 'langtag:script:suppress',
                       text => $lang,
                       value => $tag_o->{script},
                       level => $Levels->{should});
          }

          if ($script =~ /\Aqa(?>a[a-z]|b[a-x])\z/) {
            $self->onerror->(type => 'langtag:script:private',
                       value => $tag_o->{script},
                       level => $Levels->{warn});
          }
        } else {
          ## NOTE: RFC 4646 2.9. ("validating" processor MUST check)
          $self->onerror->(type => 'langtag:script:invalid',
                     value => $tag_o->{script},
                     level => $self->{RFC5646} ? $Levels->{must} : $Levels->{langtag_fact});
          delete $result->{valid};
        }
      }
      
      if (defined $tag_o->{region}) {
        my $region = $tag_o->{region};
        $region =~ tr/A-Z/a-z/;
        if ($Registry->{region}->{$region}) {
          ## NOTE: This is a registered region subtag.
          
          $check_case->('region', $tag_o->{region},
                        $Registry->{region}->{$region}->{_canon});
          $check_deprecated->('region', $tag_o->{region},
                              $Registry->{region}->{$region});

          if ($region =~ /\A(?>aa|q[m-z]|x[a-z]|zz)\z/) {
            $self->onerror->(type => 'langtag:region:private',
                       value => $tag_o->{region},
                       level => $Levels->{warn});
          }
        } else {
          ## NOTE: RFC 4646 2.2.4. 3. B. "UN numeric codes for
          ## 'economic groupings' or 'other groupings' ... MUST NOT be
          ## used", RFC 4646 2.2.4. 3. D. "UN numeric codes for
          ## countries or areas for which ... ISO 3166 alpha-2 code
          ## ... MUST NOT be used", RFC 4646 2.2.4. 3. F. "All other
          ## UN numeric codes for countries or areas that do not
          ## ... ISO 3166 alpha-2 code ... MUST NOT be used", RFC 4646
          ## 2.2.4. 4. Note "Alphanumeric codes in Appendix X ... MUST
          ## NOT be used", RFC 4646 2.9. ("validating" processor MUST
          ## check)
          $self->onerror->(type => 'langtag:region:invalid',
                     value => $tag_o->{region},
                     level => $self->{RFC5646} ? $Levels->{must} : $Levels->{langtag_fact});
          delete $result->{valid};
        }
      }

      my @prev_variant;
      my %prev_variant;
      my $last_unprefixed_variant;
      for my $variant_orig (@{$tag_o->{variant}}) {
        my $variant = $variant_orig;
        $variant =~ tr/A-Z/a-z/;
        if ($Registry->{variant}->{$variant}) {
          ## NOTE: This is a registered variant language subtag.

          my $prefixes = $Registry->{variant}->{$variant}->{Prefix} || [];
          my @longer_prefix;
          if (@$prefixes) {
            if ($self->{RFC5646} and defined $last_unprefixed_variant) {
              $self->onerror->(type => 'langtag:variant:order',
                         text => $variant,
                         value => $last_unprefixed_variant,
                         level => $Levels->{should});
            }

            HAS_PREFIX: {
              ## NOTE: @$prefixes is sorted by reverse order of
              ## lengths.
              
              my $tag = join '-', grep { defined $_ }
                  $tag_o->{language},
                  @{$tag_o->{extlang} or []},
                  $tag_o->{script},
                  $tag_o->{region},
                  @prev_variant;
              for my $prefix_s (@$prefixes) {
                if ($self->extended_filtering_rfc4647_range
                        ($prefix_s, $tag)) {
                  last HAS_PREFIX;
                } else {
                  push @longer_prefix, $prefix_s;
                }
              }
              
              ## NOTE: RFC 4646 2.9. ("validating" processor MUST
              ## check) and RFC 4646 4.1. (SHOULD)
              $self->onerror->(type => 'langtag:variant:prefix',
                         text => (join '|', @$prefixes),
                         value => $variant,
                         level => $Levels->{should});
              delete $result->{valid} unless $self->{RFC5646};
            } # HAS_PREFIX
            if ($self->{RFC5646} and @longer_prefix and @longer_prefix != @$prefixes) {
              my $tag = join '-', grep { defined $_ }
                    $tag_o->{language},
                    @{$tag_o->{extlang} or []},
                    $tag_o->{script},
                    $tag_o->{region},
                    @{$tag_o->{variant} or []};
              for my $prefix_s (@longer_prefix) {
                ## RFC 5646 4.1. Variant subtag ordering requirement
                if ($self->extended_filtering_rfc4647_range
                        ($prefix_s, $tag)) {
                  $self->onerror->(type => 'langtag:variant:order',
                             text => $prefix_s,
                             value => $variant,
                             level => $Levels->{should});
                }
              }
            }
          } else { # @$prefixes
            ## RFC 5646 4.1. Variant subtag ordering requirement
            if ($self->{RFC5646} and defined $last_unprefixed_variant) {
              if (($variant cmp $last_unprefixed_variant) < 0) {
                $self->onerror->(type => 'langtag:variant:order',
                           text => $variant,
                           value => $last_unprefixed_variant,
                           level => $Levels->{should});
              }
            }
            $last_unprefixed_variant = $variant;
          } # @$prefixes

          $check_case->('variant', $variant_orig,
                        $Registry->{variant}->{$variant}->{_canon});
          $check_deprecated->('variant', $variant_orig,
                              $Registry->{variant}->{$variant});

          if ($prev_variant{$variant}) {
            ## A variant subtag SHOULD only be used at most once in a
            ## tag (RFC 4646 4.1. 6.)
            $self->onerror->(type => 'langtag:variant:duplication',
                       value => $variant_orig,
                       level => $Levels->{should});
            delete $result->{valid};
          } elsif (($variant eq '1996' and $prev_variant{1901}) or
                   ($variant eq '1901' and $prev_variant{1996})) {
            ## RFC 4646 2.2.5. shows '1996' and '1901' as a bad
            ## example and says that they SHOULD NOT be used together.
            $self->onerror->(type => 'langtag:variant:combination',
                       text => $variant_orig,
                       value => $variant eq '1901' ? '1996' : '1901',
                       level => $Levels->{should});
          }
        } else {
          ## NOTE: RFC 4646 2.9. ("validating" processor MUST check)
          $self->onerror->(type => 'langtag:variant:invalid',
                     value => $variant_orig,
                     level => $self->{RFC5646}
                                  ? $Levels->{must}
                                  : $Levels->{langtag_fact});
          delete $result->{valid};
        }
        push @prev_variant, $variant_orig;
        $prev_variant{$variant} = 1;
      }

      my $max_ext = 0x00;
      my %has_ext;
      for my $ext (@{$tag_o->{extension}}) {
        my $ext_type = $ext->[0];
        $ext_type =~ tr/A-Z/a-z/;
        $self->onerror->(type => 'langtag:extension:unknown',
                   value => (join '-', @{$ext}),
                   level => $Levels->{langtag_fact})
            unless $ext_type eq 'u' or $ext_type eq 't';
        
        ## NOTE: "When a language tag is to be used in a specific,
        ## known, protocol, it is RECOMMENDED that the language tag
        ## not contain extensions not supported by that protocol."
        ## (RFC 4646 3.7.) - We don't check this as we don't know
        ## where the language tag is used.  (In fact we don't want to
        ## implement this kind of meaningless requirement.  Any tag
        ## not supported by a particular system (not restricted to
        ## extensions) should not be used for the document or protocol
        ## specifically targetted for the system cannot be used, but
        ## making it a conformance requirement does not contribute to
        ## interoperability.)

        if ($max_ext > ord $ext_type) {
          ## NOTE: "=" is excluded, since duplicate extension subtags
          ## are checked at the parse time.

          ## NOTE: SHOULD be canonicalized (RFC 4646 2.2.6. 11.).  A
          ## language tag SHOULD be canonicalized, and to be canonical
          ## extension tags SHOULD be ordered in ASCII order (RFC 4646
          ## 4.4. 5.).
          $self->onerror->(type => 'langtag:extension:order',
                     text => chr $max_ext, # $max_ext != 0x00
                     value => $ext->[0],
                     level => $Levels->{should});
        } else {
          if ($has_ext{$ext_type}) {
            delete $result->{well_formed} unless $self->{RFC5646};
            delete $result->{valid};
          }
          $max_ext = ord $ext_type;
          $has_ext{$ext_type} = 1;
        }

        ## NOTE: We don't check whether the case is lowercase or not
        ## for unknown extensions (see note above on the case of
        ## invalid subtags).
        if ($ext_type eq 'u' or $ext_type eq 't') {
          ## The "u" extension (UTS #35 and RFC 6067)
          for (@{$ext}[1..$#$ext]) {
            if (/[A-Z]/) {
              $self->onerror->(type => 'langtag:extension:'.$ext_type.':case',
                         value => $_,
                         level => $Levels->{warn}); # Canonical form
            }
          }
        }
      }

      ## The "u" extension (UTS #35 and RFC 6067)
      if ($tag_o->{u}) {
        my $prev = '';
        for (0..$#{$tag_o->{u}->[0]}) {
          my $attr = $tag_o->{u}->[0]->[$_];
          $attr =~ tr/A-Z/a-z/;
          if (($prev cmp $attr) > 0) {
            $self->onerror->(type => 'langtag:extension:u:attr:order',
                       text => $prev,
                       value => $attr,
                       level => $Levels->{warn}); # Canonical form
          }
          $prev = $attr;

          ## At the moment attribute is not used at all.
          $self->onerror->(type => 'langtag:extension:u:attr:invalid',
                     value => $attr,
                     level => $Levels->{langtag_fact});
          delete $result->{valid} unless $self->{RFC5646};
        }

        $prev = '';
        for (1..$#{$tag_o->{u}}) {
          my $keyword = $tag_o->{u}->[$_];
          my $key = $keyword->[0];
          $key =~ tr/A-Z/a-z/;
          if (($prev cmp $key) > 0) {
            $self->onerror->(type => 'langtag:extension:u:key:order',
                       text => $prev,
                       value => $key,
                       level => $Levels->{warn}); # Canonical form
          }
          $prev = $key;

          if ($Registry->{u_key}->{$key}) {
            my $vt = $Registry->{u_key}->{$key}->{_value_type} || '';
            if ($vt eq 'CODEPOINTS') {
              ## UTS #35 Appendix Q.
              if (not defined $keyword->[1]) {
                $self->onerror->(type => 'langtag:extension:u:type:missing',
                                 text => $key,
                                 level => $Levels->{langtag_fact});
                delete $result->{valid} unless $self->{RFC5646};
              }

              for (@$keyword[1..$#$keyword]) {
                next unless defined;
                if (not /\A[0-9A-Fa-f]{4,6}\z/ or 0x10FFFF < hex) {
                  $self->onerror->(type => 'langtag:extension:u:type:invalid',
                                   text => $key,
                                   value => $_,
                                   level => $Levels->{langtag_fact}); # may
                  delete $result->{valid} unless $self->{RFC5646};
                }
              }
            } elsif ($vt eq 'REORDER_CODE') {
              ## UTS #35 Appendix Q.
              my %used;
              for (@$keyword[1..$#$keyword]) {
                my $type = $_;
                $type =~ tr/A-Z/a-z/;
                if ($used{$type}) {
                  $self->onerror->(type => 'langtag:extension:u:type:duplication',
                                   text => $key,
                                   value => $_,
                                   level => $Levels->{langtag_fact}); ## UTS #35
                  delete $result->{valid} unless $self->{RFC5646};
                } else {
                  my $def = $Registry->{'u_' . $key}->{$type};
                  $used{$type} = 1;
                  if (not defined $def) {
                    $self->onerror->(type => 'langtag:extension:u:type:invalid',
                                     text => $key,
                                     value => $type,
                                     level => $Levels->{langtag_fact});
                    delete $result->{valid} unless $self->{RFC5646};
                  } elsif ($def->{_deprecated}) {
                    $self->onerror->(type => 'langtag:extension:u:type:deprecated',
                                     text => $def->{_preferred}, # might be undef
                                     value => $type,
                                     level => 'w');
                  }
                }
              }
            } else { # $vt
              my $type = join '-', @$keyword[1..$#$keyword];
              $type =~ tr/A-Z/a-z/;
              if (not length $type) {
                if ($Registry->{'u_' . $key}->{true}) { ## Has |true| value
                  #
                } else {
                  ## Semantics is not defined anywhere
                  $self->onerror->(type => 'langtag:extension:u:type:missing',
                                   text => $key,
                                   level => $Levels->{langtag_fact});
                  delete $result->{valid} unless $self->{RFC5646};
                }
              } elsif (my $def = $Registry->{'u_' . $key}->{$type}) {
                if ($def->{_deprecated}) {
                  $self->onerror->(type => 'langtag:extension:u:type:deprecated',
                                   text => $def->{_preferred}, # might be undef
                                   value => $type,
                                   level => 'w');
                }
              } else {
                $self->onerror->(type => 'langtag:extension:u:type:invalid',
                                 text => $key,
                                 value => $type,
                                 level => $Levels->{langtag_fact});
                delete $result->{valid} unless $self->{RFC5646};
              }
            } # $vt
          } else {
            $self->onerror->(type => 'langtag:extension:u:key:invalid',
                       value => $key,
                       level => $Levels->{langtag_fact});
            delete $result->{valid} unless $self->{RFC5646};
          }
        }

        ## According to RFC 4646 (but not in RFC 5646), if a language
        ## tag contains an extension which is not valid, the entire
        ## language tag is invalid.  However, for the "u" extension
        ## validity is not clearly defined.
      } # 'u'

      if ($tag_o->{t}) {
        my @t = @{$tag_o->{t}};
        my $langtag = shift @t;
        if (defined $langtag) {
          my $serialized = $self->serialize_parsed_tag ($langtag);
          $serialized =~ tr/A-Z/a-z/;
          if ({'en-gb-oed' => 1,
               'sgn-be-fr' => 1,
               'sgn-be-nl' => 1,
               'sgn-ch-de' => 1}->{$serialized}) {
            $self->onerror->(type => 'langtag:extension:t:irregular',
                             value => $serialized,
                             level => $Levels->{must}); # RFC 6497
            delete $result->{valid} unless $self->{RFC5646};
          } else {
            my $r = $self->check_rfc4646_parsed_tag
                ($langtag, ignore_case => 1);
            delete $result->{valid}
                if not $self->{RFC5646} and
                    (not $r->{well_formed} or not $r->{valid} or
                     $langtag->{grandfathered} or
                     $self->canonicalize_rfc5646_tag ($serialized) ne $serialized);
          }
        }

        while (@t) {
          my $t = shift @t;
          my $field = [@$t];
          my $field_sep = shift @$field;
          $field_sep =~ tr/A-Z/a-z/;
          if ($Registry->{t_key}->{$field_sep}) {
            my $value = join '-', @$field;
            $value =~ tr/A-Z/a-z/;
            if ($Registry->{'t_' . $field_sep}->{$value}) {
              #
            } elsif ($field_sep eq 'x0') {
              if (grep { not /\A[0-9A-Za-z]{3,8}\z/ } @$field) {
                $self->onerror->(type => 'langtag:extension:t:field:value:invalid',
                                 text => $field_sep,
                                 value => $value,
                                 level => $Levels->{langtag_fact});
                delete $result->{valid} unless $self->{RFC5646};
              }
            } else {
              $self->onerror->(type => 'langtag:extension:t:field:value:invalid',
                               text => $field_sep,
                               value => $value,
                               level => $Levels->{langtag_fact});
              delete $result->{valid} unless $self->{RFC5646};
            }
          } else {
            $self->onerror->(type => 'langtag:extension:t:field:invalid',
                             value => $field_sep,
                             level => $Levels->{langtag_fact});
            delete $result->{valid} unless $self->{RFC5646};
            delete $result->{valid} if not $self->{RFC5646} and
                grep { not /\A[0-9A-Za-z]{3,8}\z/ } @$field;
          }
        }

        ## According to RFC 4646 (but not in RFC 5646), if a language
        ## tag contains an extension which is not valid, the entire
        ## language tag is invalid.  However, for the "t" extension
        ## validity is not clearly defined.
      } # 't'

      if (@{$tag_o->{privateuse}}) {
        ## NOTE: "NOT RECOMMENDED where alternative exist or for
        ## general interchange" (RFC 4646 2.2.7. 6. (RECOMMENDED),
        ## 4.5. (SHOULD NOT)).  Whether alternative exist or not
        ## cannot be detected by the checker (unless providing some
        ## "well-known" private use tag list).  However, the latter
        ## condition should in most case be met (except for internal
        ## uses).
        $self->onerror->(type => 'langtag:privateuse',
                   value => (join '-', @{$tag_o->{privateuse}}),
                   level => $Levels->{should});

        for (@{$tag_o->{privateuse}}) {
          if (/\A[^A-Z]\z/ or
              /\A[^a-z]{2}\z/ or
              /\A[^A-Z]{3}\z/ or
              /\A[^a-z][^A-Z]{3}\z/ or
              /\A[^A-Z]{5,}\z/) {
            #
          } else {
            ## NOTE: RECOMMENDED (RFC 4646 2.1.)
            $self->onerror->(type => 'langtag:privateuse:case',
                             value => $_,
                             level => $Levels->{should});
          }
        }
      }

      ## NOTE: Case of illegal subtags are not checked (see note above
      ## on the case of invalid subtags).
    }
  }

  return $result;
} # check_rfc4646_parsed_tag

# Compat
*check_rfc3066_language_tag = \&check_rfc3066_tag;

sub check_rfc3066_tag ($$) {
  my ($self, $tag) = @_;
  
  my @tag = split /-/, $tag, -1;

  require Web::LangTag::_List;
  our $Registry;

  if (not $self->{RFC1766} and $tag[0] =~ /\A[0-9]+\z/) {
    $self->onerror->(type => 'langtag:illegal',
               value => $tag[0],
               level => $Levels->{langtag_fact});
  }

  for (@tag) {
    unless (/\A[A-Za-z0-9]{1,8}\z/) {
      $self->onerror->(type => 'langtag:illegal',
                 value => $_,
                 level => $Levels->{langtag_fact});
    } elsif ($self->{RFC1766} and /[0-9]/) {
      $self->onerror->(type => 'langtag:illegal',
                 value => $_,
                 level => $Levels->{langtag_fact});
    }
  }

  if ($tag[0] =~ /\A[A-Za-z]{2}\z/) {
    if ($tag[0] =~ /[A-Z]/) {
      $self->onerror->(type => 'langtag:language:case',
                 value => $tag[0],
                 level => $Levels->{good});
    }

    my $lang = $tag[0];
    $lang =~ tr/A-Z/a-z/;
    unless ($Registry->{language}->{$lang}) {
      ## ISO 639-1 language tag
      $self->onerror->(type => 'langtag:language:invalid',
                 value => $tag[0],
                 level => $Levels->{langtag_fact});
    }
  } elsif (not $self->{RFC1766} and $tag[0] =~ /\A[A-Za-z]{3}\z/) {
    if ($tag[0] =~ /[A-Z]/) {
      $self->onerror->(type => 'langtag:language:case',
                 value => $tag[0],
                 level => $Levels->{good}); # Recommendation of source stds
    }

    my $lang = $tag[0];
    $lang =~ tr/A-Z/a-z/;
    unless ($Registry->{language}->{$lang}) {
      ## - ISO 639-2 language tag (fact)
      ## - Prefer 2-letter code, if any (MUST)
      ## - Prefer /T code to /B code, if any (MUST)
      $self->onerror->(type => 'langtag:language:invalid',
                 value => $tag[0],
                 level => $Levels->{langtag_fact});
    } elsif ($lang eq 'und') {
      $self->onerror->(type => 'langtag:language:und',
                 level => $Levels->{should});
    } elsif ($lang eq 'mul') {
      $self->onerror->(type => 'langtag:language:mul',
                 level => $Levels->{should});
    } elsif ($lang =~ /\Aq[a-t][a-z]\z/) {
      $self->onerror->(type => 'langtag:language:private',
                 value => $tag[0],
                 level => $Levels->{warn});
    }
  } elsif ($tag[0] =~ /\A[Ii]\z/) {
    #
  } elsif ($tag[0] =~ /\A[Xx]\z/) {
    $self->onerror->(type => 'langtag:private',
               value => $tag,
               level => $Levels->{good});
  } else {
    $self->onerror->(type => 'langtag:language:nosemantics',
               value => $tag[0],
               level => $Levels->{langtag_fact});
  }

  if (@tag >= 2 and
      ## This is a willful violation to RFC 1766/3066, although it
      ## seems that the actual intention of these specifications is
      ## how it is implemented here:
      $tag[0] !~ /\A[IiXx]\z/) {
    if ($tag[1] =~ /\A[0-9A-Za-z]{2}\z/) {
      if ($tag[1] =~ /[a-z]/) {
        $self->onerror->(type => 'langtag:region:case',
                   value => $tag[1],
                   level => $Levels->{good}); # Recommendation of source stds
      }
      if ($tag[1] =~ /\A(?>[Aa][Aa]|[Qq][M-Zm-z]|[Xx][A-Za-z]|[Zz][Zz])\z/) {
        $self->onerror->(type => 'langtag:region:private',
                   value => $tag[1],
                   level => $self->{RFC1766}
                       ? $Levels->{warn} : $Levels->{must}); # RFC 3066 2.2.
      } elsif ($tag[1] =~ /\A([A-Za-z]{2})\z/) {
        my $region = $1;
        $region =~ tr/A-Z/a-z/;
        unless ($Registry->{region}->{$region}) {
          ## ISO 3166 country code (fact)
          $self->onerror->(type => 'langtag:region:invalid',
                     value => $tag[1],
                     level => $Levels->{langtag_fact});
        }
      }
    } elsif (length $tag[1] == 1) {
      $self->onerror->(type => 'langtag:region:nosemantics', 
                 value => $tag[1],
                 level => $Levels->{langtag_fact});
    }
  }

  if (($tag[0] eq 'i' or $tag[0] eq 'I' or
       @tag >= 3 or
       (@tag == 2 and 3 <= length $tag[1])) and
      not $tag[0] eq 'x' and
      not $tag[0] eq 'X') {
    my $tag_l = $tag;
    $tag_l =~ tr/A-Z/a-z/;
    my $def = $Registry->{grandfathered}->{$tag_l} ||
        $Registry->{redundant}->{$tag_l};
    if ($def) {
      if ($def->{_deprecated}) {
        my $level = $Levels->{warn};
        ## MUST use ISO tag rather than i-* tag (RFC 3066 2.3)
        $level = $Levels->{must}
            if not $self->{RFC1766} and
               $tag_l =~ /^i-/ and
               $def->{_preferred} and
               $def->{_preferred} =~ /^[A-Za-z]{2,3}$/;
        $self->onerror->(type => 'langtag:deprecated',
                   text => $def->{_preferred}, # or undef
                   value => $tag,
                   level => $level);
      }
    } else {
      $self->onerror->(type => 'langtag:notregistered',
                 value => $tag,
                 level => $tag_l =~ /^i-/
                     ? $Levels->{langtag_fact} : $Levels->{warn});
    }
  }
  return {};
} # check_rfc3066_tag

sub check_rfc1766_tag ($$) {
  local $_[0]->{RFC1766} = 1;
  return shift->check_rfc3066_tag (@_);
} # check_rfc1766_tag

# ------ Normalization ------

*normalize_tag = \&normalize_rfc5646_tag;

## Note: RFC 5646 2.1., 2.2.6.
sub normalize_rfc5646_tag ($$) {
  my @tag = map { tr/A-Z/a-z/; $_ } split /-/, $_[1], -1;
  my $in_extension;
  for my $i (1..$#tag) {
    if (1 == length $tag[$i - 1]) {
      if ($tag[$i - 1] ne 'x' and $tag[$i - 1] ne 'i') {
        last;
      }
    } elsif ($tag[$i] =~ /\A(..)\z/s) {
      $tag[$i] =~ tr/a-z/A-Z/;
    } elsif ($tag[$i] =~ /\A([a-z])(.{3})\z/s) {
      $tag[$i] = (uc $1) . $2;
    }
  }
  return join '-', @tag;
} # normalize_rfc5646_tag

*canonicalize_tag = \&canonicalize_rfc5646_tag;

sub canonicalize_rfc5646_tag ($$) {
  my ($self, $tag) = @_;
  $tag = '' unless defined $tag;

  my $tag_l = $tag;
  $tag_l =~ tr/A-Z/a-z/;

  require Web::LangTag::_List;
  our $Registry;

  my $def = $Registry->{grandfathered}->{$tag_l}
      || $Registry->{redundant}->{$tag_l};
  if ($def) {
    if (defined $def->{_preferred}) {
      return $def->{_preferred};
    } else {
      return $tag;
    }
  }

  my $parsed_tag = $self->parse_rfc5646_tag ($tag);
  return $tag unless defined $parsed_tag->{language};

  ## If there are more than one extlang subtags (non-conforming), the
  ## spec does not define how to canonicalize the tag.
  if (@{$parsed_tag->{extlang}} == 1) {
    my $subtag = $parsed_tag->{extlang}->[0];
    $subtag =~ tr/A-Z/a-z/;
    my $def = $Registry->{extlang}->{$subtag};
    if ($def and defined $def->{_preferred}) {
      $parsed_tag->{language} = $def->{_preferred};
      @{$parsed_tag->{extlang}} = ();
    }
  }

  for (qw(language script region)) {
    my $subtag = $parsed_tag->{$_};
    if (defined $subtag) {
      $subtag =~ tr/A-Z/a-z/;
      my $def = $Registry->{$_}->{$subtag};
      if ($def and defined $def->{_preferred}) {
        $parsed_tag->{$_} = $def->{_preferred};
      }
    }
  }

  for (0..$#{$parsed_tag->{variant}}) {
    my $subtag = $parsed_tag->{variant}->[$_];
    $subtag =~ tr/A-Z/a-z/;
    my $def = $Registry->{variant}->{$subtag};
    if ($def and defined $def->{_preferred}) {
      $parsed_tag->{variant}->[$_] = $def->{_preferred};
    }
  }

  $parsed_tag->{extension} = [sort { (ord lc $a->[0]) <=> (ord lc $b->[0]) } @{$parsed_tag->{extension}}];

  return $self->serialize_parsed_tag ($parsed_tag);
} # canonicalize_rfc5646_tag

*to_extlang_form_tag = \&to_extlang_form_rfc5646_tag;

sub to_extlang_form_rfc5646_tag ($$) {
  my $tag = $_[0]->canonicalize_rfc5646_tag ($_[1]);
  if ($tag =~ /^([A-Za-z]{3})(?=-|$)(?!-[A-Za-z]{3}(?=-|$))/) {
    my $subtag = $1;
    $subtag =~ tr/A-Z/a-z/;
    
    require Web::LangTag::_List;
    our $Registry;
    
    my $def = $Registry->{extlang}->{$subtag};
    if ($def and @{$def->{Prefix} or []}) {
      return $def->{Prefix}->[0] . '-' . $tag;
    }
  }
  return $tag;
} # to_extlang_form_rfc5646_tag

# ------ Comparison ------

*basic_filtering_range = \&basic_filtering_rfc4647_range;

*match_rfc3066_range = \&basic_filtering_rfc4647_range;

sub basic_filtering_rfc4647_range ($$$) {
  my (undef, $range, $tag) = @_;
  $range = '' unless defined $range;
  $tag = '' unless defined $tag;

  return 1 if $range eq '*';
  
  $range =~ tr/A-Z/a-z/;
  $tag =~ tr/A-Z/a-z/;
  
  return $range eq $tag || $tag =~ /^\Q$range\E-/;
} # basic_filtering_rfc4647_range

*extended_filtering_range = \&extended_filtering_rfc4647_range;

sub extended_filtering_rfc4647_range ($$$) {
  my (undef, $range, $tag) = @_;
  $range = '' unless defined $range;
  $tag = '' unless defined $tag;

  $range =~ tr/A-Z/a-z/;
  $tag =~ tr/A-Z/a-z/;
  
  ## 1.
  my @range = split /-/, $range, -1;
  my @tag = split /-/, $tag, -1;

  push @range, '' unless @range;
  push @tag, '' unless @tag;
  
  ## 2.
  unless ($range[0] eq '*' or $range[0] eq $tag[0]) {
    return 0;
  } else {
    shift @range;
    shift @tag;
  }
  
  ## 3.
  while (@range) {
    if ($range[0] eq '*') {
      ## A.
      shift @range;
      next;
    } elsif (not @tag) {
      ## B.
      return 0;
    } elsif ($range[0] eq $tag[0]) {
      ## C.
      shift @range;
      shift @tag;
      next;
    } elsif (1 == length $tag[0]) {
      ## D.
      return 0;
    } else {
      ## E.
      shift @tag;
      next;
    }
  } # @range

  return !@range;
} # extended_filtering_rfc4647_range

# ------ Tag registry data ------

*tag_registry_data = *tag_registry_data_rfc5646 = \&tag_registry_data_rfc4646;

sub tag_registry_data_rfc4646 ($$$) {
  my (undef, $type, $tag) = @_;
  $type =~ tr/A-Z/a-z/;
  $tag =~ tr/A-Z/a-z/;

  require Web::LangTag::_ListFull;
  our $RegistryFull;

  return $RegistryFull->{$type} ? $RegistryFull->{$type}->{$tag} : undef;
} # tag_registry_data_rfc4646

1;

=head1 LICENSE

Copyright 2007-2014 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
