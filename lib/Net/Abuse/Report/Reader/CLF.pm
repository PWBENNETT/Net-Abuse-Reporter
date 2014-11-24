package Net::Abuse::Reporter::Reader::CLF;

use 5.018;
use utf8;

use DateTime::Format::Strptime;
use Time::TAI64 qw( :tai );

use base qw( Net::Abuse::Reporter::Reader );

our $CLF_FORMAT = DateTime::Format::Strptime->new(
    pattern => '%d/%b/%Y:%H:%M:%S %z',
    locale => 'en_US',
);

sub parse {
    # 127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    # Also allow optional multilog-style TAI64(N(A)?)? stamp at the start
    my $self = shift;
    my ($line) = @_;
    my %rv;
    if ($line =~ /^\@([0-9a-f]{16}|[0-9a-f]{24}|[0-9a-f]{32})/io) {
        my $tai = $1;
        $rv{ tai64 } = pack 'N*', map { hex $_ } split /(..)/, $tai;
        $line =~ s/^\@$tai//;
    }
    if ($line =~ qr/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(\S+)\s\[([^\]]+)\]\s("[^"]+")\s(\d+)\s(\d+)/io) {
        @rv{qw( ip identity user clf_dt req code size ) } = ($1, $2, $3, $4, $5, $6, $7);
    }
    elsif ($line =~ qr/^([0-9a-f:]{2,})\s(\S+)\s(\S+)\s\[([^\]]+)\]\s("[^"]+")\s(\d+)\s(\d+)/io) {
        @rv{qw( ip identity user clf_dt req code size ) } = ($1, $2, $3, $4, $5, $6, $7);
    }
    return \%rv;
}

sub _normalize_special {
    my $rv = shift;
    $rv->{ incident_time } = $CLF_FORMAT->parse_datetime(delete $rv->{ clf_dt })->epoch;
    $rv->{ detection_time } = $rv->{ tai64 } ? tai2unix(delete $rv->{ tai64 }) : $rv->{ incident_time };
    return $rv;
}

sub setup {
    my $self = shift;
    return $self;
}

sub new_setup_is_needed {
    my $self = shift;
    return 0;
}

sub teardown {
    my $self = shift;
    return $self;
}

1;
