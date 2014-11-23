package Net::Abuse::Reporter::Reader::CLF;

use 5.018;
use utf8;

use DateTime::Format::Strptime;

use base qw( Net::Abuse::Reporter::Reader );

our $CLF_FORMAT = DateTime::Format::Strptime->new(
    pattern => '%d/%b/%Y:%H:%M:%S %z',
    locale => 'en_US',
);

sub parse {
    # 127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    # TODO Also allow optional TAI64N stamp at the start, because Nginx can get funky like that
    my $self = shift;
    my ($line) = @_;
    my %rv;
    if ($line =~ qr/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(\S+)\s\[([^\]]+)\]\s("[^"]+")\s(\d+)\s(\d+)/io) {
        @rv{qw( ip identity user dt req code size ) } = ($1, $2, $3, $4, $5, $6, $7);
    }
    elsif ($line =~ qr/^([0-9a-f:]{2,})\s(\S+)\s(\S+)\s\[([^\]]+)\]\s("[^"]+")\s(\d+)\s(\d+)/io) {
        @rv{qw( ip identity user dt req code size ) } = ($1, $2, $3, $4, $5, $6, $7);
    }
    return \%rv;
}

sub _normalize_special {
    my $rv = shift;
    $rv->{ epoch } = $CLF_FORMAT->parse_datetime(delete $rv->{ dt })->epoch;
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
