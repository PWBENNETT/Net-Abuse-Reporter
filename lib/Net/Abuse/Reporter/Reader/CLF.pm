package Net::Abuse::Reporter::Reader::CLF;

use 5.020;
use utf8;

use base qw( Net::Abuse::Reporter::Reader );

sub register_as { [qw( apache nginx clf )] }

sub parse {
    # 127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    # TODO Also allow optional TAI64N stamp at the start, because Nginx can get funky like that
    my $self = shift;
    my ($line) = @_;
    my %rv;
    if ($line =~ qr/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(\S+)\s(\[[^\]]+)\s("[^"]+")\s(\d+)\s(\d+)/io) {
        @rv{qw( ipv4 identity user dt req code size ) } = ($1, $2, $3, $4, $5, $6, $7);
    }
    elsif ($line =~ qr/^([0-9a-f:]{2,})\s(\S+)\s(\S+)\s(\[[^\]]+)\s("[^"]+")\s(\d+)\s(\d+)/io) {
        @rv{qw( ipv6 identity user dt req code size ) } = ($1, $2, $3, $4, $5, $6, $7);
    }
    %rv = %{$self->normalize(\%rv)};
    return \%rv;
}

sub setup {
    my $self = shift;
    return $self;
}

sub new_setup_is_needed {
    my $self = shift;
    return 0;
}

sub send {
    my $self = shift;
    return 1;
}

sub teardown {
    my $self = shift;
    return $self;
}

1;
