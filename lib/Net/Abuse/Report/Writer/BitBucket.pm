package Net::Abuse::Report::Writer::BitBucket;

use 5.018;
use utf8;

use base qw( Net::Abuse::Reporter::Writer );

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
