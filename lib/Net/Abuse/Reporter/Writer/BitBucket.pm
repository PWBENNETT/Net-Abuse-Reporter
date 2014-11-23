package Net::Abuse::Reporter::Writer::BitBucket;

use base qw( Net::Abuse::Reporter::Writer );

sub register_as { 'bitbucket' }

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
