package Net::Abuse::Report;

# transport-agnostic storage class for one "incident"

use 5.018;
use utf8;

sub new {
    my $class = shift;
    my %args = @_;
    return bless \%args => (ref($class) || $class);
}

sub best_guess {
    my $self = shift;
    return $self->ranked_guess_ref->[ 0 ];
}

sub ranked_guess_ref {
    my $self = shift;
    my $scored_guess_ref = { };
    $scored_guess_ref = eval { $self->{ reader_class }->ranked_guess_ref() } if eval { $self->{ reader_class }->can('ranked_guess_ref') };
    $scored_guess_ref = { %$scored_guess_ref, malware => 100 }; # FIXME more here
    my $ranked_guess_ref = [
        map { $_->[ 1 ] }
        sort { $a->[ 0 ] <=> $b->[ 0 ] }
        map { [ $scored_guess_ref->{ $_ }, $_ ] }
        keys %{$scored_guess_ref}
    ];
    return $ranked_guess_ref;
}

1;
