package Net::Abuse::Reporter;

# Master package that provides the ->new, ->add_incident, and ->send_reports methods

use 5.018;
use utf8;

sub new {
    my $class = shift;
    my %args = @_;
    $args{ reader } ||= _get_default_readers();
    $args{ writer } ||= _get_default_writers();
    return bless \%args => (ref($class) || $class);
}

sub register_reader {
    my $self = shift;
    return $self->_register('reader', @_);
}

sub register_writer {
    my $self = shift;
    return $self->_register('writer', @_);
}

sub _register {
    my $self = shift;
    my ($role, $agent_class) = @_;
    unless (ref $agent_class) {
        eval "require $agent_class" or do {
            warn $@;
            return $self;
        };
    }
    my $obj = $agent_class->new();
    eval { $obj->setup() if $obj->can('setup'); 1 } or do {
        warn $@;
        return $self;
    };
    $self->{ $role } ||= [ ];
    push @{$self->{ $role }}, $obj;
    return $self;
}

1;
