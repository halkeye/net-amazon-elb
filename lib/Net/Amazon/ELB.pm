package Net::Amazon::ELB;
use Moose;

use strict;
use vars qw($VERSION);

use XML::Simple;
use LWP::UserAgent;
use Digest::HMAC_SHA1;
use URI;
use MIME::Base64 qw(encode_base64 decode_base64);
use HTTP::Date qw(time2isoz);
use Params::Validate qw(validate SCALAR ARRAYREF);
use Data::Dumper qw(Dumper);
use URI::Escape;

$VERSION = '0.1';

=head1 NAME

Net::Amazon::ELB - Perl interface to the Amazon Elastic Load Balancing (ELB) environment.

=head1 VERSION

This document describes version 0.1 of Net::Amazon::ELB, released April 1st, 2011
This module is coded against the Query API version of the '2009-05-15' version of 
the ELB API last updated May 15th, 2009.

=head1 SYNOPSIS

 use Net::Amazon::ELB;

 my $ec2 = Net::Amazon::ELB->new(
	AWSAccessKeyId => 'PUBLIC_KEY_HERE', 
	SecretAccessKey => 'SECRET_KEY_HERE'
 );

 # Register instance with load balancer
 $ec2->register_instances_with_load_balancer(InstanceId => 'i-XXXXXXXX', LoadBalancerName => 'LB NAME');

=head1 DESCRIPTION

This module is a Perl interface to Amazon's Elastic Load Balancing. It uses the Query API to communicate with Amazon's Web Services framework.

=head1 CLASS METHODS

=head2 new(%params)

This is the constructor, it will return you a Net::Amazon::ELB object to work with.  It takes these parameters:

=over

=item AWSAccessKeyId (required)

Your AWS access key.

=item SecretAccessKey (required)

Your secret key, WARNING! don't give this out or someone will be able to use your account and incur charges on your behalf.

=item debug (optional)

A flag to turn on debugging. It is turned off by default

=back

=cut

has 'AWSAccessKeyId'	=> ( is => 'ro', isa => 'Str', required => 1 );
has 'SecretAccessKey'	=> ( is => 'ro', isa => 'Str', required => 1 );
has 'debug'				=> ( is => 'ro', isa => 'Str', required => 0, default => 0 );
has 'signature_version'	=> ( is => 'ro', isa => 'Int', required => 1, default => 2 );
has 'signature_method'	=> ( is => 'ro', isa => 'Str', required => 1, default => 'HmacSHA1' );
has 'version'			=> ( is => 'ro', isa => 'Str', required => 1, default => '2009-05-15' );
has 'timestamp'			=> ( 
	is			=> 'ro', 
	isa			=> 'Str', 
	required	=> 1, 
	default		=> sub { 
		my $ts = time2isoz(); 
		chop($ts); 
		$ts .= '.000Z'; 
		$ts =~ s/\s+/T/g; 
		return $ts; 
	} 
);
has 'base_url'			=> ( 
	is			=> 'ro', 
	isa			=> 'Str', 
	required	=> 1,
	lazy		=> 1,
	default		=> sub {
		return 'elasticloadbalancing.amazonaws.com';
	}
);

sub _sign {
	my $self						= shift;
	my %args						= @_;
	my $action						= delete $args{Action};
	my %sign_hash					= %args;
	$sign_hash{AWSAccessKeyId}		= $self->AWSAccessKeyId;
    $sign_hash{SignatureMethod}     = $self->signature_method;
	$sign_hash{SignatureVersion}	= $self->signature_version;
	$sign_hash{Version}				= $self->version;
	$sign_hash{Timestamp}			= $self->timestamp;
	$sign_hash{Action}			    = $action;

	my $sign_this = '';;
	# The sign string must be alphabetical in a case-insensitive manner.
	foreach my $key (sort keys %sign_hash) {
        $sign_this .= '&' if $sign_this;
		$sign_this .= $key .'='. $self->_urlencode($sign_hash{$key});
	}

    my $stringToSign = "GET\n" . lc($self->base_url) . "\n/\n$sign_this";
    {
        my $stringToSign_pretty = $stringToSign;
        $stringToSign_pretty =~ s/&/\n&/g;
        $self->_debug("QUERY TO SIGN: $stringToSign_pretty");
    }
    my $uri = URI->new('http://' .$self->base_url.'/');

	$sign_hash{Signature} = $self->_hashit($self->SecretAccessKey, $stringToSign);

    my $query = "";
	foreach my $key (sort keys %sign_hash) {
        $query .= '&' if $query;
		$query .= $key .'='. $self->_urlencode($sign_hash{$key});
	}
    $uri->query($query);

	my $ur	= $uri->as_string();
	$self->_debug("GENERATED QUERY URL: $ur");

	my $ua	= LWP::UserAgent->new();
	my $res	= $ua->get($ur);
	# We should force <item> elements to be in an array
	my $xs	= XML::Simple->new(ForceArray => qr/(?:item|Errors)/i, KeyAttr => '');
	my $xml;
	
	# Check the result for connectivity problems, if so throw an error
 	if ($res->code >= 500) {
 		my $message = $res->status_line;
		$xml = <<EOXML;
<xml>
	<RequestID>N/A</RequestID>
	<Errors>
		<Error>
			<Code>HTTP POST FAILURE</Code>
			<Message>$message</Message>
		</Error>
	</Errors>
</xml>
EOXML

 	}
	else {
		$xml = $res->content();
	}

	warn Dumper($xml) . "\n\n" if $self->debug == 1;
	my $ref = $xs->XMLin($xml);
	warn Dumper($ref) . "\n\n" if $self->debug == 1;

	return $ref;
}


sub _urlencode {
    my ( $self, $unencoded ) = @_;
    return uri_escape_utf8( $unencoded );
}

sub _parse_errors {
	my $self		= shift;
	my $errors_xml	= shift;
	
	my $es;
	my $request_id = $errors_xml->{RequestID};

	foreach my $e (@{$errors_xml->{Errors}}) {
		my $error = Net::Amazon::EC2::Error->new(
			code	=> $e->{Error}{Code},
			message	=> $e->{Error}{Message},
		);
		
		push @$es, $error;
	}
	
	my $errors = Net::Amazon::EC2::Errors->new(
		request_id	=> $request_id,
		errors		=> $es,
	);

	foreach my $error (@{$errors->errors}) {
		$self->_debug("ERROR CODE: " . $error->code . " MESSAGE: " . $error->message . " FOR REQUEST: " . $errors->request_id);
	}
	
	return $errors;	
}

sub _debug {
	my $self	= shift;
	my $message	= shift;
	
	if ((grep { defined && length} $self->debug) && $self->debug == 1) {
		print "$message\n\n\n\n";
	}
}

# HMAC sign the query with the aws secret access key and base64 encodes the result.
sub _hashit {
	my $self								= shift;
	my ($secret_access_key, $query_string)	= @_;
	my $hashed								= Digest::HMAC_SHA1->new($secret_access_key);
	$hashed->add($query_string);
	
	my $encoded = encode_base64($hashed->digest, '');

	return $encoded;
}

=head1 OBJECT METHODS

=head2 register_instances_with_load_balancer(%params)

Assigns an Instance to a load balancer

=over

=item InstanceId (required)

Either a scalar or an array ref can be passed in (containing instance ids to be attached).

=item LoadBalancerName (required)

Name of load balancer to assign to

=back

TODO - Returns an array ref of Net::Amazon::EC2::InstanceStateChange objects.

=cut

sub register_instances_with_load_balancer {
	my $self = shift;
    my %args = validate(
        @_,
        {
            InstanceId       => {type => SCALAR | ARRAYREF},
            LoadBalancerName => {type => SCALAR},
        }
    );
	
	# If we have a array ref of instances lets split them out into their InstanceId.n format
	if (ref ($args{InstanceId}) eq 'ARRAY') {
		my $instance_ids	= delete $args{InstanceId};
		my $count			= 1;
		foreach my $instance_id (@{$instance_ids}) {
			$args{"Instances.member." . $count . '.InstanceId'} = $instance_id;
			$count++;
		}
	}
	
	my $xml = $self->_sign(Action  => 'RegisterInstancesWithLoadBalancer', %args);	
	if ( $xml->{Errors} && grep { defined && length } $xml->{Errors} ) {
		return $self->_parse_errors($xml->{ResponseMetaData});
	}
	else {
        ### TODO --- handle return
		return 1;
	}
}

no Moose;
1;

__END__

=head1 AUTHOR

Gavin Mogan <cpan@halkeye.net>

=head1 COPYRIGHT

Copyright (c) 2010 Gavin Mogan. This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 SEE ALSO

Amazon ELB API: L<http://docs.amazonwebservices.com/ElasticLoadBalancing/latest/APIReference/>
