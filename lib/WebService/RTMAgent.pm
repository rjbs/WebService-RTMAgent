use strict;
use warnings;
package WebService::RTMAgent;
# ABSTRACT: a user agent for the Remember The Milk API

=head1 SYNOPSIS

 $ua = WebService::RTMAgent->new;
 $ua->api_key($key_provided_by_rtm);
 $ua->api_secret($secret_provided_by_rtm);
 $ua->init;
 $url = $ua->get_auth_url;  # then do something with the URL
 $res = $ua->tasks_getList('filter=status:incomplete');

 ...

=head1 DESCRIPTION

WebService::RTMAgent is a Perl implementation of the rememberthemilk.com API.

=head2 Calling API methods

All API methods documented at L<https://www.rememberthemilk.com/services/api/>
can be called as methods, changing dots for underscores and optionnaly taking
off the leading 'rtm': C<< $ua->auth_checkToken >>, C<< $ua->tasks_add >>, etc.

Parameters should be given as a list of strings, e.g.:

  $ua->tasks_complete(
    "list_id=4231233",
    "taskseries_id=124233",
    "task_id=1234",
  );

Refer to the API documentation for each method's parameters.

Return values are the XML response, parsed through L<XML::Simple>. Please refer
to XML::Simple for more information (and Data::Dumper, to see what the values
look like) and the sample B<rtm> script for examples.

If the method call was not successful, C<undef> is returned, and an error
message is set which can be accessed with the B<error> method:

  $res = $ua->tasks_getList;
  die $ua->error unless defined $res;

Please note that at this stage, I am not very sure that this is the best way to implement the API. "It works for me," but:

=for :list
* Parameters may turn to hashes at some point
* Output values may turn to something more abstract and useful,
  as I gain experience with API usage.

=head2 Authentication and authorisation

Before using the API, you need to authenticate it. If you are going to be
building a desktop application, you should get an API key and shared secret
from the people at rememberthemilk.com (see
L<https://groups.google.com/group/rememberthemilk-api/browse_thread/thread/dcb035f162d4dcc8>
for rationale) and provide them to RTMAgent.pm with the C<api_key> and
C<api_secret> methods.

You then need to proceed through the authentication cycle: create a useragent,
call the get_auth_url method and direct a Web browser to the URL it returns.
There RememberTheMilk will present you with an authorisation page: you can
authorise the API to access your account.

At that stage, the API will get a token which identifies the API/user
authorisation. B<RTMAgent> saves the token in a file, so you should never need
to do the authentication again.

=head2 Proxy and other strange things

The object returned by B<new> is also a LWP::UserAgent. This means you can
configure it the same way, in particular to cross proxy servers:

  $ua = new WebService::RTMAgent;
  $ua->api_key($key);
  $ua->api_secret($secret);
  $ua->proxy('http', 'https://proxy:8080');
  $ua->init;
  $list = $ua->tasks_getList;

Incidentally, this is the reason why the C<init> method exists: C<init> needs
to access the network, so its work cannot be done in C<new> as that would leave
no opportunity to configure the LWP::UserAgent.

=cut

use Carp;
use Digest::MD5 qw(md5_hex);
use LWP::UserAgent;
use XML::Simple;

use parent 'LWP::UserAgent';

my $REST_endpoint = "https://api.rememberthemilk.com/services/rest/";
my $auth_endpoint = "https://api.rememberthemilk.com/services/auth/";

our $config_file = "$ENV{HOME}/.rtmagent";
our $config;  # reference to config hash

=head1 PUBLIC METHODS

=head2 $ua = WebService::RTMAgent->new;

Creates a new agent.

=cut

sub new {
    my $class = shift;
    Carp::confess("tried to call ->new on an instance") if ref $class;
    my $self  = $class->SUPER::new(@_);
    $self->verbose('');
    return bless $self, $class;
}

=head2 $ua->api_key($key);

=head2 $ua->api_secret($secret);

Set the API key and secret. These are obtained from the people are
RememberTheMilk.com.

=head2 $ua->verbose('netin netout');

Sets what type of traces the module should print. You can use 'netout' to print
all the outgoing messages, 'netin' to print all the incoming messages.

=head2 $err = $ua->error;

Get a message describing the last error that happened.

=cut

# Create accessors
BEGIN {
    my $subs;
    foreach my $data ( qw/error verbose api_secret api_key/ ) {
        $subs .= qq{
            sub $data {
                \$_[0]->{rtma_$data} =  
                    defined \$_[1] ? \$_[1] : \$_[0]->{rtma_$data};
            }
        }
    }
    eval $subs;
}

=head2 $ua->init;

Performs authentication with RTM and various other book-keeping
initialisations.

=cut

sub init {
    my ($self) = @_;

    if (-e $config_file) {
        die "$config_file: can't read or write\n"
          unless -r $config_file and -w $config_file;

        my $ok = eval {
          $config = XMLin($config_file, KeyAttr=>'', ForceArray => ['undo']);
          1;
        };
        croak "$config_file: Invalid XML file" unless $ok;
    }

    # Check Token
    if ($config->{token}) {
        my $res = $self->auth_checkToken;
        if (not defined $res) {
            delete $config->{frob};
            delete $config->{token};
            croak $self->error;
        }
    }

    # If we have a frob and no token, we're half-way through
    # authentication -- finish it
    if ($config->{frob} and not $config->{token}) {
        warn "frobbed -- getting token\n";
        my $res = $self->auth_getToken("frob=$config->{frob}");
        die $self->error."(Maybe you need to erase $config_file)\n"
          unless defined $res;
        $config->{token} = $res->{auth}->[0]->{token}->[0];
        warn "token $config->{token}\n";
    }

    # If we have no timeline, get one
    unless ($config->{timeline}) {
        my $res = $self->timelines_create();
        $config->{timeline} = $res->{timeline}->[0];
        $config->{undo} = [];
    }
}

=head2 $ua->get_auth_url;

Performs the beginning of the authentication: this returns a URL to which
the user must then go to allow RTMAgent to access his or her account.

This mecanism is slightly contrieved and designed so that users do not have
to give their username and password to third party software (like this one).

=cut

sub get_auth_url {
    my ($self) = @_;

    my $res = $self->auth_getFrob();

    my $frob = $res->{'frob'}->[0];

    my @params;
    push @params, "api_key=".$self->api_key, "perms=delete", "frob=$frob";
    push @params, "api_sig=".($self->sign(@params));

    my $url = "$auth_endpoint?". (join '&', @params);

    # save frob for later
    $config->{'frob'} = $frob;

    return $url;
}

=head2 @undo = $ua->get_undoable;

Returns the transactions which we know how to undo (unless data has been lost,
that's all the undo-able transaction that go with the timeline that is saved in
the state file).

The value returned is a list of { id, op, [ params ] } with id the transaction
id, op the API method that was called, and params the API parameters that were
called.

=cut

sub get_undoable {
    my ($self) = @_;

    return $config->{undo};
}

=head2 $ua->clear_undo(3);

Removes an undo entry.

=cut

sub clear_undo {
    my ($self, $index) = @_;

    splice @{$config->{undo}}, $index, 1;
}

=head1 PRIVATE METHODS

Don't use those and we'll stay friends.

=head2 $ua->sign(@params);

Returns the md5 signature for signing parameters. See RTM Web site for details.
This should only be useful for the module, don't use it.

=cut

sub sign {
    my ($self, @params) = @_;

    my $sign_str = join '', sort @params;
    $sign_str =~ s/=//g;

    return md5_hex($self->api_secret."$sign_str");
}

=head2 $ua->rtm_request("rtm.tasks.getList", "list_id=234", "taskseries_id=2"..)

Signs the parameters, performs the request, returns a parsed XML::Simple
object.

=cut

sub rtm_request {
    my ($self, $request, @params) = @_;

    unshift @params, "method=$request";
    push @params, "api_key=".$self->api_key;
    push @params, "auth_token=$config->{token}" if exists $config->{token};
    push @params, "timeline=$config->{timeline}" if exists $config->{timeline};
    my $sig = $self->sign(@params);
    my $param = join '&', @params;

    my $req = HTTP::Request->new( POST => $REST_endpoint);
    $req->content_type('application/x-www-form-urlencoded');
    $req->content("$param&api_sig=$sig");
    warn("request:\n".$req->as_string."\n\n") if $self->verbose =~ /netout/;

    my $res = $self->request($req);
    die $res->status_line unless $res->is_success;

    warn("response:\n".$res->as_string."\n\n") if $self->verbose =~ /netin/;
    return XMLin($res->content, KeyAttr=>'', ForceArray=>1);
}

# AUTOLOAD gets calls to undefined functions
# we add 'rtm' and change underscores to dots, to change perl function
# names to RTM API: tasks_getList => rtm.tasks.getList
# arguments are as strings:
# $useragent->tasks_complete("list_id=$a", "taskseries_id=$b" ...);
our $AUTOLOAD;
sub AUTOLOAD {
    my $function = $AUTOLOAD;

    my $self = shift;

    $function =~ s/^.*:://; # Remove class name
    $function =~ s/_/./g;   # Change underscores to dots (auth_getFrob => auth.getFrob)
    $function =~ s/^/rtm./ unless $function =~ /^rtm./; # prepends rtm if needed
    my $res = $self->rtm_request($function, @_);

    # Treat errors
    if (exists $res->{'err'}) {
        croak ("$function does not exist\n") if $res->{'err'}->[0]->{'code'} == 112;
        $self->error("$res->{'err'}->[0]->{'code'}: $res->{'err'}->[0]->{'msg'}\n");
        return undef;
    }

    # If action is undo-able, store transaction ID
    if (exists $res->{transaction} and
        exists $res->{transaction}->[0]->{undoable}) {
        push @{$config->{undo}}, {
                'id' => $res->{transaction}->[0]->{id},
                'op' => $function,
                'params' => \@_,
            };
    }
    return $res;
}


# When destroying the object, save the config file
# (careful, this all means we can only have one instance running...)
sub DESTROY {
    return unless defined $config;
    open my $f, "> $config_file";
    print $f XMLout($config, NoAttr=>1, RootName=>'RTMAgent');
}

=head1 FILES

=for :list
= F<~/.rtmagent>
XML file containing runtime data: frob, timeline, authentication token. This
file is overwritten on exit, which means you should only have one instance of
RTMAgent (this should be corrected in a future version).

=head1 SEE ALSO

=for :list
* C<< L<rtm|https://www.rutschle.net/rtm> >>, example command-line script.
* L<LWP::UsrAgent>
* L<XML::Simple>

=cut

1;
