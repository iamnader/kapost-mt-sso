#!/usr/bin/perl -w
package MT::Plugin::KapostSSO;

use strict;
use base qw( MT::Plugin );

our $VERSION = "0.1";

my $plugin = MT::Plugin::KapostSSO->new(
{
	name => 'Kapost SSO',
    version => $VERSION,
    description => "Adds Kapost.com Single Sign On.",
    author_name => "Kapost",
    author_link => "http://kapost.com",
    doc_link => 'http://kapost.com',
    system_config_template => 'config.tmpl',
    settings => MT::PluginSettings->new([
        ['kapost_domain' => { Default => '' }],
        ['kapost_apikey' => { Default => '' }],
    ]),
});

MT->add_plugin($plugin);

sub init_app 
{
	my ($plugin, $app) = @_;	
	#return unless $app->isa('MT::App::CMS');
	return unless $app->isa('MT::App::Comments');
    $app->add_methods(
		kapostsso => sub 
		{ 
			sso($plugin, $app); 
		},
    );
}

sub	sso
{
	my $app = MT::App->instance();
	#my $user = $app->user;
	 
    # FIXME: normally, $app->user should contain the currently logged
    # in user, but in the case of MT::App::Comments it doesn't.

	my $tmp1 = {};
	my @tmp2 = split(';',$app->cookie_val('mt_blog_user'));
	for my $v (@tmp2) 
	{
		my @vv = split(':',$v);
		@vv[1] =~ s/'//g;
			
		$tmp1->{@vv[0]} = @vv[1];
	}

	my $user = '';

	if(	$tmp1->{is_authenticated} == 1 and
		#$tmp1->{can_comment} == 1 and
		$tmp1->{email} )
	{
		use MT::Author;
		$user = MT::Author->load({'email'=>$tmp1->{email}});
	}
		
	# FIXME: check for permissions (normally this shouldn't be the case
	# as we are talking about the cookies from the actual request, so its
	# safe to assume that the user is all good when we reach this.
	if(!$user)
	{
		return '[]';
	}
		 
	# System-wide (site) settings ...         	
	my $settings = MT::Plugin::KapostSSO->instance->get_config_hash('system');
	my $domain = $settings->{kapost_domain};
	my $apikey = $settings->{kapost_apikey};
     	     	
	if(!$domain or !$apikey)
	{
		return '[]';
   	}
     	
	my @tmp = split(/\./,$domain);
	my $subdomain = @tmp[0];
     	
	if(!$subdomain)
	{
		return '[]';
	}

	my ($userpic,$w,$h) = $user->userpic_url;

	require KapostSSO;
	require JSON;
	my $params =
	{
		'domain'=>$domain,
		'token'=>KapostSSO::token(	$subdomain,
									$apikey,
									$user->id,
									$user->email,
									$user->nickname,
									$userpic,
									0,
									$domain )
	};
	
	new JSON()->encode($params);
}

sub instance { $plugin }
