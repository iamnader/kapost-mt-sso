package KapostSSO;
use strict;
use HTTP::Request::Common qw(POST);
use URI::Escape;
use LWP::UserAgent;
use JSON;

#
# Generates a Kapost SSO token for the given +guid+, +email+, +name+, +avatar+, 
# and +bio+ signed with the provided +subdomain+ and +key+.
#
sub token
{
	my($subdomain, $key, $guid, $email, $name, $avatar, $bio, $domain) = @_;	
	if(!$subdomain or !$key or !$guid or !$email)
	{
		return 0;
	}
	
	if(!$domain)
	{
		$domain = "$subdomain.kapost.com";
	}
	
	my $token = 0;
	
	my $data =
	{
		'subdomain'=>$subdomain,
		'key'=>$key,
		'guid'=>$guid,
		'email'=>$email
	};
			
	if($name) 
	{		
		$data->{'name'} = $name;
	}
	
	if($avatar)
	{
		$data->{'avatar'} = $avatar;
	}
	
	if($bio)
	{
		$data->{'bio'} 	= $bio;
	}
		
	my $req = LWP::UserAgent->new;
	my $res = $req->request(POST "http://$domain/sso/token.json",$data);
	
	if($res and $res->is_success)
	{
		$res = new JSON()->decode($res->content);
		if($res)
		{
			$token = $res->{'token'};
		}
	}
		
	return $token;
}

#
# Generates a Kapost SCRIPT tag. The script will automatically rewrite all Kapost
# URLs to include a 'sso' query parameter with a signed Kapost SSO token.
#
sub script 
{
	my ($o) = @_;

	my $subdomain = $o->{'subdomain'};
	my $domain = $o->{'domain'};	
	if(!$domain)
	{
		$domain = "$subdomain.kapost.com";	
	}

	my $token = token(	$o->{'subdomain'}, 
						$o->{'key'}, 
						$o->{'guid'}, 
						$o->{'email'}, 
						$o->{'name'}, 
						$o->{'avatar'}, 
						$o->{'bio'},
						$domain) or return 0;
	
	$token = uri_escape($token);
	
	my $script = <<EOF;
<script type="text/javascript">
(function()
{		
	var scr = document.createElement("script");
	scr.src = 'http://$domain/javascripts/sso.js';
	scr.id = 'kapostsso';
			
	var s = document.getElementsByTagName('script')[0]; 
	s.parentNode.insertBefore(scr, s);
		
	window.onload = (function()
	{
		var oldonload = window.onload;
		return function()
		{	
			if(oldonload && typeof oldonload == 'function') oldonload.apply(this, arguments);
			setTimeout(function(){try{KapostSSO.instance('$token','$domain');}catch(err){}},100);
		};
	})();
	
})();
</script>
EOF

	return $script;
}

1;
