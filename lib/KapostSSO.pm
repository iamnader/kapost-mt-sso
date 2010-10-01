package KapostSSO;
use strict;
use Crypt::CBC;
use Digest::SHA;
use URI::Escape;
use MIME::Base64;
use JSON;

#
# Generates a Kapost SSO token for the given +guid+, +email+, +name+, +avatar+, 
# and +bio+ signed with the provided +subdomain+ and +key+.
#
sub token
{
	my($subdomain, $key, $guid, $email, $name, $avatar, $bio) = @_;	
	if(!$subdomain or !$key or !$guid or !$email)
	{
		return 0;
	}
	
	my $options = 
	{
		"external_user_id"	=> $guid,
		"email"				=> $email,
		"name"				=> $name,
		"avatar_url"		=> $avatar,
		"bio"				=> $bio
	};

	my $sha = new Digest::SHA;
	$sha->add("$subdomain:$key");
	my $kp = substr($sha->hexdigest,0,32);
	
	my $data = new JSON()->encode($options);
	
	my $iv = "Kapost is cool?!";
	foreach my $i (0 .. 15) 
	{
    	substr($iv,$i,1) ^= substr($iv,$i,1);
  	}

	my $cipher = Crypt::CBC->new(
	                  -key			=> pack("H*", $kp),
    	              -cipher		=> 'Rijndael',
    	              -iv			=> $iv,
    	              -literal_key	=> 1,
    	              -keysize		=> 16,
    	              -header		=> 'none');
                  
	my $cdata = encode_base64($cipher->encrypt($data));
	$cdata =~ s/\n//g; # replace newlines
  	return uri_escape($cdata);
}

#
# Generates a Kapost SCRIPT tag. The script will automatically rewrite all Kapost
# URLs to include a 'sso' query parameter with a signed Kapost SSO token.
#
sub script 
{
	my ($o) = @_;
	my $token = token(	$o->{'subdomain'}, 
						$o->{'key'}, 
						$o->{'guid'}, 
						$o->{'email'}, 
						$o->{'name'}, 
						$o->{'avatar'}, 
						$o->{'bio'}) or return 0;
	
	my $subdomain = $o->{'subdomain'};
	my $domain = $o->{'domain'};
	
	if(!$domain)
	{
		$domain = "$subdomain.kapost.com";	
	}
	
	my $script = <<EOF;
<script type="text/javascript">
(function()
{		
	var scr = document.createElement("script");
	scr.src = 'http://$domain/javascripts/sso.js';
	scr.id = 'kapostsso';
			
	var s = document.getElementsByTagName('script')[0]; 
	s.parentNode.insertBefore(scr, s);
		
	var oldonload = window.onload;
	window.onload = function()
	{
		if(oldonload && typeof oldonload == 'function') oldonload();
		try { KapostSSO.instance('$token','$domain'); } catch(err) {}
	}
})();
</script>
EOF

	return $script;
}

1;
