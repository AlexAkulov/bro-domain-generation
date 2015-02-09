##! Domain generation algorithm based detection for NewGOZ (Game Over Zeus)
##!
##! Ported from Python script found here:
##!     http://www.johannesbader.ch/2014/12/the-dga-of-newgoz/
##!
##! Requires: Bro 2.1+
##! Author:   Vlad Grigorescu <vlad@broala.com>
##! 

@load ./utils

module DomainGeneration;

export { 
	## These are the current names based on the number of hours being offset
	## and calculated.
	global newgoz_current_names: set[string] = set();

	redef enum Kit += { NEWGOZ };
}

function hex_to_int(seed_value: string): count
	{
	local indices = vector(6, 4, 2, 0);
	local seed = "";
	for ( i in indices )
		seed = seed + sub_bytes(seed_value, indices[i] + 1, 2);
	return bytestring_to_count(hexstr_to_bytestring(seed));
	}

function get_seed(sequence_number: count, year: count, month: count, day: count): string
	{
	local key = "\x01\x05\x19\x35";
	local seed = md5_hash_init();
	
	# 1. Sequence number (uint32 in little-endian format)
	md5_hash_update(seed, hexstr_to_bytestring(fmt("%2x", sequence_number % 256)));
	md5_hash_update(seed, hexstr_to_bytestring(fmt("%2x", sequence_number / 256)));
	md5_hash_update(seed, "\x00\x00");
	# 2. Year (uint16 in little-endian format)
	md5_hash_update(seed, hexstr_to_bytestring(fmt("%2x", year % 256)));
	md5_hash_update(seed, hexstr_to_bytestring(fmt("%2x", year / 256)));
	# 3. Key
	md5_hash_update(seed, key);
	# 4. Month
	md5_hash_update(seed, hexstr_to_bytestring(fmt("%2x", month)));
	md5_hash_update(seed, "\x00");
	# 5. Key
	md5_hash_update(seed, key);
	# 6. Day
	md5_hash_update(seed, hexstr_to_bytestring(fmt("%2x", day)));
	md5_hash_update(seed, "\x00");
	# 7. Key
	md5_hash_update(seed, key);

	return md5_hash_finish(seed);
	}

function generate_domain_part(seed_value: count, sequence_number: count): string
	{
	local part = "";
	local char = 0;

	for ( i in vector(0, 1, 2, 3, 4, 5, 6) )
		{
		local edx = seed_value % 36;
		seed_value = seed_value/36;

		if (edx > 9)
			char = 97 + (edx - 10);
		else
			char = edx + 48;

		part += fmt("%02x", char);

		if ( seed_value == 0 )
			break;
		}
	return reverse(hexstr_to_bytestring(part));
	}

function generate_newgoz_domain(sequence_number: count, year: count, month: count, day: count): string
	{
	local seed_value = get_seed(sequence_number, year, month, day);
	local domain = "";

	local loop = vector(0, 4, 8, 12);
	for ( i in loop )
		{
		local seed = sub_bytes(seed_value, (loop[i]*2) + 1, 8);
		domain += generate_domain_part(hex_to_int(seed), 1);
		}

	if ( sequence_number % 4 == 0 )      domain += ".com";
	else if ( sequence_number % 3 == 0 ) domain += ".org";
	else if ( sequence_number % 2 == 0 ) domain += ".biz";
	else                                 domain += ".net";
		
	return domain;
	}

function generate_newgoz_domains(date: time): set[string]
	{
	local year = to_count(strftime("%Y", date));
	local month = to_count(strftime("%m", date));
	local day = to_count(strftime("%d", date));

	local result: set[string] = set();

	local daily_domains = 1000;
	local todo = vector(0);
	local sequence_number: count = 0;
	
	for ( i in todo )
		{
		local d = generate_newgoz_domain(sequence_number, year, month, day);
		++sequence_number;
		add result[d];
		add newgoz_current_names[d];
		domains[d] = NEWGOZ;

		# This is our hack for looping over this daily_domains number of times.
		--daily_domains;
		if ( daily_domains > 0 )
			todo[|todo|] = 0;
		}

	return result;
	}

event update_newgoz_current_names()
	{
	local now = network_time();

	# We generate domains for yesterday, today, and tomorrow, in case
	# an infected client has some clock drift or a different timezone

	newgoz_current_names = set();

	generate_newgoz_domains(now - 1day);
	generate_newgoz_domains(now);
	generate_newgoz_domains(now + 1day);

	schedule 60mins { update_newgoz_current_names() };
	}

event bro_init()
	{
	event update_newgoz_current_names();
	}
