require 'msf/core'

# RFC 3164 Notes:
#
#	<-----1024 Bytes or Less---------->
#
#	| PRI |     HEADER      | MESSAGE |
#
#    <###>
#		  TIMESTAMP HOSTNAME
#							TAG CONTENT
#							 32:content
#
#	TIMESTAMP Format Mmm dd hh:mm:ss


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Udp
	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'syslog fuzzer',
			'Description'    => %q{
				This is fuzzer for testing syslog daemons and causing general havoc with
				syslogs that allow unrestricted access.  Syslog servers behave loosely, 
				so you may want to evaluate limited results first to ensure the server 
				is not globbing fields.  
			},
			'Author'         => ['Saint Patrick <saintpatrick@l1pht.com>'],
			'License'        => BSD_LICENSE,
			'Version'        => '11',
			'DisclosureDate' => 'Nov 13 2008'))

		register_options([
			Opt::RPORT(514),
			OptString.new('FIELD',[false,'FIELD to fuzz (PRI, HEADER, MESSAGE, RANDOM, NONE)',"RANDOM"]),
			OptInt.new('TIMES',[false,'Times to send fuzz',1000])
		])
	end

	#--------Fuzz Data----------
	$bad_int = ['0xffffffff','0x1FFFFFFF','0x7fffffff','0xfffffffe','0x80000000','0x100','0x1000',
			  '0xfffffffd','0x10000','0x100000','0x1000000','-1','0','1','0xff','0xffff','0xfe',
			  '0xfd','0xfffe','0x1fffffff','-1000','-10000','-100000','-1000000']
	$bad_str = ['%n','%s','%p','%x',':','..\\','\\..','[',',',"\x00",'A',"\n",'<','>','%','|','X']
	$bad_size = [3,11,36,65,129,1025,1280,1536,1537,2049,3000,3072,6144,6145,10000]
	#--------Fuzz Data----------
	
	$month_array = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

	# Making a fuzz value for PRI
	def make_bad_pri
		ran_select = rand(2)
		if ran_select==0
			bad_pri = $bad_int[rand($bad_int.length-1)]
		else
			stringholder=$bad_str[rand($bad_str.length-1)]
			bad_pri = stringholder*(1+rand($bad_size[$bad_size.length-1]))
		end
		return bad_pri
	end

	# Making a fuzz value for HEADER
	def make_bad_header
		piece = rand(5)
		
		# This time we'll mess with month
		if piece == 0
			monthholder = $bad_str[rand($bad_str.length-1)]
			month = monthholder*(1+rand(3))
		else
			month_select = rand(11)
			month = $month_array[month_select]
		end
		
		# This time we'll mess with day
		if piece == 1
			@day_str = $bad_int[rand($bad_int.length-1)]
		else
			day = rand(28)
			if day < 10
				@day_str = day.to_s.rjust(2," ")
			else
				@day_str = day.to_s
			end
		end
		
		# This time we'll mess with hour
		if piece == 2
			hour = $bad_int[rand($bad_int.length-1)]
		else
			hour=rand(23)
			hour = hour.to_s.rjust(2,"0")
		end
		
		# This time we'll mess with minute
		if piece == 3
			minute = $bad_int[rand($bad_int.length-1)]
		else
			minute=rand(59)
			minute = minute.to_s.rjust(2,"0")
		end
		
		#  This time we'll mess with second
		if piece == 4
			second = $bad_int[rand($bad_int.length-1)]
		else
			second = rand(59)
			second = second.to_s.rjust(2,"0")
		end
		time_str= month + " " + @day_str + " " + hour.to_s + ":" + minute.to_s + ":" + second.to_s
		
		#  This time we mess with the hostname
		if piece == 5
			host = $bad_str[rand($bad_str.length-1)]
		else
			host = "fuzzhost"	# Might want to change this?
		end
		
		wicked_header = time_str + " " + host
		
		return wicked_header
	end
	
	def make_bad_msg
	    ran_select = rand(2)
		if ran_select==0
			bad_msg = $bad_int[rand($bad_int.length-1)]*(1+rand($bad_size[$bad_size.length-1]))
		else
			stringholder=$bad_str[rand($bad_str.length-1)]
			bad_msg = stringholder*(1+rand($bad_size[$bad_size.length-1]))
		end
		return bad_msg
	end

	def run
		
		print_status("Starting fuzz...")
		start_t=Time.now()
		time=datastore['TIMES']
		for i in 1..time do
		
			# Start Your Engines!
			if datastore['FIELD']=="RANDOM"
				myselector=rand(3)				# There are three separate sections to select
			elsif datastore['FIELD']=="PRI"
				myselector=0
			elsif datastore['FIELD']=="HEADER"
				myselector=1
			elsif datastore['FIELD']=="MESSAGE"
				myselector=2
			elsif datastore['FIELD']=="NONE"
				myselector=3
			else
				myselector=rand(2)
			end
			
			#---------PRI--------------
			if myselector != 0
				facility = rand(23)				# There are 24 RFC'd facilities       <---------- these are currently not weighted
				severity = rand(7)				# There are 8 RFC'd severity levels   <------/
				pri = (facility*8)+severity
			else
				pri = make_bad_pri()
			end
			pri_str = "<"+pri.to_s+">"
			#---------PRI--------------
			
			#---------HEADER-----------
			if myselector != 1
				
				month_select = rand(11)
				month = $month_array[month_select]
				day = rand(28)
				if day < 10
					day_str = day.to_s.rjust(2," ")
				else
					day_str = day.to_s
				end
				hours = rand(23)
				hours = hours.to_s.rjust(2,"0")
				minutes = rand(59)
				minutes = minutes.to_s.rjust(2,"0")
				seconds = rand(59)
				seconds = seconds.to_s.rjust(2,"0")
				time_str = month + " " + day_str + " " + hours + ":" + minutes + ":" + seconds + " fuzzhost"
			else
				time_str = make_bad_header()
			end
			#---------HEADER-----------
			
			#---------MESSAGE----------
			if myselector != 2
				tag=Rex::Text.rand_text_english(7)       #<-------------32 byte tag, no reason for 90, it's just a valid length.
				content=Rex::Text.rand_text_alpha(90)    #<------/
				number = rand(99)
				message=tag+"["+number.to_s+"]:"+content
			else
				message = make_bad_msg()
			end
			#---------MESSAGE----------
			
			fuzz = pri_str + time_str + " " + message
			
			# Do the sending
				connect_udp
				fuzz = fuzz.slice(0,9215)
				udp_sock.put(fuzz)
				print_status("Sent fuzz #"+i.to_s)
				disconnect_udp

		end
		end_t =Time.now()
		elapsed=end_t-start_t
		print_status("Fuzzed for: " +elapsed.to_s)
		print_status("Finished fuzzing...")
	end	
end