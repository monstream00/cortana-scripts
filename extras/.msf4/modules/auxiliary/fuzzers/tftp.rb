require 'msf/core'
require 'rex'
require 'find'


class Metasploit3 < Msf::Auxiliary

	include Exploit::Remote::Udp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'tftp fuzzer',
			'Description'    => %q{
				Tftp fuzzer
			},
			'Author'         => 'monstream00',
			'License'        => MSF_LICENSE,
			'Version'        => '1',
			'References'     =>
				[ [ 'URL', 'http://www.faqs.org/rfcs/rfc1350.html'] ],
			'Payload'        =>
				{
					'Space'    => 350,
					'BadChars' => "\x00",
					'StackAdjustment' => -3500,
				},
			'DisclosureDate' => 'Oct 28 2008'))

		register_options([
			Opt::RHOST('127.0.0.1'),
			Opt::RPORT(69),
			OptString.new('PATTERNQU', [ true,  "The pattern: A=A pattern, P=pattern_create, S=SmartFuz, R=random, X=R-80% & S-20%, B=BruteforceFuzzLength", 'A']),
			OptString.new('FUZZWHAT', [ true,  "Remove fuzzing for: F=FileName, M=Mode, B=Both", 'B']),
			OptString.new('PROCESS', [ true,  "Only for localhost fuzzing: [ProcessName]", 'tftpserver']),
			OptString.new('PROCESSV', [ true,  "Only for localhost fuzzing: [Process Viewer]", 'ps -A'])
			#OptString.new('SMBPIPE', [ true,  "The pipe name to use", 'LSARPC']),
		], self.class)
		
	end

	#--------Fuzz Data----------
	$bad_int = ['0xffffffff','0x1FFFFFFF','0x7fffffff','0xfffffffe','0x80000000','0x100','0x1000',
			  '0xfffffffd','0x10000','0x100000','0x1000000','-1','1','0xff','0xffff','0xfe',
			  '0xfd','0xfffe','0x1fffffff','-1000','-10000','-100000','-1000000']
	$bad_str = ['%n','%s','%p','%x',':','..\\','\\..','[',',','A',"\n",'<','>','%']
	$bad_size = [36,65,129,1025,1280,2049,3000,4097]
	#--------Fuzz Data----------

	def randbytes(length)
		tempstring = ""
		chars = ""
		
		while length > 0
			#print_status("RandbytesWhile")
			xyz = rand(256).chr
			tempstring = xyz.to_s
			chars += tempstring
			length = length - 1
		end
		
		return chars
	end


	def make_pattern(lengthpat)
		print_status("make_pattern")
		pattern = Rex::Text.pattern_create(lengthpat, Rex::Text::DefaultPatternSets)
		
		return pattern
	end

	def make_Sdata()
		
		whatfuzz = datastore['FUZZWHAT']
		type = rand(2)
		if type == 0
			stringholder=$bad_str[rand($bad_str.length-1)]
		else
			stringholder=$bad_int[rand($bad_int.length-1)]
		end
		type = rand(10)
		#print_status("make_Sdata")
		if type <= 5
			
			
			typeRW = rand(2)
			#print_status(typeRW)
			if typeRW == 0
				data = "\x00\x01"#read
				
			else
				data = "\x00\x02"#write
				
			end
			if whatfuzz == 'M'
				data += stringholder * rand(5)
			else
				data += stringholder * rand(9215)
			end
			data += "\x00"
			if whatfuzz == 'F'
				data += stringholder * rand(5)
				
			else
				data += stringholder * rand(9215)
			end
			data += "\x00"
		
		elsif type == 6
				
				data = "\x00\x03"#data
				
				data += self.randbytes(2)
				
				data += stringholder * rand(9215)
				

		elsif type == 7
				
				data = "\x00\x04"#ACK
				
				data += self.randbytes(2)
				
				typeAnom = rand(2)
				if typeAnom == 0
					data += stringholder * rand(9215)
				end
				

		elsif type == 8
				
				data = "\x00\x05"#Err
				
				data += self.randbytes(2)
				
				data += stringholder * rand(9215)
				
				data += "\0"
				
		else
			
			data = stringholder * rand(9215)

		end
		return data
	end

	def make_Rdata()
		whatfuzz = datastore['FUZZWHAT']
		type = rand(10)
		
		if type <= 5
			
			
			typeRW = rand(2)
			#print_status(typeRW)
			if typeRW == 0
				data = "\x00\x01"#read
				
			else
				data = "\x00\x02"#write
				
			end
			if whatfuzz == 'M'
				data += self.randbytes(rand(5))
			else
				data += self.randbytes(rand(9215))
			end
			data += "\x00"
			if whatfuzz == 'F'
				data += self.randbytes(rand(5))
			else
				data += self.randbytes(rand(9215))
			end
			data += "\x00"
			
		
		elsif type == 6
				
				data = "\x00\x03"#data
				
				data += self.randbytes(2)
				
				data += self.randbytes(rand(9215))
				

		elsif type == 7
				
				data = "\x00\x04"#ACK
				
				data += self.randbytes(2)
				
				typeAnom = rand(2)
				if typeAnom == 0
					data += self.randbytes(rand(9215))
				end
				

		elsif type == 8
				
				data = "\x00\x05"#Err
				
				data += self.randbytes(2)
				
				data += self.randbytes(rand(9215))
				
				data += "\x00"
				

		else
			
			data = self.randbytes(rand(9215))

		end
		return data
	end

	def make_Pdata()
		whatfuzz = datastore['FUZZWHAT']
		type = rand(10)
		
		if type <= 5
			
			
			typeRW = rand(2)
			#print_status(typeRW)
			if typeRW == 0
				data = "\x00\x01"#read
				
			else
				data = "\x00\x02"#write
				
			end
			if whatfuzz == 'M'
				data += make_pattern(rand(5))
			else
				data += make_pattern(rand(9215))
			end
			data += "\x00"
			if whatfuzz == 'F'
				data += make_pattern(rand(5))
			else
				data += make_pattern(rand(9215))
			end
			data += "\x00"
			
		
		elsif type == 6
				
				data = "\x00\x03"#data
				
				data += self.randbytes(2)
				
				data += make_pattern(rand(9215))
				

		elsif type == 7
				
				data = "\x00\x04"#ACK
				
				data += self.randbytes(2)
				
				typeAnom = rand(2)
				if typeAnom == 0
					data += make_pattern(rand(9215))
				end
				

		elsif type == 8
				
				data = "\x00\x05"#Err
				
				data += self.randbytes(2)
				
				data += make_pattern(rand(9215))
				
				data += "\x00"
				

		else
			
			data = make_pattern(rand(9215))

		end
		return data
	end

	def make_Adata()
		whatfuzz = datastore['FUZZWHAT']
		type = rand(10)
		
		if type <= 5
			
			
			typeRW = rand(2)
			#print_status(typeRW)
			if typeRW == 0
				data = "\x00\x01"#read
				
			else
				data = "\x00\x02"#write
				
			end
			if whatfuzz == 'M'
				data += "A" * rand(5)
			else
				data += "A" * rand(9215)
			end
			data += "\x00"
			if whatfuzz == 'F'
				data += "A" * rand(5)
			else
				data += "A" * rand(9215)
			end
			data += "\x00"
			
		
		elsif type == 6
				
				data = "\x00\x03"#data
				
				data += self.randbytes(2)
				
				data += "A" * rand(9215)
				

		elsif type == 7
				
				data = "\x00\x04"#ACK
				
				data += self.randbytes(2)
				
				typeAnom = rand(2)
				if typeAnom == 0
					data += "A" * rand(9215)
				end
				

		elsif type == 8
				
				data = "\x00\x05"#Err
				
				data += self.randbytes(2)
				
				data += "A" * rand(9215)
				
				data += "\0"
				

		else
			
			data = "A" * rand(9215)

		end
		return data
	end

$readdata = 1
$writedata = 1
$datadata = 1
$ackdata = 1
$errdata = 1

	def make_Bdata()
		whatfuzz = datastore['FUZZWHAT']
		
		if $errdata == 9215
			print_status("Max UDP packet size reached: Exiting Now.")
			exit
		else
			if $readdata == $errdata
				data = "\x00\x01"#read
				
				if whatfuzz == 'M'
					data += "B" * rand(5)
				else
					data += "B" * $readdata
				end
				data += "\x00"
				if whatfuzz == 'F'
					data += "B" * rand(5)
					
				else
					data += "B" * $readdata
				end
				data += "\x00"
				
				
				$readdata += 1
			elsif $readdata > $writedata

				data = "\x00\x02"#write
				
		
				if whatfuzz == 'M'
					data += "B" * rand(5)
				else
					data += "B" * $readdata
				end
				data += "\x00"
				if whatfuzz == 'F'
					data += "B" * rand(5)
				else
				data += "B" * $readdata
				end
				data += "\x00"
				$writedata += 1
		
			elsif $writedata > $datadata
				
				data = "\x00\x03"#data
			
				data += self.randbytes(2)
				
				data += "B" * $datadata
			
				$datadata += 1

			elsif $datadata > $ackdata
				
				data = "\x00\x04"#ACK
				
				data += self.randbytes(2)
				
				typeAnom = rand(2)
				if typeAnom == 0
					data += "B" * $ackdata
				end
				
				$ackdata += 1

			elsif $ackdata > $errdata
				
				data = "\x00\x05"#Err
				
				data += self.randbytes(2)
				
				data += "B" * $errdata
				
				data += "\0"
				
				$errdata += 1

			else
			
			data = "B" * rand(9215)

			end
			return data
		end
		
	end

#		2 bytes     string    1 byte     string   1 byte
#		------------------------------------------------
#		| Opcode |  Filename  |   0  |    Mode    |   0  | (Read x00 x01, Write x00 x02)
#		------------------------------------------------
#		2 bytes     2 bytes      n bytes
#		----------------------------------
#		| Opcode |   Block #  |   Data     | (Data x00 x03)
#		----------------------------------
#		2 bytes     2 bytes
#		---------------------
#		| Opcode |   Block #  | (ACK x00 x04)
#		---------------------
#		2 bytes     2 bytes      string    1 byte
#		-----------------------------------------
#		| Opcode |  ErrorCode |   ErrMsg   |   0  | (err x00 x05)
#		-----------------------------------------
	def run
		connect_udp

		pattype = datastore['PATTERNQU']
		processname = datastore['PROCESS']
		rhosttest = datastore['RHOST']
		processviewer = datastore['PROCESSV']
		


		xqwe = 0
		while 1 == 1
			if pattype == 'X'
				typepat = rand(10)
				if typepat <= 7
					dat = self.make_Rdata()
				else
					dat = self.make_Sdata()
				end
			elsif pattype == 'P'
				dat = self.make_Pdata()
			elsif pattype == 'R'
				dat = self.make_Rdata()
			elsif pattype == 'S'
				dat = self.make_Sdata()
			elsif pattype == 'B'
				dat = self.make_Bdata()
			else
				dat = self.make_Adata()
			end
			#dat = 'A' * 9300
			dat = dat.slice(0,9215)
			#print_status("Data: " + dat)
			print_status("Length of Data: " + dat.length.to_s)
			udp_sock.put(dat)
			if rhosttest == '127.0.0.1'
				
				if processviewer == 'tasklist'#change to windows version
					print_status(processviewer)
					print_status(processname)
					bb = IO.popen(processviewer.to_s)
					b = bb.readlines
					if b.to_s.match(processname).to_s == processname
						print_status("Process is alive: " + b.to_s.match(processname).to_s) 
					else
						print_status("This Data killed the process!!!! " + processname.to_s + " 0-day time!!!!")
						print_status("Data: " + dat)
						print_status("Length of Data: " + dat.length.to_s)
						print_status("This Data killed the process!!!! " + processname.to_s + " 0-day time!!!!")
						exit
					end    
				else
					print_status(processviewer)
					print_status(processname)
					bb = IO.popen(processviewer.to_s)
					b = bb.readlines
					if b.to_s.match(processname).to_s == processname
						print_status("Process is alive: " + b.to_s.match(processname).to_s) 
					else
						print_status("This Data killed the process!!!! " + processname.to_s + " 0-day time!!!!")
						print_status("Data: " + dat)
						print_status("Length of Data: " + dat.length.to_s)
						print_status("This Data killed the process!!!! " + processname.to_s + " 0-day time!!!!")
						exit
					end    
					
				end
			end
			

		end

		handler
		disconnect_udp
	end
	
end
