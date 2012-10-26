##
# $Id: tcp.rb 14976 2012-03-18 05:08:13Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Capture

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	#include Msf::Ui::Console::CommandDispatcher


	def initialize
		super(
			'Name'        => 'TCP Port Scanner',
			'Version'     => '$Revision: 14976 $',
			'Description' => 'Enumerate open TCP services',
			'Author'      => [ 'hdm', 'kris katterjohn' ],
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptString.new('PORTS', [true, "Default(All metasploit module ports) Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
			OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
			OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]),
		], self.class)

		deregister_options('RPORT')

	end

	# Generate an up2date list of ports used by exploit modules
	def get_tcp_port_list
		# UDP ports
		udp_ports = [53,67,137,161,123,138,139,1434]

		# Ports missing by the autogen
		additional_ports = [465,587,995,993,5433,50001,50002,1524, 6697, 8787, 41364, 48992, 49663, 59034]

		print_status("Generating list of ports used by Auxiliary Modules")
		ap = (framework.auxiliary.collect { |n,e| x=e.new; x.datastore['RPORT'].to_i}).compact
		print_status("Generating list of ports used by Exploit Modules")
		ep = (framework.exploits.collect { |n,e| x=e.new; x.datastore['RPORT'].to_i}).compact

		# Join both list removing the duplicates
		port_list = (((ap | ep) - [0,1]) - udp_ports) + additional_ports
		return port_list
	end


	def run_host(ip)

		timeout = datastore['TIMEOUT'].to_i

		ports = Rex::Socket.portspec_crack(datastore['PORTS'])

		if ports.empty?
			#print_error("Error: No valid ports specified")
			#return
			ports = get_tcp_port_list
			print_status("Scanning Ports: #{ports} ")
		end

		while(ports.length > 0)
			t = []
			r = []
			begin
			1.upto(datastore['CONCURRENCY']) do
				this_port = ports.shift
				break if not this_port
				t << framework.threads.spawn("Module(#{self.refname})-#{ip}:#{this_port}", false, this_port) do |port|
					begin
						s = connect(false,
							{
								'RPORT' => port,
								'RHOST' => ip,
								'ConnectTimeout' => (timeout / 1000.0)
							}
						)
						print_status("#{ip}:#{port} - TCP OPEN")
						r << [ip,port,"open"]
					rescue ::Rex::ConnectionRefused
						vprint_status("#{ip}:#{port} - TCP closed")
						r << [ip,port,"closed"]
					rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
					rescue ::Interrupt
						raise $!
					rescue ::Exception => e
						print_error("#{ip}:#{port} exception #{e.class} #{e} #{e.backtrace}")
					ensure
						disconnect(s) rescue nil
					end
				end
			end
			t.each {|x| x.join }

			rescue ::Timeout::Error
			ensure
				t.each {|x| x.kill rescue nil }
			end

			r.each do |res|
				report_service(:host => res[0], :port => res[1], :state => res[2])
			end
		end
	end

end
