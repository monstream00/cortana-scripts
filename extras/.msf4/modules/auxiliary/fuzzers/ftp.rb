#
# Simple FTP fuzzer for Metasploit
# Written by Peter Van Eeckhoutte
# http://www.corelan.be:8800
# v1.3 - added more exception handlers
# v1.2 - added  current date & time to output on screen
# v1.1 - added part 5 - oct 20th 2009
# v1.0 - initial version released - oct 19th 2009

#
require 'msf/core'
class Metasploit3 < Msf::Auxiliary
    include Msf::Auxiliary::Scanner
    include Msf::Exploit::Remote::Tcp
    def initialize
         super(
              'Name'           => 'Simple FTP Fuzzer',
              'Description'    => %q{ 
                                Simple FTP Fuzzer
                                },
              'Author'         => [ 'Peter Van Eeckhoutte' ],
              'License'        => MSF_LICENSE,
              'Version'        => '$Revision: 1.3 $'
              )
          register_options( [OptInt.new('STARTATSTAGE', [ false, "Start at this test stage",1])], self.class)
          register_options( [ Opt::RPORT(21)], self.class)
          register_options( [OptInt.new('STEPSIZE', [ false, "Increase string size each iteration with this number of chars",10])], self.class)
          register_options( [OptInt.new('DELAY', [ false, "Delay between connections",0.5])], self.class)
          register_options( [OptInt.new('STARTSIZE', [ false, "Fuzzing string startsize",10])], self.class)
          register_options( [OptInt.new('ENDSIZE', [ false, "Fuzzing string endsize",20000])], self.class)
          #register_options( [ Opt::RHOST()], self.class)
          register_options( [ OptString.new('USER', [ false, "Username",'anonymous'])], self.class)
          register_options( [ OptString.new('PASS', [ false, "Password",'anonymous@test.com'])], self.class)
          deregister_options('RHOST')               
    end

    def run_host(ip)


        evilchars = ['A','a','%s','%d','%n','%x','%p','-1','0','0xfffffffe','0xffffffff','A/','//','/..','//..','A%20','./A','.A',',A','A:','!A','&A','?A','\A','../A/','..?','//A:','\\A','{A','$A','A*','cmd','A@a.com','#A','A/../','~','~A','~A/','A`/','>A','<A','A%n','A../','.././','A../','....//','~?*/','.\../','\.//A','-%A','%Y','%H','/1','!','@','%','&','/?(*','*','(',')','`',',','~/','/.','\$:','/A~%n','=','=:;)}','1.2.','41414141','-1234','999999,','%00','+A','+123','..\'','??.','..\.\'','.../','1234123+']
        
        commands = ['ABOR','ACCT','ALLO','APPE','AUTH','CWD','CDUP','DELE','FEAT','HELP','HOST','LANG','LIST','MDTM','MKD','MLST','MODE','NLST','NLST -al','NOOP','OPTS','PASV','PORT','PROT','PWD','REIN','REST','RETR','RMD','RNFR','RNTO','SIZE','SITE','SITE CHMOD','SITE CHOWN','SITE EXEC','SITE MSG','SITE PSWD','SITE ZONE','SITE WHO','SMNT','STAT','STOR','STOU','STRU','SYST','TYPE','XCUP','XCRC','XCWD','XMKD','XPWD','XRMD']
        startstage=datastore['STARTATSTAGE']
        stepsize=datastore['STEPSIZE']
        print_status("Connecting to host " + ip + " on port " + datastore['RPORT']) 
        count=datastore['STARTSIZE']
        max=datastore['ENDSIZE']



        #Fuzz without command
        if (startstage==1)
         print_status("[Phase 1] Fuzzing without command - #{Time.now.localtime}")
         evilchars.each do | evilstr |
           count=datastore['STARTSIZE']
           while count < max
            begin
              connect 
              print_status("  -> Fuzzing size set to #{count}")
              evil = evilstr * count
              pkt =  evil + "\n"
              sock.put(pkt)
              sock.get
              sock.put("QUIT\n")
              sleep datastore['DELAY']
              disconnect
              count+=stepsize
              rescue ::Exception => e
                if (e.class.name=='Rex::ConnectionRefused') or (e.class.name=='EOFError') or (e.class.name=='Errno::ECONNRESET') or (e.class.name='Errno::EPIPE')
                   print_status("Crash string : #{evilstr} x #{count}")
                   print_status("System does not respond - exiting now\n")
                   exit()
                end
                print_status("Error: #{e.class} #{e} #{e.backtrace}\n")
            end
           end
        end
        startstage+=1
       end


       if (startstage==2)
        #Fuzz USER
        print_status("[Phase 2] Fuzzing USER - #{Time.now.localtime}")
        evilchars.each do | evilstr | 
         count=datastore['STARTSIZE']
         while count < max
          begin
            connect
            print_status("  -> Fuzzing size set to #{count}")
            evil = evilstr * count
            pkt =  "USER " + evil + "\n"
            sock.put(pkt)
            sock.get
            sock.put("QUIT\n")
            sleep datastore['DELAY']
            disconnect
            count+=stepsize
            rescue ::Exception => e
                if (e.class.name=='Rex::ConnectionRefused') or (e.class.name=='EOFError') or (e.class.name=='Errno::ECONNRESET') or (e.class.name='Errno::EPIPE')
                   print_status("Crash string : #{evilstr} x #{count}")
                   print_status("System does not respond - exiting now\n")
                   exit()
                end
                print_status("Error: #{e.class} #{e} #{e.backtrace}\n")
           end
          end
         end
         startstage+=1
        end



        if (startstage==3)
         #Fuzz PASS
         print_status("[Phase 3] Fuzzing PASS - #{Time.now.localtime}")
         evilchars.each do | evilstr |
          count=datastore['STARTSIZE']
          while count < max
          begin
            connect
            print_status("  -> Fuzzing size set to #{count}")
            evil = evilstr * count
            pkt =  "USER " + datastore['USER'] + "\n"
            sock.put(pkt)
            sock.get
            pkt = "PASS " + evil + "\n"
            sock.put(pkt)
            sock.get
            sock.put("QUIT\n")
            sleep datastore['DELAY']
            disconnect
            count+=stepsize
            rescue ::Exception => e
                if (e.class.name=='Rex::ConnectionRefused') or (e.class.name=='EOFError') or (e.class.name=='Errno::ECONNRESET') or (e.class.name='Errno::EPIPE')
                   print_status("Crash string : #{evilstr} x #{count}") 
                   print_status("System does not respond - exiting now\n")
                   exit()
                end
                print_status("Error: #{e.class} #{e} #{e.backtrace}\n")
          end
         end
        end
        startstage+=1
       end


       #Fuzz other commands
       if (startstage==4)
         evilchr=""
         print_status("[Phase 4] Fuzzing other commands - Part 1 - #{Time.now.localtime}")
         commands.each do | thiscommand |
            print_status("Fuzzing command #{thiscommand} - #{Time.now.localtime}")
            evilchars.each do | evilstr |
              count=datastore['STARTSIZE']
              evilchr=evilstr
              while count < max
               begin
                connect
                print_status("  -> Fuzzing size set to #{count}")
                evil =  evilstr * count
                pkt =  "USER " + datastore['USER'] + "\n"
                sock.put(pkt)
                sock.get 
                pkt = "PASS " + datastore['PASS'] + "\n"
                sock.put(pkt)
                sock.get
                pkt = thiscommand + " " + evil + "\n"
                sock.put(pkt)
                sock.get
                sock.put("QUIT\n")
                sleep datastore['DELAY']
                disconnect
                count+=stepsize
                rescue ::Exception => e
                  if (e.class.name=='Rex::ConnectionRefused') or (e.class.name=='EOFError') or (e.class.name=='Errno::ECONNRESET') or (e.class.name='Errno::EPIPE')
                    print_status("Crash string : #{thiscommand} #{evilchr} x #{count}")
                    print_status("System does not respond - exiting now\n")
                    exit()
                  end
                  print_status("Error: #{e.class} #{e} #{e.backtrace}\n")
               end #end begin
              end  #end while
            end #end evilchars
          end #end commands
        end #end if




       #Fuzz other commands, all command combinations in one session 
       if (startstage==5)
         evilchr=""
         print_status("[Phase 5] Fuzzing other commands - Part 2 - #{Time.now.localtime}")
         commands.each do | thiscommand |
           print_status("Fuzzing command #{thiscommand} - #{Time.now.localtime}" )
           connect
           count=datastore['STARTSIZE']
           pkt =  "USER " + datastore['USER'] + "\n"
           sock.put(pkt)
           sock.get
           pkt = "PASS " + datastore['PASS'] + "\n"
           sock.put(pkt)
           sock.get
           while count < max
            print_status("  -> Fuzzing size set to #{count}")
            begin
              evilchars.each do | evilstr |
                 evilchr=evilstr
                 evil =  evilstr * count
                 pkt = thiscommand + " " + evil + "\n"
                 sock.put(pkt)
                 sock.get
                 sleep datastore['DELAY']
              end
                 rescue ::Exception => e
                   if (e.class.name=='Rex::ConnectionRefused') or (e.class.name=='EOFError') or (e.class.name=='Errno::ECONNRESET') or (e.class.name='Errno::EPIPE')
                     print_status("Crash string : #{thiscommand} #{evilchr} x #{count}")
                     print_status("System does not respond - exiting now\n")
                     exit()
                   end
                   print_status("Error: #{e.class} #{e} #{e.backtrace}\n")
             end #end begin
             count+=stepsize
           end  #end while
           sock.put("QUIT\n")
           sleep datastore['DELAY']
           disconnect
          end #end commands
        end #end if
    end  #end function
end  #end class
