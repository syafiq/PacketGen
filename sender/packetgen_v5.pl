#
# PacketGen v1.3
# PacketGen.pl
# this script read tcpdump file with cpan Net::Pcap
# then send the correspondence packet to the designated IP address through socket
# 
# 1.1 version 08_11_2013
# 1.2 version 10_11_2013 ++ add packetlen to cut trailer, install Math::BaseCnv
# 1.3 version 13_2_2014 ++ read from configuration file
# 
# created by 	Syafiq Al Atiiq ~ atiiq [at] kth [dot] se
# 		Surya Seetharaman ~ suryas [at] kth [dot] se 
# 
# Please be noted that, all calculations in this code are based on hexadecimal
#

#!/usr/bin/perl -w

#use strict;
use Net::Pcap;
use IO::Socket::INET;
use String::HexConvert ':all';
use Math::BaseCnv;
use Switch;
use Config::Simple;
use Data::Dumper;

my $pcap = undef;
my $err  = '';
my $count = 0;

$cfg = new Config::Simple('packet.conf');

# Read from configuration file 
my $apps = $cfg->param('apps');
my $ipdest = $cfg->param('ipdest');
my $portdest = $cfg->param('portdest');
my $protocol = $cfg->param('proto');
my $file = $cfg->param('pcapfile');
my $counter = $cfg->param('counter');
my $packet_per_pcap = $cfg->param('ppp');
my $tcp_header_len = $cfg->param('header_len');
my $code = $cfg->param('input_code');
my $new_value = $cfg->param('input_value');


# counter for different packet
switch ($apps) {
	case gtp {
		$packcount = 46;
	}
	case diameter {
		$diam_header = 20;
	}
}
sub process_packet {
	$count++;
	my ($user_data, $header_ref, $packet) = @_;
	
	# Start socket
	$| = 1;

	# socket initiation
	my $socket = new IO::Socket::INET (
		PeerHost => $ipdest,
		PeerPort => $portdest,
		Proto => $protocol 
	);
	die "cannot connect to the server $!\n" unless $socket;
	print "connected to the server\n";	

	# sending file
	my $req = $packet;
	$req = ascii_to_hex($packet);

	# separate the packet container as an array
	@packet_split = ( $req =~ m/../g );
	
	# my $maxpacket = scalar(@packet_split);
	# where is the packet length located
	my $packetlen_hex = $packet_split[$tcp_header_len+2].$packet_split[$tcp_header_len+3];
	#print "$packetlen_hex \n";
	
	# packet len in GTP should be added by 8 to get real length
	my $packetlen_dec = (cnv($packetlen_hex,16,10));
	print "packet length : $packetlen_dec \n";
	# ============
	if ($apps == "diameter") {
		$flag = 0;
		#print "which code's corresponding value do you want to change?\n";
		#$code = <>;
		# print "\n This is diameter\n";
		$jump = $tcp_header_len + $diam_header;
		@avp = splice(@packet_split, $jump, $packetlen_dec-20);
		@avp_print = @avp;
		print "\n------------before changing----------------->\n";
		#$avp = ('',@avp);
		$avp_print = join('',@avp_print);
		print "$avp_print";
		print "\n<------------------------------\n";
		my @avp_tables;
		$start_avp = 0;
		@grouped_avp = (437,443,446,456,458,873,874);#only possible grouped thing "in this pcap"
		for ($i = 0; $i<=100; $i++) { # we set the maximum number of avp per diameter pcap is 100
			if (@avp) {
				@code_avp = splice(@avp, $start_avp, 4);
				$code_avp = join('',@code_avp);#joind every element in this array.
		       		$code_avp_dec = cnv($code_avp,16,10);	
				
				@flags_avp = splice(@avp, $start_avp, 1);
				$flags_avp = join('',@flags_avp);
				$flags_avp_dec = cnv($flags_avp,16,10);
				#print "\nflags avp dec = $flags_avp_dec \n";

				@len_avp = splice(@avp, $start_avp, 3);
				$len_avp = join('',@len_avp); 
				$len_avp_dec = cnv($len_avp,16,10);
				
				if ($flags_avp_dec == 192) { #both vendor id + mandatory flag is set
					# there is vendor id header to be taken care of
					@vendorid_avp = splice(@avp, $start_avp, 4);
					$vendorid_avp = join('',@vendorid_avp);
					$vendorid_avp_dec = cnv($vendorid_avp,16,10);
					# avp value
					@value_avp = splice(@avp, $start_avp, $len_avp_dec-12);
				} elsif ($flags_avp_dec == 64) { #only mandatory flag is set
					# avp value
					@value_avp = splice(@avp, $start_avp, $len_avp_dec-8);
				} else {
					# do nothing, it's undefined
				}
				$value_avp_len_dec = scalar(@value_avp);
                                $value_avp = join('',@value_avp);
				if ($code == $code_avp_dec) {
					
					#print "what is the new value?\n";
					#$new_value = "74656c6b6f6d736565";
					#print "new_value = $new_value\n\n";
					$value_avp = $new_value;
					$flag = 1;
				}
				#not joining value since it could be any base type.
				#print "\n";
				#print "avp code = $code_avp \n";
				#print "flags avp dec = $flags_avp_dec \n";
				#print "avp code dec = $code_avp_dec \n";
				#print "avp flags = $flags_avp \n";
				#print "avp length = $len_avp \n";
				#print "avp length dec = $len_avp_dec \n";	
				#print "avp value = $value_avp \n";
				#print "avp value len dec = $value_avp_len_dec \n";
				
				$avp_tables[$i][0] = $code_avp;
				$avp_tables[$i][1] = $flags_avp;
				$avp_tables[$i][2] = $len_avp;
				if($flags_avp_dec==192) {
					$avp_tables[$i][3] = $vendorid_avp;
                			$avp_tables[$i][4] = $value_avp;
        	    		} else {
	                		$avp_tables[$i][3] = $value_avp;
                		}
                		#padding calculation for avp
				if ($value_avp_len_dec%4 > 0) {
                    			$padding_len_dec = 4-($value_avp_len_dec%4);
                		} else {
                    			$padding_len_dec = 0;
                		}
                		#print "padding length dec = $padding_len_dec \n";      

                		@padding = splice(@avp, $start_avp, $padding_len_dec);
                		$padding = join('', @padding);
                		if ($value_avp_len_dec%4 > 0) {
                    			if($flags_avp_dec==192) {
                        			$avp_tables[$i][5] = $padding;
                    			} else {
                        			$avp_tables[$i][4] = $padding;
                    			}
                		} else {
                    			#do nothing 
                		}
                		$new_value_avp = '';

				# grouped avp handling
				if (grep {$_ eq $code_avp_dec} @grouped_avp) {
					#print "\n ============== found grouped avp! =============== \n";
					for ($k = 0; $k<20; $k++) {     #max sub avp no=20
						if (@value_avp) {
							@code_sub_avp = splice(@value_avp, $start_avp, 4);
							$code_sub_avp = join('',@code_sub_avp);
							$code_sub_avp_dec = cnv($code_sub_avp,16,10);

							@flags_sub_avp = splice(@value_avp, $start_avp, 1);
							$flags_sub_avp = join('',@flags_sub_avp);
							$flags_sub_avp_dec = cnv($flags_sub_avp,16,10);
							#print "\nflags sub avp dec = $flags_sub_avp_dec \n";

							@len_sub_avp = splice(@value_avp, $start_avp, 3);
							$len_sub_avp = join('',@len_sub_avp);
							$len_sub_avp_dec = cnv($len_sub_avp,16,10);
							
							if ($flags_sub_avp_dec == 192) { # both vendor id + mandatory flag is set
								@vendorid_sub_avp = splice(@value_avp, $start_avp, 4);
								$vendorid_sub_avp = join('',@vendorid_sub_avp);
								$vendorid_sub_avp_dec = cnv($vendorid_sub_avp,16,10);

								# avp value
								@value_sub_avp = splice(@value_avp, $start_avp, $len_sub_avp_dec-12);
							} elsif ($flags_sub_avp_dec == 64) { # only mandatory flag is set
								$vendorid_sub_avp = '';
								@value_sub_avp = splice(@value_avp, $start_avp, $len_sub_avp_dec-8);
							} else {
								# do nothing, it's undefined
							}
							$value_sub_avp_len_dec = scalar(@value_sub_avp);
							$value_sub_avp = join('',@value_sub_avp);
							if ($value_sub_avp_len_dec%4 > 0) {
                                				$sub_padding_len_dec = 4-($value_sub_avp_len_dec%4);
                            				} else {
                                				$sub_padding_len_dec = 0;
                            				}
                            				@sub_padding = splice(@value_avp, $start_avp, $sub_padding_len_dec);
                            				$sub_padding = join('',@sub_padding);

							if ($code == $code_sub_avp_dec) {
			                    			#print "what is the new value?\n";
                        	    				#$new_value = <>;
                            					#print "new_value = $new_value\n\n";
                                				$value_sub_avp = $new_value;
								$new_value_avp = $new_value_avp.$code_sub_avp.$flags_sub_avp.$len_sub_avp.$vendorid_sub_avp.$value_sub_avp.$sub_padding;
				   				$flag = 1;
							} else {
								$new_value_avp = $new_value_avp.$code_sub_avp.$flags_sub_avp.$len_sub_avp.$vendorid_sub_avp.$value_sub_avp.$sub_padding;					
							}
							if($flags_avp_dec==192) {
                                				$avp_tables[$i][4] = $new_value_avp;
                            				} else {
                                				$avp_tables[$i][3] = $new_value_avp;
                            				}
                            				#print "\n";
							#print "sub avp code :$code_sub_avp_dec \n";
							#print "sub avp flags :$flags_sub_avp \n";
							#print "sub avp len :$len_sub_avp_dec \n";
							#print "sub avp value :$value_sub_avp \n";

							$new_value_sub_avp = '';
							# sub grouped handling
							if (grep {$_ eq $code_sub_avp_dec} @grouped_avp) {
								#print "\n >>>>>>>>>> found sub grouped avp! <<<<<<<<<<<<< \n";
								for ($m = 0; $m<20; $m++) {# max nuo of sub sub avp's
									if (@value_sub_avp) {
										@code_sub_sub_avp = splice(@value_sub_avp, $start_avp, 4);
										$code_sub_sub_avp = join('',@code_sub_sub_avp);
										$code_sub_sub_avp_dec = cnv($code_sub_sub_avp,16,10);

										@flags_sub_sub_avp = splice(@value_sub_avp, $start_avp, 1);
										$flags_sub_sub_avp = join('',@flags_sub_sub_avp);
										$flags_sub_sub_avp_dec = cnv($flags_sub_sub_avp,16,10);
										#print "flags sub sub avp dec = $flags_sub_sub_avp_dec ";

										@len_sub_sub_avp = splice(@value_sub_avp, $start_avp, 3);
										$len_sub_sub_avp = join('',@len_sub_sub_avp);
										$len_sub_sub_avp_dec = cnv($len_sub_sub_avp,16,10);
										
										if ($flags_sub_sub_avp_dec == 192) { #both vendor id + mandatory flag is set
											@vendorid_sub_sub_avp = splice(@value_sub_avp, $start_avp, 4);
											$vendorid_sub_sub_avp = join('',@vendorid_sub_sub_avp);
											$vendorid_sub_sub_avp_dec = cnv($vendorid_sub_sub_avp,16,10);

											# avp value
											@value_sub_sub_avp = splice(@value_sub_avp, $start_avp, $len_sub_sub_avp_dec-12);
										} elsif ($flags_sub_sub_avp_dec == 64) { #only mandatory flag is set
											$vendorid_sub_sub_avp = '';
											@value_sub_sub_avp = splice(@value_sub_avp, $start_avp, $len_sub_sub_avp_dec-8);
										} else {
											# do nothing, it's undefined
										}
										$value_sub_sub_avp_len_dec = scalar(@value_sub_sub_avp);
										$value_sub_sub_avp = join('',@value_sub_sub_avp);
										if ($value_sub_sub_avp_len_dec%4 > 0) { #padding exits
                                            						$sub_sub_padding_len_dec = 4-($value_sub_sub_avp_len_dec%4);
                                        					} else { # no padding
                                            						$sub_sub_padding_len_dec = 0;
                                        					}
                                        					@sub_sub_padding = splice(@value_sub_avp, $start_avp, $sub_sub_padding_len_dec);
                                        					$sub_sub_padding = join('',@sub_sub_padding);

										if ($code == $code_sub_sub_avp_dec) {
                       									#print "what is the new value?\n";
	                                        					#$new_value = <>;
                       									#print "new_value = $new_value\n\n";
                       									$value_sub_sub_avp = $new_value;
											$new_value_sub_avp = $new_value_sub_avp.$code_sub_sub_avp.$flags_sub_sub_avp.$len_sub_sub_avp.$vendorid_sub_sub_avp.$value_sub_sub_avp.$sub_sub_padding;
			       								$flag = 1;
										} else {
											$new_value_sub_avp = $new_value_sub_avp.$code_sub_sub_avp.$flags_sub_sub_avp.$len_sub_sub_avp.$vendorid_sub_sub_avp.$value_sub_sub_avp.$sub_sub_padding;
										}

										#print "\n";
										#print "sub sub avp code : $code_sub_sub_avp_dec \n";
										#print "sub sub avp flags : $flags_sub_sub_avp \n";
										#print "sub sub avp len : $len_sub_sub_avp_dec \n";
										#print "sub sub avp value : $value_sub_sub_avp\n";

										$total_len_sub_sub = $len_sub_sub_avp_dec + $sub_sub_padding_len_dec;
									} else {
										last;
									}
								}
								$new_value_merge_avp = $code_sub_avp.$flags_sub_avp.$len_sub_avp.$vendorid_sub_avp.$new_value_sub_avp.$sub_padding;
                                				if($flags_avp_dec==192) {
                                   					$avp_tables[$i][4] = $new_value_merge_avp;
                                				} else {
                                    					$avp_tables[$i][3] = $new_value_merge_avp;
                                				}

							}
							$total_len_sub = $len_sub_avp_dec + $sub_padding_len_dec;
						} else {
							last;
						}
					}
				} else {
					# do nothing
					
					#print "padding : @padding \n";
					#print "avp after remove padding : @avp \n";
					$total_len = $len_avp_dec + $padding_len_dec;
					#print "total len : $total_len \n \n"
				}	
			} else {
				last;
			}
		}
		for(my $a = 0; $a < 100; $a++) {
                        $result = $result.$avp_tables[$a][0].$avp_tables[$a][1].$avp_tables[$a][2].$avp_tables[$a][3].$avp_tables[$a][4].$avp_tables[$a][5];
                }

		if ($flag == 0) {
		print "entered code did not match; please try again\n";
		} else { 
		print "\n------------after changing----------------->\n";
		print "$result";
		#print Dumper(@avp_tables);
		print "\n<------------------------------\n";
		}
	}
	# ============
	#print "@packet_split\n";
	@tcp_header = splice(@packet_split, 0, $tcp_header_len);
	@diameter_header = splice(@packet_split, 0, 20);
	$diameter_header = join('',@diameter_header);
	#print "printing diameter header @diameter_header\n";	
	#my @packet_specific = splice(@packet_split, $packcount, $packetlen_dec);
	$packet_send = $diameter_header.$result;
	#print "printing packet_send $packet_send\n";
	$packet_send = hex_to_ascii($packet_send);
	# print "\n@packet_specific \n";
	my $size = $socket->send($packet_send);
	#$socket->send($packet_send);
	print "sent data of length $size\n";
	#print "debug \n";
	# notify server that request has been sent
	shutdown($socket, 1);

	# closing socket
	$socket->close();	

}

$pcap = Net::Pcap::open_offline($file, \$err)
        or die "Can't read '$file': $err\n";

Net::Pcap::loop($pcap, $counter, \&process_packet, '');

Net::Pcap::close($pcap);

print "Number of packets = $count\n";
	


                
