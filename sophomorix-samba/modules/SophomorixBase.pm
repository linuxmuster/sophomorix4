#!/usr/bin/perl -w
# This perl module SophomorixBase is maintained by Rüdiger Beck
# It is Free Software (License GPLv3)
# If you find errors, contact the author
# jeffbeck@web.de  or  jeffbeck@linuxmuster.net

package Sophomorix::SophomorixBase;
require Exporter;
use File::Basename;
use Time::Local;
use Config::IniFiles;
#use Unicode::GCString;
use Encode qw(decode encode);
use LaTeX::Encode ':all';
use File::Temp qw/ tempfile tempdir /;
use Math::Round;
use Text::Iconv;

use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 

# use Net::LDAP::SID;  17.10 18.04

@ISA = qw(Exporter);

@EXPORT_OK = qw( 
               );
@EXPORT = qw(
            print_line
            print_title
            mount_school
            umount_school
            testmount_school
            create_schoollist
            NTACL_set_file
            remove_from_list
            ymdhms_to_date
            ymdhms_to_epoch
            epoch_to_ymdhms
            unlock_sophomorix
            lock_sophomorix
            log_script_start
            log_script_end
            log_script_exit
            get_login_avoid
            create_test_login
            backup_auk_file
            get_passwd_charlist
            get_plain_password
            create_plain_password
            check_options
            config_sophomorix_read
            result_sophomorix_init
            result_sophomorix_add
            result_sophomorix_add_log
            result_sophomorix_add_summary
            result_sophomorix_check_exit
            result_sophomorix_print
            filelist_fetch
            smbclient_dirlist
            dir_listing_user
            dns_query_ip
            remove_whitespace
            remove_embracing_whitespace
            json_progress_print
            json_dump
            console_print_mail_user
            console_print_quota_user
            console_print_mailquota_user
            analyze_smbcquotas_out
            get_homedirectory
            get_sharedirectory
            get_group_basename
            recode_utf8_to_ascii
            read_encoding_data
            analyze_encoding
            print_analyzed_encoding
            read_smb_conf
            test_webui_permission
            call_sophomorix_command
            string_to_latex
            get_lang_from_config
            read_sophomorix_add
            read_sophomorix_update
            read_sophomorix_kill
            run_hook_scripts
            smb_command
            smbpasswd_command
            smb_file_rewrite
            );


# formatted printout
######################################################################
sub print_line {
   print "========================================",
         "========================================\n";
}



sub print_title {
    # type: top (no \n after title)
    # type: bottom (no \n before title)
    # type: slim always use oneliner
    my ($a,$type) = @_;
    if (not defined $type){
        $type="standard";
    }
    if($Conf::log_level>=2 and $type ne "slim"){
        if ($type eq "bottom"){
            # no \n
        } else {
            print "\n";
        }
        print "#########################################",
              "#########################################\n";
        printf "# %-79s#\n",$a;
        print "#########################################",
              "#########################################\n";
        if ($type eq "top"){
            # no \n
        } else {
            print "\n";
        }
    } else {
        printf "#### %-73s####\n",$a;
    }
}



# mount/umount school
######################################################################
sub mount_school {
    # mountpoint=filesystem directory
    # 
    my ($share,$root_dns,$smb_admin_pass,$ref_sophomorix_config)=@_;
    &print_title("Mounting school $share $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}");
    my $smb_unc;
    my $mountpoint;
    if ($share eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'} or
        $share eq $DevelConf::AD_global_ou or
        $share eq $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}){
        # global share (global/GLOBAL/linuxmuster-global will work)
        $smb_unc="//".$root_dns."/".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
        $mountpoint=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'MOUNTPOINT'};
    } else {
        # school share
        $smb_unc="//".$root_dns."/".$share;
        $mountpoint=$ref_sophomorix_config->{'SCHOOLS'}{$share}{'MOUNTPOINT'};
    }
    if ( not defined $mountpoint){
        print "\nERROR: No mountpoint found for $share (Not a school?)\n\n";
        exit 88;
    }

    # test if it is mounted already
    my $res1=&testmount_school($mountpoint,$smb_unc,$ref_sophomorix_config,0);
    if ($res1 eq "TRUE"){
        print "\n   $smb_unc is mounted already\n\n";
        return;
    }

    # mount
    system ("install -oroot -groot --mode=0755 -d $mountpoint");
    my $user=$DevelConf::sophomorix_AD_admin;
    my $mount_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'MOUNT'}.
                      " -t cifs -o user=".
                      $user.
                      ",pass=\"".
                      $smb_admin_pass.
                      "\",domain=".
                      $ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}.
                      " ".
                      $smb_unc.
                      " ".
                      $mountpoint."/";
    print "COMMAND: $mount_command\n";
    system($mount_command);

    # Test if mount was successful
    my $res2=&testmount_school($mountpoint,$smb_unc,$ref_sophomorix_config,0);
    if ($res2 eq "FALSE"){
        print "\nERROR: $smb_unc not mounted to $mountpoint\n\n";
    }
}



sub testmount_school {
    my ($mountpoint,$smb_unc,$ref_sophomorix_config,$list)=@_;
    # collect data from system
    my %mounts=();
    open(PROCMOUNTS, $ref_sophomorix_config->{'INI'}{'PATHS'}{'PROCMOUNTS'}) or die "Mount File not found";
    while(<PROCMOUNTS>){
        my ($unc,$mpoint,$mtype,$mopts) = split(/ +/, $_);
        if ($mtype eq "cifs"){ # care only about cifs mounts
        $mounts{$unc}{'MPOINT'}=$mpoint;
        $mounts{$unc}{'MTYPE'}=$mtype;
        $mounts{$unc}{'MOPTS'}=$mopts;
        }
    }
    close(PROCMOUNTS);
    if ($list==1){
        ##### list
        my @unc_list=();
        my $line="+------------------------------------------+------------------------------------+\n";
        print "\n";
        print "List of cifs mounts on this server:\n";
        foreach my $unc (keys %mounts) {
            push @unc_list,$unc;
        }
	@unc_list = sort @unc_list;
        print $line;
        print    "| Mountpoint                               | UNC-Path                           |\n";
        print $line;
        foreach my $unc (@unc_list){
            printf "| %-41s| %-35s|\n",$mounts{$unc}{'MPOINT'},$unc;
        }
        print $line;
    } else {
        ##### test
        if (exists $mounts{$smb_unc} and $mounts{$smb_unc}{'MPOINT'} eq $mountpoint){
	    print "OK: UNC-Path $smb_unc  is mounted to $mountpoint as $mounts{$smb_unc}{'MTYPE'}\n";
            return "TRUE";
        } else {
            return "FALSE";
        }
    }
}



sub umount_school {
    my ($share,$root_dns,$ref_sophomorix_config)=@_;
    &print_title("Umounting school $share $DevelConf::AD_global_ou $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}");
    my $mountpoint;
    if ($share eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'} or
        $share eq $DevelConf::AD_global_ou){
        $mountpoint=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'MOUNTPOINT'};
    } else {
        $mountpoint=$ref_sophomorix_config->{'SCHOOLS'}{$share}{'MOUNTPOINT'};
    }
    if (defined $mountpoint){
        my $umount_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'UMOUNT'}." ".$mountpoint;
        print "COMMAND: $umount_command\n";
        my $return=system($umount_command);
    }
}



sub create_schoollist {
    my ($opt_school,$ref_sophomorix_config)=@_;
    my @schoollist=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    if ($opt_school eq "---"){
        @schoollist=($DevelConf::name_default_school);
    } elsif ($opt_school ne ""){
        @schoollist=split(/,/,$opt_school);
        foreach my $school (@schoollist){
            if (not exists $ref_sophomorix_config->{'SCHOOLS'}{$school}){
                print "ERROR: $school is not a valid school\n";
                exit;
            }
        }
    }
    return (@schoollist);
}



# mail stuff
######################################################################
sub alias_from_name {
    my ($surname,$firstname,$root_dns,$ref_sophomorix_config)=@_;
    $surname=~tr/A-Z/a-z/; # make lowercase
    $firstname=~tr/A-Z/a-z/; # make lowercase
    my $alias_short=$firstname.".".$surname;
    my $alias_long=$firstname.".".$surname."\@".$root_dns;
    # print "TEST: Alias is $alias\n";
    return ($alias_short,$alias_long);
}



# json stuff
######################################################################
sub json_progress_print {
    my ($arg_ref) = @_;
    my $ref_progress = $arg_ref->{ref_progress};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    if ($json==1){
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_pretty_printed = $json_obj->pretty->encode( $ref_progress );
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'}} "# JSON-begin\n";
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'}} "$utf8_pretty_printed\n";
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'}} "# JSON-end\n";
    } elsif ($json==2){
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_json_line   = $json_obj->encode( $ref_progress );
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'}} "# JSON-begin\n";
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'}} "$utf8_json_line\n";
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'}} "# JSON-end\n";
    } elsif ($json==3){
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PROGRESS'}} Dumper( $ref_progress );
   }
}



sub json_dump {
    my ($arg_ref) = @_;
    my $jsoninfo = $arg_ref->{jsoninfo};
    my $jsoncomment = $arg_ref->{jsoncomment};
    my $json = $arg_ref->{json};
    my $log_level = $arg_ref->{log_level};
    my $hash_ref = $arg_ref->{hash_ref};
    my $role = $arg_ref->{role};
    my $type = $arg_ref->{type};
    my $object_name = $arg_ref->{object_name};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    # json 
    if ($json==0){
        if ($jsoninfo eq "SESSIONS"){
            &_console_print_sessions($hash_ref,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "ONESESSION"){
            &_console_print_onesession($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "DEVICE"){
            &_console_print_device_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "DEVICES"){
            &_console_print_devices($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "ADMINS_V"){
            &_console_print_admins_v($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "USERS_V"){
            &_console_print_users_v($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "USERS_OVERVIEW"){
            &_console_print_users_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "USER"){
            # incl. administrators            
            &_console_print_user_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "EXAMUSER"){
            &_console_print_examusers($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "PROJECTS_OVERVIEW"){
            &_console_print_projects_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "PROJECT"){
            &_console_print_group_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config,"project");
        } elsif ($jsoninfo eq "CLASSES_OVERVIEW"){
            &_console_print_classes_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config,$type);
        } elsif ($jsoninfo eq "CLASS"){
            &_console_print_group_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config,"class");
        } elsif ($jsoninfo eq "GROUPS_OVERVIEW"){
            &_console_print_groups_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "ROOM"){
            &_console_print_group_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config,"room");
        } elsif ($jsoninfo eq "GROUP"){
            &_console_print_group_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config,"sophomorix-group");
        } elsif ($jsoninfo eq "MANAGEMENTGROUPS_OVERVIEW"){
            &_console_print_managementgroups_overview($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "MANAGEMENTGROUP"){
            &_console_print_group_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config,"managementgroup");
        } elsif ($jsoninfo eq "MAIL"){
            &_console_print_mail_full($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "SHARES"){
            &_console_print_shares($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "UI"){
            &_console_print_ui($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "SCHEMA_ATTRIBUTE"){
            &_console_print_schema_attribute($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "PRINTDATA"){
            &_console_print_printdata($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "ADDFILE"){
            &_console_print_addfile($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "UPDATEFILE"){
            &_console_print_updatefile($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "KILLFILE"){
            &_console_print_killfile($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        } elsif ($jsoninfo eq "DIRLISTING"){
            &_console_print_dirlisting($hash_ref,$object_name,$log_level,$ref_sophomorix_config);
        }
    } elsif ($json==1){
        # pretty output
        $hash_ref->{'JSONINFO'}=$jsoninfo;
        $hash_ref->{'JSONCOMMENT'}=$jsoncomment;
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_pretty_printed = $json_obj->pretty->encode( $hash_ref );
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} "# JSON-begin\n";
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} "$utf8_pretty_printed\n";
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} "# JSON-end\n";
    } elsif ($json==2){
        # compact output
        $hash_ref->{'JSONINFO'}=$jsoninfo;
        $hash_ref->{'JSONCOMMENT'}=$jsoncomment;
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_json_line   = $json_obj->encode( $hash_ref  );
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} "# JSON-begin\n";
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} "$utf8_json_line\n";
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} "# JSON-end\n";
    } elsif ($json==3){
        &print_title("DUMP: $jsoncomment");
        print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_PRINTOUT'}} Dumper( $hash_ref );
    } elsif ($json==4){
        # pretty output in file
        $hash_ref->{'JSONINFO'}=$jsoninfo;
        $hash_ref->{'JSONCOMMENT'}=$jsoncomment;
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_pretty_printed = $json_obj->pretty->encode( $hash_ref );
        my $output=$ref_sophomorix_config->{'INI'}{'PATHS'}{'JSON_OUTPUT_PATH'}."/output.json";
	print "output to file $output\n";
        open(my $fh, ">", $output);
        print $fh $utf8_pretty_printed;
        close($fh);
    } elsif ($json==5){
        # compact output in file
        $hash_ref->{'JSONINFO'}=$jsoninfo;
        $hash_ref->{'JSONCOMMENT'}=$jsoncomment;
        my $json_obj = JSON->new->allow_nonref;
        my $utf8_json_line   = $json_obj->encode( $hash_ref  );
        my $output=$ref_sophomorix_config->{'INI'}{'PATHS'}{'JSON_OUTPUT_PATH'}."/output.json";
	print "output to file $output\n";
        open(my $fh, ">", $output);
        print $fh $utf8_json_line;
        close($fh);
    }
}



sub _console_print_sessions {
    my ($ref_sessions,$log_level,$ref_sophomorix_config)=@_;
    my $line="+---------------------+------------+-----------------------------------------\n";
    print "$ref_sessions->{'SESSIONCOUNT'} sessions by Session-Name:\n";
    print $line;
    printf "| %-20s|%11s | %-80s\n",
                "Session-ID", 
                " supervisor",
                "sophomorixSessions";
    print $line;
    foreach my $session (@{ $ref_sessions->{'ID_LIST'} }){
        printf "| %-20s|%11s | %-80s\n",
                $session, 
                $ref_sessions->{'ID'}{$session}{'SUPERVISOR'}{'sAMAccountName'},
                $ref_sessions->{'ID'}{$session}{'sophomorixSessions'};
        }
    print $line;
    print "$ref_sessions->{'SESSIONCOUNT'} sessions in total\n";
}



sub _console_print_onesession {
    my ($ref_sessions,$object_name,$log_level,$ref_sophomorix_config)=@_;
    &print_line();
    print "$ref_sessions->{'ID'}{$object_name}{'COMMENT'}  (Session-ID $object_name):\n";
    &print_line();
    my $supervisor=$ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'sAMAccountName'};
    my $exammode_string;
    if ($ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'sophomorixExamMode'} eq "---"){
        $exammode_string="ExamMode: OFF";
    } else {
        $exammode_string="ExamMode of $supervisor ON by ".$ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'sophomorixExamMode'};
    }
    print "Supervisor: $supervisor ",
          " ($ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'givenName'} ",
          "$ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'sn'})",
          "  $exammode_string\n";
    print "  $ref_sessions->{'ID'}{$object_name}{'SUPERVISOR'}{'SMBhomeDirectory'}\n";
    foreach my $item (@{ $ref_sessions->{'TRANSFER_DIRS'}{$supervisor}{'TRANSFER_LIST'} }){
        print "      $ref_sessions->{'TRANSFER_DIRS'}{$supervisor}{'TRANSFER'}{$item}{'TYPE'}  $item\n";
    }
    print "$ref_sessions->{'ID'}{$object_name}{'PARTICIPANT_COUNT'} participants:\n";
    &print_line();
    foreach my $participant (@{ $ref_sessions->{'ID'}{$object_name}{'PARTICIPANT_LIST'} }){
        my $exammode_string;
        if ($ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'sophomorixExamMode'} eq "---"){
            $exammode_string="OFF";
        } else {
            $exammode_string="ON by ".$ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'sophomorixExamMode'};
        }
        print "Participant: $participant",
              " ($ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'givenName'} ",
              "$ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'sn'})",
              " ExamMode: $exammode_string\n";
        foreach my $grouptype (@{ $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'} }){
            printf "      %-16s%-20s\n",
                $grouptype.":",
                $ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'group_'.$grouptype};
        }
        print "  $ref_sessions->{'ID'}{$object_name}{'PARTICIPANTS'}{$participant}{'SMBhomeDirectory'}\n";
        foreach my $item (@{ $ref_sessions->{'TRANSFER_DIRS'}{$participant}{'TRANSFER_LIST'} }){
            print "      $ref_sessions->{'TRANSFER_DIRS'}{$participant}{'TRANSFER'}{$item}{'TYPE'}  $item\n";
        }
        print "------------------------------------------------------------\n"
    }
    &print_line();
}



sub _console_print_devices {
    my ($ref_devices,$school_opt,$log_level,$ref_sophomorix_config)=@_;

    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    my $line=     "+---------------------------------------------------------------------------------+\n";
    my $line_dev ="+----------------+----------------+-------------+---------------------------------+\n";
    my $head_dev ="| dnsNode          IPv4             Room          sophomorixComment               |\n";
    my $line_room="+---------------------+-------+---------------------------------------------------+\n";
    my $head_room="| Room                  Comp.   description                                       |\n";
    my $line_dgr= "+------------------------+-------+------------------------------------------------+\n";
    my $head_dgr= "| Devicegroup              Comp.   description                                    |\n";
    foreach my $school (@school_list){
        # rooms
        my $school_rooms_count=$#{ $ref_devices->{'LISTS'}{'ROOM_BY_sophomorixSchoolname'}{$school}{'rooms'} }+1;
        print "\n";
        print $line;
	printf "| %-80s|\n",$school_rooms_count." Rooms in school $school:";
        print $head_room;
        print $line_room;
        foreach my $room (@{ $ref_devices->{'LISTS'}{'ROOM_BY_sophomorixSchoolname'}{$school}{'rooms'} }){
            printf "| %-20s| %5s | %-50s|\n",
                $room, 
                $#{ $ref_devices->{'room'}{$room}{'sophomorixRoomComputers'} }+1,
                $ref_devices->{'room'}{$room}{'description'};
        }
        print $line_room;
        print $head_room;
	printf "| %-80s|\n"," ... ".$school_rooms_count." Rooms in school $school";
        print $line;
        print "\n";

        # devices
        my $school_devices_count=$#{ $ref_devices->{'LISTS'}{'DEVICE_BY_sophomorixSchoolname'}{$school}{'dnsNodes'} }+1;
        #print "\n";
        print $line;
	printf "| %-80s|\n",$school_devices_count." Devices in school $school:";
        foreach my $role (@{ $ref_sophomorix_config->{'LISTS'}{'ROLE_DEVICE'} }){
            my $role_alt=$ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}{$role};

            my $device_string;
            if ($ref_sophomorix_config->{'INI'}{"computerrole.".$role}{'COMPUTER_ACCOUNT'} eq "TRUE"){
                $device_string="dnsNode+computer";
            } else {
                $device_string="dnsNode";
            }

            my $host_group_string;
            if ($ref_sophomorix_config->{'INI'}{"computerrole.".$role}{'HOST_GROUP'} eq "TRUE"){
                $host_group_string=",hostgroup";
            } else {
                $host_group_string="";
            }

            # skip when there are 0 devices
            my $number_of_devices=$#{ $ref_devices->{'LISTS'}{'DEVICE_BY_sophomorixSchoolname'}{$school}{$role} }+1;
            if ($number_of_devices==0){
                # no device of this role
                next;
            }
            # one device per line
            print $line;
            printf "| %-80s|\n",$number_of_devices." ".$role." (".$role_alt.", ".$device_string.$host_group_string."):";
            print $head_dev;
            print $line_dev;
            foreach my $dns_node ( @{ $ref_devices->{'LISTS'}{'DEVICE_BY_sophomorixSchoolname'}{$school}{$role} } ){
                my $computer;
                my $dgr;
                my $adminclass;
                my $mac;
                if (exists $ref_devices->{'LOOKUP'}{'sAMAccountName_BY_sophomorixDnsNodename'}{$dns_node}){
                    $computer=$ref_devices->{'LOOKUP'}{'sAMAccountName_BY_sophomorixDnsNodename'}{$dns_node};
                    $dgr="";
                    $adminclass=$ref_devices->{'computer'}{$computer}{'sophomorixAdminClass'};
                    $mac=$ref_devices->{'computer'}{$computer}{'sophomorixComputerMAC'};
                } else {
                    $computer="---";
                    $dgr="---";
                    $adminclass="---";
                    $mac="---";
                }

                # sophomorixRole and sophomorixComment
                my $role_short;
                if (not exists $ref_devices->{'computer'}{$computer}{'sophomorixRole'}){
                    $role_short="---";
                } else {
                    $role_short=$ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}{$role};
                }
                my $comment;
                if ( not exists $ref_devices->{'computer'}{$computer}{'sophomorixComment'} ){ 
		    $comment=" ";
                } elsif ( $ref_devices->{'computer'}{$computer}{'sophomorixComment'} eq "---" ){
	  	    $comment=" ";
                } else {
		    $comment=$ref_devices->{'computer'}{$computer}{'sophomorixComment'};
                }
                my $role_display=$comment.$role_short;

                printf "| %-15s| %-15s| %-12s| %-32s|\n",
                       $dns_node,
                       $ref_devices->{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dns_node}{'IPv4'},
                       $adminclass,
                       $comment;
            }
            print $line_dev;
            print $head_dev;
            printf "| %-80s|\n"," ... ".$number_of_devices." ".$role." (".$role_alt.", ".$device_string.$host_group_string.")";
            print $line;
            #print "    /-/#: sophomorixComment nonexisting/---/existing\n";

            # showing help
            # my @role_help=();
            # foreach my $keyname (keys %{$ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}} ) {
            #     push @role_help, "$ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}{$keyname}: $keyname";
            # }
            # @role_help = sort @role_help;
            #
            # my $count=0;
            # foreach my $item (@role_help){
            #     if ( int($count/2)*2==$count){
            #         #print "even $count\n";
	    # 	      if (defined $role_help[$count+1]){
	    # 	          printf "   %-34s %-34s \n",$role_help[$count],$role_help[$count+1];
            #         } else {
            #             # last element
	    # 	          printf "   %-34s %-34s \n",$role_help[$count],"";
            #         }
            #     } else {
            #         #print "odd  $count\n";
	    #     }
            #     $count++;
            # }
        }
        if ($school_devices_count==0){
	    print $line;
        }
    }

    # global part
    my $dgr_global_count=$#{ $ref_devices->{'LIST_DEVICEGROUPS'} }+1;
    print "\n";
    print $line;
    printf "| %-80s|\n","".$dgr_global_count." Devicegroups (global):";
    print $head_dgr;
    print $line_dgr;
        foreach my $dgr (@{ $ref_devices->{'LIST_DEVICEGROUPS'} }) {
            printf "| %-23s| %5s | %-46s |\n",
                $dgr,
                $#{ $ref_devices->{$ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}}{$dgr}{'member'} }+1,
                $ref_devices->{$ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}}{$dgr}{'description'};
        }
    print $line_dgr;
    print $head_dgr;
    printf "| %-80s|\n"," ... ".$dgr_global_count." Devicegroups (global)";
    print $line;
}



sub _console_print_classes_overview {
    my ($ref_groups_v,$school_opt,$log_level,$ref_sophomorix_config,$class_type)=@_;
    my $line  ="+--------------------+--+--+--+---+--+-+-+-+-+-+--------------------------------+\n";
    my $line2 ="+-------------------------------------------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq "" or $school_opt eq "---"){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    foreach my $school (@school_list){
        my $string;
        if ($class_type eq "class"){
            $string=$class_type." (admin-/extra-/teacherclass) in school ".$school.":";
	} else {
	    $string=$class_type." in school ".$school.":";
	}

        print "\n";
        &print_title("$ref_groups_v->{'COUNTER'}{$school}{'by_type'}{$class_type} $string");
        if ($ref_groups_v->{'COUNTER'}{$school}{'by_type'}{$class_type}==0){
            next;
        }
        print $line;
        print "| Class Name         | t| s| Q| MQ|MM|H|A|L|S|J| Class Description              |\n";
        print $line;
        foreach my $group ( @{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{$class_type} }){
            my $MQ;
            if ($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailQuota'} eq "---:---:"){
                $MQ=" - "; # unmodified
            } else {
                $MQ=" * "; # modified
            }
            my $Q=0;
            foreach my $quota ( @{ $ref_groups_v->{'GROUPS'}{$group}{'sophomorixQuota'} }){
                my ($share,$value,$comment)=split(/:/,$quota);
		if ($value ne "---" or $comment ne "---"){
                    $Q++;
                }
            }
            printf "| %-19s|%2s|%2s|%2s|%3s|%2s|%1s|%1s|%1s|%1s|%1s| %-31s|\n",
                    $group,
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'teacher'},
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'student'},
                    $Q,
                    $MQ,
                    $ref_groups_v->{'GROUPS'}{$group}{'sophomorixMaxMembers'},
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixHidden'},0,1),
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailAlias'},0,1),
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailList'},0,1),
                    $ref_groups_v->{'GROUPS'}{$group}{'sophomorixStatus'},
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixJoinable'},0,1),
	            $ref_groups_v->{'GROUPS'}{$group}{'description'};
        }
        print $line;
        if ($class_type eq "class"){
            my $max_count=$#{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'class'} }+1;
            printf "| %-78s|\n", $max_count." admin-/extra-/teacherclass in ".$school;
        } else {
            my $max_count=$#{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{$class_type} }+1;
            printf "| %-78s|\n", $max_count." $class_type in ".$school;
        }
        print $line2;
        print "t=teachers  s=students   Q=Quota   MQ=MailQuota  MM=MaxMembers\n";
        print "H=Hidden    A=MailAlias  L=MaiList  S=Status      J=Joinable \n";
    }
}



sub _console_print_groups_overview {
    my ($ref_groups_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line="+-------------------+--+---+-+-+--+--+--+---------------------------------------+\n";
    my $line2 = "+-------------------------------------------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq "" or $school_opt eq "---"){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
    # display also global groups
    unshift @school_list,"global";

    foreach my $school (@school_list){
        print "\n";
        if (not defined $ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'sophomorix-group'} or
	    $ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'sophomorix-group'}==0
	    ){
            &print_title("0 sophomorix-groups in school $school:");
            next;
        }
        &print_title("$ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'sophomorix-group'} sophomorix-groups in school $school:");
        print $line;
        print "| Group Name        |AQ|AMQ|A|L| m| t| s| Group Description                     |\n";
        print $line;
        foreach my $group ( @{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'sophomorix-group'} }){
            my $AMQ;
            if ($ref_groups_v->{'GROUPS'}{$group}{'sophomorixAddMailQuota'} eq "---:---:"){
                $AMQ=" - "; # unmodified
            } else {
                $AMQ=" * "; # modified
            }
            my $AQ=0;
            foreach my $addquota ( @{ $ref_groups_v->{'GROUPS'}{$group}{'sophomorixAddQuota'} }){
                my ($share,$value,$comment)=split(/:/,$addquota);
		if ($value ne "---" or $comment ne "---"){
                    $AQ++;
                }
            }

            printf "| %-18s|%2s|%3s|%1s|%1s|%2s|%2s|%2s| %-38s|\n",
                $group,
                $AQ,
                $AMQ,
                substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailAlias'},0,1),
                substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailList'},0,1),
                $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'TOTAL'},
                $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'teacher'},
                $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'student'},
	        $ref_groups_v->{'GROUPS'}{$group}{'description'};
        }
        print $line;
        my $max_count=$#{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'sophomorix-group'} }+1;
        printf "| %-78s|\n", $max_count." sophomorix-groups in ".$school;
        print $line2;
        print "AQ=AddQuota  AMQ=AddMailQuota A=MailAlias   L=MaiList\n";
        print " m=member-entries             t=teachers    s=students\n";
    }
}



sub _console_print_managementgroups_overview {
    my ($ref_groups_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line="+------------------+----+----+----+----------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq "" or $school_opt eq "---"){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
 
    foreach my $school (@school_list){
        print "\n";
        &print_title("Managementgroups in school $school:");
        print $line;
        print "| Managementgroup  |  m |  t |  s | Group Description                            |\n";
        print $line;

        # walk through all the list of managementgroup-TYPES (sophomorixType)
        foreach my $grouptype ( @{ $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'} } ){
            # fetch all groups that have this sophomorixType
            foreach my $group ( @{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{$grouptype} }){
                printf "| %-17s|%4s|%4s|%4s| %-45s|\n",
                    $group,
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'TOTAL'},
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'teacher'},
                    $ref_groups_v->{'GROUPS'}{$group}{'member_COUNT'}{'student'},
	            $ref_groups_v->{'GROUPS'}{$group}{'description'};
            }
        }
        print $line;
        print "m=member-entries  t=teachers  s=students\n";
    }
}



sub _console_print_projects_overview {
    my ($ref_groups_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line = "+-----------------------+--+---+--+-+-+-+-+-+-----------------------------------+\n";
    my $line2 = "+-------------------------------------------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq "" or $school_opt eq "---"){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    foreach my $school (@school_list){
        print "\n";
        &print_title("$ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'project'} projects in school $school:");
        if ($ref_groups_v->{'COUNTER'}{$school}{'by_type'}{'project'}==0){
            next;
        }
        print $line;
        print "| Project Name          |AQ|AMQ|MM|H|A|L|S|J| Project Description               |\n";
        print $line;
        foreach my $group ( @{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'project'} }){
            my $AMQ;
            if ($ref_groups_v->{'GROUPS'}{$group}{'sophomorixAddMailQuota'} eq "---:---:"){
                $AMQ=" - "; # unmodified
            } else {
                $AMQ=" * "; # modified
            }
            my $AQ=0;
            foreach my $addquota ( @{ $ref_groups_v->{'GROUPS'}{$group}{'sophomorixAddQuota'} }){
                my ($share,$value,$comment)=split(/:/,$addquota);
		if ($value ne "---" or $comment ne "---"){
                    $AQ++;
                }
            }
            printf "| %-22s|%2s|%3s|%2s|%1s|%1s|%1s|%1s|%1s| %-34s|\n",
                    $group,
                    $AQ,
                    $AMQ,
                    $ref_groups_v->{'GROUPS'}{$group}{'sophomorixMaxMembers'},
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixHidden'},0,1),
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailAlias'},0,1),
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixMailList'},0,1),
                    $ref_groups_v->{'GROUPS'}{$group}{'sophomorixStatus'},
                    substr($ref_groups_v->{'GROUPS'}{$group}{'sophomorixJoinable'},0,1),
	            $ref_groups_v->{'GROUPS'}{$group}{'description'};
        }
        print $line;
        my $max_count=$#{ $ref_groups_v->{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$school}{'project'} }+1;
        printf "| %-78s|\n", $max_count." projects in ".$school;
        print $line2;
        print "AQ=AddQuota  AMQ=AddMailQuota  J=Joinable  MM=MaxMembers\n";
        print " A=MailAlias   L=MaiList       S=Status     H=Hidden\n";
    }
}



sub _console_print_schema_attribute {
    my ($ref_schema,$attribute,$log_level,$ref_sophomorix_config)=@_;
    my $line1="#####################################################################\n";
    my $line= "---------------------------------------------------------------------\n";

    if (exists $ref_schema->{'LDAPDisplayName'}{$attribute}){
        print "\n";
        print $line1;
        print "Schema attribute $attribute:\n";
        print "DN=$ref_schema->{'LDAPDisplayName'}{$attribute}{'DN'}\n";
        print $line1;

        # create an ascibetical list of keys
        my @list=();
        foreach my $key (keys %{ $ref_schema->{'LDAPDisplayName'}{$attribute} }) {
            if ($key eq "DN"){
            } else {
                push @list, $key;
            }
        }
        @list = sort @list;

        # display the keys
        foreach my $item (@list){
            foreach $value (@{ $ref_schema->{'LDAPDisplayName'}{$attribute}{$item} }){
                my $camel_case=$ref_schema->{'LOOKUP'}{'CamelCase'}{$item};
                #printf "%29s: %-40s\n",$item,$value; # all lowercase
                printf "%29s: %-40s\n",$camel_case,$value; # camelcase
            }
        }
        print $line;
    } else {
        print "\nAttribute $attribute not found\n";
        print "\nFor a list of all attributes use:\n";
        print "   sophomorix-samba --show-all-attributes\n\n";
    }
}



sub _console_print_printdata {
    my ($ref_printdata,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    
    &print_title("History of $ref_printdata->{'RESULT'}{'HISTORY'}{'TOTAL'} user additions:");
    my $back_in_time_count=0;
    my $line="+---------------------+---------------------+-------+-------------------+\n";
    print $line;
    print "| Option to use       | Date                | users | AD-Date           |\n";
    print $line;
    foreach my $ymdhms ( @{ $ref_printdata->{'LISTS'}{'sophomorixCreationDate'} } ){
        my $date=&ymdhms_to_date($ymdhms);
        my $count=$#{ $ref_printdata->{'LIST_BY_sophomorixCreationDate'}{$ymdhms}}+1;
        printf "| --back-in-time %-5s| %7s |%6s | %7s |\n",$back_in_time_count, $date, $count, $ymdhms;
        $back_in_time_count++;
    }
    print $line;
}



sub _console_print_addfile {
    my ($ref_addfile,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    print "\n";
    print "A total of $ref_addfile->{'COUNTER'}{'TOTAL'} users can be added:\n";
    print "\n";
    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
    my $line = "+-+-------------+-------------+------------------------------------+---------------+-----------------+\n";
    foreach my $school (@school_list){
        if (not defined $ref_addfile->{'COUNTER'}{'SCHOOL'}{$school} or
            $ref_addfile->{'COUNTER'}{'SCHOOL'}{$school}==0){
            print "School: $school (0  users can be added)\n";
            print "\n";
            next;
        } else {
            print "School: $school ($ref_addfile->{'COUNTER'}{'SCHOOL'}{$school} users can be added)\n";
        }

        print $line;
        printf "|%-1s| %-12s| %-12s| %-35s| %-14s| %-16s|\n",
               "R",
               "Login",
               "adminclass",
               "Identifier",
               "unid",
               "Password";
        print $line;

        foreach my $sam ( @{ $ref_addfile->{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school} } ){

            my $role_display;
            if ($ref_addfile->{'USER'}{$sam}{'ROLE'} eq "student"){
                $role_display="s";
            } elsif ($ref_addfile->{'USER'}{$sam}{'ROLE'} eq "teacher"){
                $role_display="t";
            } else {
                $role_display="?";
            }
            printf "|%-1s| %-12s| %-12s| %-35s| %-14s| %-16s|\n",
                   $role_display,
                   $sam,
                   $ref_addfile->{'USER'}{$sam}{'ADMINCLASS'},
                   $ref_addfile->{'USER'}{$sam}{'IDENTIFIER'},
                   $ref_addfile->{'USER'}{$sam}{'UNID'},
                   $ref_addfile->{'USER'}{$sam}{'PWD_WISH'};
        }
        print $line;
        print "$ref_addfile->{'COUNTER'}{'SCHOOL'}{$school} users can be added in $school\n";
        print "\n";
    } 
    print "--> Total number of users to be added: $ref_addfile->{'COUNTER'}{'TOTAL'}\n\n";   
    print "Fields with --- are automatically created by sophomorix-add\n";
    print "R: sophomorixRole (s=student, t=teacher)\n";
}




sub _console_print_updatefile {
    my ($ref_updatefile,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $count=0;
    print "\n";
    print "A total of $ref_updatefile->{'COUNTER'}{'TOTAL'} users can be updated:\n";
    print "\n";
    my @school_list;
    if ($school_opt eq ""){
        @school_list=(@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} },
                      $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'});
    } else {
        @school_list=($school_opt);
    }
    my $line= "===================================================================================\n";
    foreach my $school (@school_list){
        if (not defined $ref_updatefile->{'COUNTER'}{'SCHOOL'}{$school} or
            $ref_updatefile->{'COUNTER'}{'SCHOOL'}{$school}==0){
            # typout
            print "\n";
            if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
                print "School: $school (0  users can change school)\n";
            } else {
                print "School: $school (0  users can be updated)\n";
            }

            print "\n";
            next;
        } else {
            print "\n";
            print $line;
            if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
                print "School: $school ($ref_updatefile->{'COUNTER'}{'SCHOOL'}{$school} users can change school)\n";
            } else {
                print "School: $school ($ref_updatefile->{'COUNTER'}{'SCHOOL'}{$school} users can be updated)\n";
            }
        }

        foreach my $sam ( @{ $ref_updatefile->{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school} } ){
            $count++;
            print $line;
            my $name_ascii_new=$ref_updatefile->{'USER'}{$sam}{'SURNAME_ASCII_NEW'}.
                               ", ".
                               $ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_ASCII_NEW'};
            my $name_utf8_new=$ref_updatefile->{'USER'}{$sam}{'SURNAME_UTF8_NEW'}.
                              ", ".
                              $ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_UTF8_NEW'};
            printf " %-82s\n", "User ".$count."/".$ref_updatefile->{'COUNTER'}{'TOTAL'}.": ".
		               $sam.
                               " (current name/school/role: ".
		               $ref_updatefile->{'USER'}{$sam}{'SURNAME_UTF8_OLD'}.
		               ", ".
                               $ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_UTF8_OLD'}.
                               "/".
                               $ref_updatefile->{'USER'}{$sam}{'SCHOOL_OLD'}.
                               "/".
                               $ref_updatefile->{'USER'}{$sam}{'ROLE_OLD'}.
                               "):";
            if ($ref_updatefile->{'USER'}{$sam}{'UNID_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixUnid",$ref_updatefile->{'USER'}{$sam}{'UNID_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'UNID_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'SURNAME_ASCII_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixSurnameASCII",$ref_updatefile->{'USER'}{$sam}{'SURNAME_ASCII_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'SURNAME_ASCII_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_ASCII_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixFirstnameASCII",$ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_ASCII_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_ASCII_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'BIRTHDATE_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixBirthdate",$ref_updatefile->{'USER'}{$sam}{'BIRTHDATE_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'BIRTHDATE_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'SURNAME_UTF8_NEW'} ne "---"){
                printf " %27s: %-53s\n","sn",$ref_updatefile->{'USER'}{$sam}{'SURNAME_UTF8_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'SURNAME_UTF8_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_UTF8_NEW'} ne "---"){
                printf " %27s: %-53s\n","givenName",$ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_UTF8_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_UTF8_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'SURNAME_INITIAL_UTF8_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixSurnameInitial",$ref_updatefile->{'USER'}{$sam}{'SURNAME_INITIAL_UTF8_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'SURNAME_INITIAL_UTF8_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_INITIAL_UTF8_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixFirstnameInitial",$ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_INITIAL_UTF8_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'FIRSTNAME_INITIAL_UTF8_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'FILE_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixAdminFile",$ref_updatefile->{'USER'}{$sam}{'FILE_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'FILE_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'STATUS_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixStatus",$ref_updatefile->{'USER'}{$sam}{'STATUS_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'STATUS_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'ROLE_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixRole",$ref_updatefile->{'USER'}{$sam}{'ROLE_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'ROLE_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'CLASS_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixAdminClass",$ref_updatefile->{'USER'}{$sam}{'CLASS_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'CLASS_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'SCHOOL_NEW'} ne "---"){
                printf " %27s: %-53s\n","sophomorixSchoolname",$ref_updatefile->{'USER'}{$sam}{'SCHOOL_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'SCHOOL_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'MAIL_NEW'} ne "---"){
                printf " %27s: %-53s\n","mail",$ref_updatefile->{'USER'}{$sam}{'MAIL_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'MAIL_NEW'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'HOMEDIRECTORY_NEW'} ne "---"){
                printf " %27s: %-53s\n","homeDirectory",$ref_updatefile->{'USER'}{$sam}{'HOMEDIRECTORY_OLD'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'HOMEDIRECTORY_NEW'}; 
            }
            if (defined $ref_updatefile->{'USER'}{$sam}{'HOMEDIRECTORY_NEW_REL'} and
                $ref_updatefile->{'USER'}{$sam}{'HOMEDIRECTORY_NEW_REL'} ne "---"
               ){
                printf " %27s: %-53s\n","sophomorixIntrinsic2",$ref_updatefile->{'USER'}{$sam}{'HOMEDIRECTORY_OLD_REL'}.
                                                              " --> ".
                                                              $ref_updatefile->{'USER'}{$sam}{'HOMEDIRECTORY_NEW_REL'}; 
            }
            if ($ref_updatefile->{'USER'}{$sam}{'WEBUI_STRING_NEW'} ne "---"){
                printf "  %-82s\n","sophomorixWebuiPermissionsCalculated:";
                printf "    %-80s\n",$ref_updatefile->{'USER'}{$sam}{'WEBUI_STRING_OLD'};
                printf "         %-75s\n","----->";
                printf "    %-80s\n",$ref_updatefile->{'USER'}{$sam}{'WEBUI_STRING_NEW'};
            }
        }
        print $line;
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            print "$ref_updatefile->{'COUNTER'}{'SCHOOL'}{$school} users can change school\n";
        } else {
            print "$ref_updatefile->{'COUNTER'}{'SCHOOL'}{$school} users can be updated in $school\n";
        }
        print "\n";
    } 
    print "--> Total number of users to be updated: $ref_updatefile->{'COUNTER'}{'TOTAL'}\n\n";   
}



sub _console_print_killfile {
    my ($ref_killfile,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $count=0;
    print "\n";
    print "A total of $ref_killfile->{'COUNTER'}{'TOTAL'} users can be killed:\n";
    print "\n";
    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
    my $line= "+---------------+--------------+--------------------------------------------------------+\n";
    foreach my $school (@school_list){
        if (not defined $ref_killfile->{'COUNTER'}{'SCHOOL'}{$school} or
            $ref_killfile->{'COUNTER'}{'SCHOOL'}{$school}==0){
            print "School: $school (0 users can be killed)\n";
            print "\n";
            next;
        } else {
            #print "\n\n";
            print "School: $school ($ref_killfile->{'COUNTER'}{'SCHOOL'}{$school} users can be killed)\n";
        }
        print $line;
        printf "| %-14s| %-13s| %-55s|\n",
           "Loginname",
           "AdminClass",
           "Identifier";
        print $line;
        foreach my $sam ( @{ $ref_killfile->{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school} } ){
            $count++;
        printf "| %-14s| %-13s| %-55s|\n",
               $sam,
               $ref_killfile->{'USER'}{$sam}{'sophomorixAdminClass'},
               $ref_killfile->{'USER'}{$sam}{'IDENTIFIER'};

        }
        print $line;
        print "$ref_killfile->{'COUNTER'}{'SCHOOL'}{$school} users can be killed in $school\n";
        print "\n";
    }
    print "--> Total number of users to be killed: $ref_killfile->{'COUNTER'}{'TOTAL'}\n\n";  
}



sub _console_print_users_overview {
    my ($ref_users_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
    my $line0= "+----------------------------------------------------------------+\n";
    my $line = "+-----------+---+------+------+------+------++------+------+-----+\n";
    foreach my $school (@school_list){
        if ($ref_users_v->{'COUNTER'}{$school}{'TOTAL'}==0){
            print "\n";
            print $line0;
            printf "| %-62s |\n",
                $ref_users_v->{'COUNTER'}{$school}{'TOTAL'}." users in school ".$school.":";
                print $line0;
                next;
        } else {
            print "\n";
            print $line0;
            printf "| %-42s|| global            |\n",
                $ref_users_v->{'COUNTER'}{$school}{'TOTAL'}." users in school ".$school.":";
        }

        print "| status          stud   teach  sadm   sbin || gadm   gbin   oth |\n";
        print $line;
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "permanent | P",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'P'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'P'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schooladministrator'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schoolbinduser'},
               $ref_users_v->{'COUNTER'}{'global'}{'by_role'}{'globaladministrator'},
               $ref_users_v->{'COUNTER'}{'global'}{'by_role'}{'globalbinduser'},
               $ref_users_v->{'COUNTER'}{'OTHER'};
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "usable    | U",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'U'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'U'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "activated | A",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'A'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'A'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "enabled   | E",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'E'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'E'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "selfactiv.| S",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'S'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'S'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "tolerated | T",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'T'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'T'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "managed   | M",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'M'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'M'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "disabled  | D",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'D'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'D'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "locked    | L",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'L'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'L'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "frozen    | F",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'F'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'F'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "removable | R",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'R'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'R'},
            "","","","","";
        printf "| %-13s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
            "killable  | K",
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'student'}{'K'},
            $ref_users_v->{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'K'},
            "","","","","";
        print $line;
        printf "| %-10s|%2s |%5s |%5s |%5s |%5s ||%5s |%5s |%4s |\n",
               "sum: ".$ref_users_v->{'COUNTER'}{$school}{'TOTAL'},
               "",
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'student'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'teacher'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schooladministrator'},
               $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schoolbinduser'},
               $ref_users_v->{'COUNTER'}{'global'}{'by_role'}{'globaladministrator'},
               $ref_users_v->{'COUNTER'}{'global'}{'by_role'}{'globalbinduser'},
               $ref_users_v->{'COUNTER'}{'OTHER'};
        print $line;
        print "(stud=student,teach=teacher,sadm=schooladministrator,sbin=schoolbinduser,\n";
        print " gadm=globaladministrator,gbin=globalbinduser,oth=other)\n";
    }
    print "\nOther (oth) user objects (objectclass=user):\n";
    foreach my $user ( @{ $ref_users_v->{'LISTS'}{'USER_by_SCHOOL'}{'OTHER'}{'OTHER'} }  ){
        print "   * $user (".$ref_users_v->{'USERS'}{$user}{'DN'}.")\n";
    }
    print "\n";
}



sub _console_print_group_full {
    my ($ref_groups,$school_opt,$log_level,$ref_sophomorix_config,$type)=@_;
    my $line1="#####################################################################\n";
    my $line= "---------------------------------------------------------------------\n";
    my $line2="+---------------------------------+---------------------------------+\n"; # class
    my $line3="+----------------+----------------+---------------------+---------------------+\n"; #project
    my $group_count=0;
    if ($ref_groups->{'COUNTER'}{'TOTAL'}==0){
        print "0 groups can be displayed\n";
        return;
    }
    foreach my $group (@{ $ref_groups->{'LISTS'}{'GROUPS'} }){
	$group_count++;

        ############################################################
        # printout
        ############################################################
        # header
        print $line1;
        print $ref_groups->{'GROUPS'}{$group}{'sophomorixType'}." ".
              $group_count."/".$ref_groups->{'COUNTER'}{'TOTAL'}.": ",
              $group." in school ".$ref_groups->{'GROUPS'}{$group}{'sophomorixSchoolname'}."\n";
        print "$ref_groups->{'GROUPS'}{$group}{'dn'}\n";
        print $line1;

        # attributes
        printf "%25s: %-40s\n","cn",$ref_groups->{'GROUPS'}{$group}{'cn'};
        printf "%25s: %-40s\n","description",$ref_groups->{'GROUPS'}{$group}{'description'};
        printf "%25s: %-40s\n","sAMAccountName",$ref_groups->{'GROUPS'}{$group}{'sAMAccountName'};
        printf "%25s: %-40s\n","sAMAccountType",$ref_groups->{'GROUPS'}{$group}{'sAMAccountType'};
        printf "%25s: %-40s\n","objectSid",$ref_groups->{'GROUPS'}{$group}{'objectSid'};
        print $line;

        # sophomorix attributes
        printf "%25s: %-40s\n","sophomorixType",$ref_groups->{'GROUPS'}{$group}{'sophomorixType'};
        printf "%25s: %-40s\n","sophomorixCreationDate",$ref_groups->{'GROUPS'}{$group}{'sophomorixCreationDate'};
        if ($type eq "class"){
            printf "%25s: %-40s\n","sophomorixHidden",$ref_groups->{'GROUPS'}{$group}{'sophomorixHidden'};
            printf "%25s: %-40s\n","sophomorixJoinable",$ref_groups->{'GROUPS'}{$group}{'sophomorixJoinable'};
            printf "%25s: %-40s\n","sophomorixMaxMembers",$ref_groups->{'GROUPS'}{$group}{'sophomorixMaxMembers'};
            printf "%25s: %-40s\n","sophomorixStatus",$ref_groups->{'GROUPS'}{$group}{'sophomorixStatus'};
        } elsif ($type eq "project" or $type eq "sophomorix-group"){
            printf "%25s: %-40s\n","sophomorixHidden",$ref_groups->{'GROUPS'}{$group}{'sophomorixHidden'};
            printf "%25s: %-40s\n","sophomorixJoinable",$ref_groups->{'GROUPS'}{$group}{'sophomorixJoinable'};
            printf "%25s: %-40s\n","sophomorixMaxMembers",$ref_groups->{'GROUPS'}{$group}{'sophomorixMaxMembers'};
            printf "%25s: %-40s\n","sophomorixStatus",$ref_groups->{'GROUPS'}{$group}{'sophomorixStatus'};
        } elsif ($type eq "managementgroup"){
            # nothing to show
        } elsif ($type eq "room"){
            # nothing to show
        } else {
             print "ERROR: group type not known\n";
             exit 88;
        }
        # intrinsic
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic1'}){
            printf "%25s: %-40s\n","sophomorixIntrinsic1",$ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic1'};
        }
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic2'}){
            printf "%25s: %-40s\n","sophomorixIntrinsic2",$ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic2'};
        }
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic3'}){
            printf "%25s: %-40s\n","sophomorixIntrinsic3",$ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic3'};
        }
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic4'}){
            printf "%25s: %-40s\n","sophomorixIntrinsic4",$ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic4'};
        }
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic5'}){
            printf "%25s: %-40s\n","sophomorixIntrinsic5",$ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsic5'};
        }
         foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsicMulti1'} } ){
            printf "%25s: %-40s\n","sophomorixIntrinsicMulti1",$item;
	}
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsicMulti2'} } ){
            printf "%25s: %-40s\n","sophomorixIntrinsicMulti2",$item;
	}
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsicMulti3'} } ){
            printf "%25s: %-40s\n","sophomorixIntrinsicMulti3",$item;
	}
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsicMulti4'} } ){
            printf "%25s: %-40s\n","sophomorixIntrinsicMulti4",$item;
	}
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixIntrinsicMulti5'} } ){
            printf "%25s: %-40s\n","sophomorixIntrinsicMulti5",$item;
	}

        # custom
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixCustom1'}){
            printf "%25s: %-40s\n","sophomorixCustom1",$ref_groups->{'GROUPS'}{$group}{'sophomorixCustom1'};
        }
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixCustom2'}){
            printf "%25s: %-40s\n","sophomorixCustom2",$ref_groups->{'GROUPS'}{$group}{'sophomorixCustom2'};
        }
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixCustom3'}){
            printf "%25s: %-40s\n","sophomorixCustom3",$ref_groups->{'GROUPS'}{$group}{'sophomorixCustom3'};
        }
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixCustom4'}){
            printf "%25s: %-40s\n","sophomorixCustom4",$ref_groups->{'GROUPS'}{$group}{'sophomorixCustom4'};
        }
        if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixCustom5'}){
            printf "%25s: %-40s\n","sophomorixCustom5",$ref_groups->{'GROUPS'}{$group}{'sophomorixCustom5'};
        }
         foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixCustomMulti1'} } ){
            printf "%25s: %-40s\n","sophomorixCustomMulti1",$item;
	}
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixCustomMulti2'} } ){
            printf "%25s: %-40s\n","sophomorixCustomMulti2",$item;
	}
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixCustomMulti3'} } ){
            printf "%25s: %-40s\n","sophomorixCustomMulti3",$item;
	}
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixCustomMulti4'} } ){
            printf "%25s: %-40s\n","sophomorixCustomMulti4",$item;
	}
        foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixCustomMulti5'} } ){
            printf "%25s: %-40s\n","sophomorixCustomMulti5",$item;
	}
        print $line;

        # sophomorix mail attributes
        printf "%25s: %-40s\n","mail",$ref_groups->{'GROUPS'}{$group}{'mail'};
        if ($type eq "class"){
            printf "%25s: %-40s\n","sophomorixMailQuota",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailQuota'};
            printf "%25s: %-40s\n","sophomorixMailAlias",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailAlias'};
            printf "%25s: %-40s\n","sophomorixMailList",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailList'};
        } elsif ($type eq "project" or $type eq "sophomorix-group"){
            printf "%25s: %-40s\n","sophomorixAddMailQuota",$ref_groups->{'GROUPS'}{$group}{'sophomorixAddMailQuota'};
            printf "%25s: %-40s\n","sophomorixMailAlias",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailAlias'};
            printf "%25s: %-40s\n","sophomorixMailList",$ref_groups->{'GROUPS'}{$group}{'sophomorixMailList'};
        } elsif ($type eq "managementgroup"){
            # show nothing
        } elsif ($type eq "room"){
            # show nothing
        } else {
            print "ERROR: group type not known\n";
            exit 88;
        }

        print $line;

        # sophomorix quota attributes
        if ($type eq "class"){
             foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixQuota'} } ){
                 printf "%25s: %-40s\n","sophomorixQuota",$item;
	     }
        } elsif ($type eq "project" or $type eq "sophomorix-group"){
             foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixAddQuota'} } ){
                 printf "%25s: %-40s\n","sophomorixAddQuota",$item;
	     }
        } elsif ($type eq "managementgroup"){
             # show nothing
        } elsif ($type eq "room"){
             # show nothing
        } else {
             print "ERROR: group type not known\n";
             exit 88;
        }

        # memberships
        if ($type eq "class"){
            ##### class #####
            # calculate max entries for column height
            my $max=1; # display at least one line, even if no members are there
            if ($ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'} > $max){
	        $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'};
            }
            if ($ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'} > $max){
	        $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'};
            }
            # printout
            print $line2;
            print "| sophomorixAdmins:               | sophomorixMembers:              |\n";
            print $line2;
            for (my $i=0;$i<$max;$i++){
	        # default display values:
                my $admin="";
                my $member="";
                # modify defaults if defined:
                if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins'}[$i]){
                    $admin=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins'}[$i];
                }
                if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixMembers'}[$i]){
                    $member=$ref_groups->{'GROUPS'}{$group}{'sophomorixMembers'}[$i];
                }
                printf "|%32s |%32s |\n",$admin,$member;
	    }
            print $line2;
            # sum up
            printf "| Number of sophomorixAdmins:%4s | Number of sophomorixMembers:%3s |\n",
                $ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'},
                $ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'};
            print $line2;
        } elsif ($type eq "project" or $type eq "sophomorix-group"){
            ##### project/sophomorix-group #####
            # calculate max entries for column height
            my $max=1; # display at least one line, even if no members are there
            if ($ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'} > $max){
	        $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'};
            }
            if ($ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'} > $max){
	        $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'};
            }
            if ($ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups_count'} > $max){
	        $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups_count'};
            }
            if ($ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups_count'} > $max){
	        $max=$ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups_count'};
            }

            print $line3;
            print "| Admins:        | Members:       | AdminGroups:        | MemberGroups:       |\n";
            print $line3;
            for (my $i=0;$i<$max;$i++){
	        # default display values:
                my $admin="";
                my $member="";
                my $admingroup="";
                my $membergroup="";
                # modify defaults if defined:
                if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins'}[$i]){
                    $admin=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins'}[$i];
                }
                if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixMembers'}[$i]){
                    $member=$ref_groups->{'GROUPS'}{$group}{'sophomorixMembers'}[$i];
                }
                if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups'}[$i]){
                    $admingroup=$ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups'}[$i];
                }
                if (defined $ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups'}[$i]){
                    $membergroup=$ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups'}[$i];
                }
                printf "|%15s |%15s |%20s |%20s |\n",$admin,$member,$admingroup,$membergroup;
	    }
            print $line3;
            # sum up
            printf "| Admins: %6s | Members:%6s | AdminGroups: %6s | MemberGroups:%6s |\n",
                $ref_groups->{'GROUPS'}{$group}{'sophomorixAdmins_count'},
                $ref_groups->{'GROUPS'}{$group}{'sophomorixMembers_count'},
                $ref_groups->{'GROUPS'}{$group}{'sophomorixAdminGroups_count'},
                $ref_groups->{'GROUPS'}{$group}{'sophomorixMemberGroups_count'};
            print $line3;
        } elsif ($type eq "managementgroup"){
            ##### managementgroup ####
            # nothing to show
        } elsif ($type eq "room"){
            ##### room  ####
            print $line;
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixRoomComputers'} } ){
                printf "%25s: %-40s\n","sophomorixRoomComputers",$item;
	    }
            print $line;
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixRoomIPs'} } ){
                printf "%25s: %-40s\n","sophomorixRoomIPs",$item;
	    }
            print $line;
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'sophomorixRoomMACs'} } ){
                printf "%25s: %-40s\n","sophomorixRoomMACs",$item;
	    }
            print $line;
        } else {
             print "ERROR: group type not known\n";
             exit 88;
        }

        ############################################################
        # optional -v : show memberships
        if ($log_level>1){
            print "memberOf:\n";
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'memberOf'} } ){
                print "$item\n";
            }
            print $line;
            my $count_member=$#{ $ref_groups->{'GROUPS'}{$group}{'member'} }+1;
            print "member ($count_member):\n";
            foreach my $item ( @{ $ref_groups->{'GROUPS'}{$group}{'member'} } ){
                print "$item\n";
	    }
            if ($count_member>9){
                print "... $ref_groups->{'GROUPS'}{$group}{'cn'} has $count_member entries in multivalue attribute member\n";
            }
            print $line;
        }
	print "\n";
    }
}



sub console_print_mail_user {
    my ($arg_ref) = @_;
    my $ref_mail = $arg_ref->{ref_mail};
    my $ref_sophomorix_config = $arg_ref->{ref_sophomorix_config};
    my $user = $arg_ref->{user};
    my $log_level=$arg_ref->{log_level};
    my $line="+------------------------------------------".
              "------------------------------------+\n";
    my $role=$ref_mail->{'QUOTA'}{'USERS'}{$user}{'sophomorixRole'};
    my $school=$ref_mail->{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'};

    print $line;
    printf "| %-77s|\n", $user." in ".$school;
    print $line;
    printf "%30s: %-40s\n","Addresbook displayName",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'displayName'};
    printf "%30s: %-40s\n","mail",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'mail'};
    if ( $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIAS'} eq "TRUE" ){
        printf "%30s: %-40s\n","Calculated Alias",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIASNAME_LONG'};
    } else {
        printf "%30s: %-40s\n","Calculated Alias",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIAS'};
    }

    printf "%30s: %-40s\n","Calculated maillist membership",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLISTMEMBER'};
    if ( $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLISTMEMBER'} eq "TRUE" ){
        foreach my $list (keys %{ $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLIST_MEMBERSHIPS'} } ) {
            printf "%30s: %-40s\n","* MAILLIST",$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLIST_MEMBERSHIPS'}{$list};
        }
    }
}



sub console_print_mailquota_user {
    my ($arg_ref) = @_;
    my $ref_quota = $arg_ref->{ref_quota};
    my $ref_sophomorix_config = $arg_ref->{ref_sophomorix_config};
    my $user = $arg_ref->{user};
    my $log_level=$arg_ref->{log_level};
    my $line="+------------------------------------------".
              "------------------------------------+\n";

    # create shortcut vars
    my $role=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixRole'};

    ############################################################
    # MailQuota
    my $mailquota_school_default=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'SCHOOLDEFAULT'};
    my $mailquota_user_display;
    my $mailquota_user_comment;
    if (defined $ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'VALUE'}){
        $mailquota_user_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'VALUE'};
	$mailquota_user_comment=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'COMMENT'};
    } else {
        $mailquota_user_display="---";
        $mailquota_user_comment="---";
    }
    my $mailquota_class_display;
    my $mailquota_class_comment;
    if (defined $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'}){
        $mailquota_class_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'};
        $mailquota_class_comment=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'COMMENT'};
    } else {
        $mailquota_class_display="---";
        $mailquota_class_comment="comment";
    }

    my $mailcalc_display;
    if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'} eq "TRUE"){
        # append asterisk
        $mailcalc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'CALC'}."*";
    } else {
        # append space
        $mailcalc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'CALC'}." ";
    }

    # printout
    if($log_level>=2){
        # print extensive information
        print $line;
        printf "| %-77s|\n","MailQuota for user ".$user." in MiB (Mebibyte):";
        printf "|%10s %-67s|\n",
               $mailquota_school_default,
               " (A) default MailQuota for sophomorixRole \'".$role."\'";
        if ($mailquota_class_display ne "---"){
            printf "|%10s %-67s|\n",
                   $mailquota_class_display,
                   " (B) Quota at the users class \'".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sAMAccountName'}.
                   "\': Overrides (A)";
            printf "|%10s %-67s|\n",
                   " ",
                   " Comment: \'".
                   $mailquota_class_comment.
                   "\'";
        } else {
            printf "|%10s %-67s|\n",
                   $mailquota_class_display,
                   " (B) No Quota at the users class \'".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sAMAccountName'}.
                   "\'";
        }


        foreach my $group ( @{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }) {
            my @reason=();
            my $membership_string="";
            foreach my $reason (keys %{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'REASON'} }) {
                push @reason,$reason;
            }
            @reason = sort @reason;
            $membership_string=join(",",@reason);
	    if (exists $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'}){
		my $add=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'};
                printf "|%10s %-67s|\n",
                       "+ ".
                       $add,
                       " AddMailQuota, member in ".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixType'}.
                       " \'".
                       $group.
                       "\' (".
                       $membership_string.
                       ")";
                printf "|%10s %-67s|\n",
                       "",
                       " Comment: \'".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'COMMENT'}.
                       "\'";
	    } else {
                printf "|%10s %-67s|\n",
                       "0",
                       " No AddMailQuota, member in ".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixType'}.
                       " \'".
                       $group.
                       "\' (".
                       $membership_string.
                       ")";
	    }
        }


        if ($mailquota_user_display eq "---"){
            printf "|%10s %-67s|\n",
                   $mailquota_user_display,
                   " (C) No MailQuota at the user Object \'".
                   $user.
                   "\'";
        } else {
            printf "|%10s %-67s|\n",
                   $mailquota_user_display,
                   " (C) MailQuota at the user will override all above settings";
            printf "|%10s %-67s|\n",
                   " ",
                   " Comment: \'".
                   $mailquota_user_comment.
                   "\'";
        }

        # show calc 
        if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'} eq "TRUE"){
            printf "|%11s%-67s|\n",
                   $mailcalc_display,
                   " sophomorixMailQuotaCalculated must be set (current: ".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'OLDCALC'}.
                   " MiB)";
        } else {
            printf "|%11s%-67s|\n",
                   $mailcalc_display,
                   " sophomorixMailQuotaCalculated is ".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'OLDCALC'}.
                   " MiB";
        }
        print $line;
    } else {
        # print single line
	printf "| %-25s| %-7s|%6s|%5s |%5s | %-18s|\n",
               "$user($role:$mailquota_school_default)",
               "**MQ**",
               $mailcalc_display,
               $mailquota_user_display,
               $mailquota_class_display,
               $ref_quota->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'GROUPSTRING'};
    }
}



sub console_print_quota_user {
    my ($arg_ref) = @_;
    my $ref_quota = $arg_ref->{ref_quota};
    my $ref_sophomorix_config = $arg_ref->{ref_sophomorix_config};
    my $user = $arg_ref->{user};
    my $log_level = $arg_ref->{log_level};
    my $line="+------------------------------------------".
              "------------------------------------+\n";
    if (not exists $ref_quota->{'QUOTA'}{'USERS'}{$user}){
        print "  WARNING: User $user not found!\n";
        next;
    } 
    # create shortcut vars
    my $role=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixRole'};
    my $school=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'};

    # print user end/share begin line
    if($log_level==1){
        #print $line;
    } else {
        print $line;
        printf "| %-77s|\n", $user." in ".$school;
    }

    ############################################################
    # Walk through all shares
    foreach my $share ( @{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }){
        # get values for display
        my $school_default;
        my $share_display;
	if ($share eq $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}){
            $school_default=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'QUOTA_DEFAULT_GLOBAL'};
	    $share_display="GLOBAL";
	} elsif ($share eq $school){
            $school_default=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'QUOTA_DEFAULT_SCHOOL'};
	    $share_display=$share;
        } else {
            $school_default="---";                    
	    $share_display=$share;
        }
  	if ($share eq $DevelConf::name_default_school){
            $share_display="DEFLT";
	}

        # get the users quota or --- for display
        my $quota_user_display;
        my $quota_user_comment;
        if (defined $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}
                                {$share}{'sophomorixQuota'}){
	    $quota_user_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}
                                            {$share}{'sophomorixQuota'};
	    $quota_user_comment=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}
	                                    {$share}{'COMMENT'};
	} else {
            $quota_user_display="---";
            $quota_user_comment="---";
        }
        my $quota_class_display;
        my $quota_class_comment;
        if (defined $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}
                                {'sophomorixQuota'}{$share}{'VALUE'}){
	    $quota_class_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}
	                                     {'sophomorixQuota'}{$share}{'VALUE'};
	    $quota_class_comment=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}
	                                     {'sophomorixQuota'}{$share}{'COMMENT'};

        } else {
            $quota_class_display="---";
            $quota_class_comment="---";
        }

        my $calc_display;
        if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'} eq "TRUE"){
            # append asterisk
            $calc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'CALC'}."*";
        } else {
                # append space
                $calc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'CALC'}." ";
        }

        # printout
        if($log_level>=2){
            # print extensive information
            print $line;
            printf "| %-77s|\n",$share." share for user ".$user." in MiB (Mebibyte):";
            printf "|%10s %-67s|\n",
                $school_default,
                " (A) default Quota for sophomorixRole \'".$role."\'";
            if ($quota_class_display ne "---"){
                printf "|%10s %-67s|\n",
                       "",
                       " (B) Quota at the users class \'".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sAMAccountName'}.
                       "\': Overrides (A)";
                printf "|%10s %-67s|\n",
                       $quota_class_display,
                       " Comment: \'".
                       $quota_class_comment.
                       "\'";
    	    } else {
                printf "|%10s %-67s|\n",
                       $quota_class_display,
                       " (B) No Quota at the users class \'".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sAMAccountName'}.
                       "\'";
            }
            foreach my $group ( @{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }) {
                my @reason=();
                my $membership_string="";
                foreach my $reason (keys %{ $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'REASON'} }) {
                    push @reason,$reason;
                }
                @reason = sort @reason;
                $membership_string=join(",",@reason);
		if (exists $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'}){
		    my $add=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'};
                    printf "|%10s %-67s|\n","+ ".$add,
                           " AddQuota, member in ".
                           $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixType'}.
                           " \'".
                           $group.
                           "\' (".
                           $membership_string.")";
                    printf "|%10s %-67s|\n","",
                           " Comment: \'".
                           $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'COMMENT'}.
                           "\'";
		} else {
                    printf "|%10s %-67s|\n","0",
                           " No AddQuota, member in ".
                           $ref_quota->{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixType'}.
                           " \'".
                           $group.
                           "\' (".
                           $membership_string.")";
		}
            }
            if ($quota_user_display eq "---"){
                printf "|%10s %-67s|\n",$quota_user_display," (C) No Quota at the user Object \'".$user."\'";
            } else {
                printf "|%10s %-67s|\n",$quota_user_display," (C) Quota at the user will override all above settings";
                printf "|%10s %-67s|\n"," "," Comment: \'".$quota_user_comment."\'";
            }

            # show calc 
            if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'} eq "TRUE"){
                printf "|%11s%-67s|\n",
                       $calc_display,
                       " CALC must be set for ".$user." on ".$share;
            } else {
                printf "|%11s%-67s|\n",
                       $calc_display,
                       " CALC was already set for ".$user." on ".$share;
                my $mib=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'}/1024/1024;
                printf "|%11s%-67s|\n",
                       "",
                       " SMB share quota was set to ".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'}." Bytes (".
                       $mib.
                       " MiB)";
            }
            if (exists $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}){
	        printf "| %-77s|\n",
                       "smbcquota  USED=".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'USED_MiB'}.
                       "  SOFT=".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SOFTLIMIT_MiB'}.
                       "  HARD=".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'HARDLIMIT_MiB'}.
                       " (in MiB)";
            }
	} else {
            # print single line
	    printf "| %-25s| %-7s|%6s|%5s |%5s | %-18s|\n",
                   "$user($role:$school_default)",
                   $share_display,
                   $calc_display,
                   $quota_user_display,
                   $quota_class_display,
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'GROUPSTRING'};
            if (exists $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}){
	        printf "| %-75s|\n",
                       " smbcquotas in MiB: USED=".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'USED_MiB'}.
                       "  SOFT=".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SOFTLIMIT_MiB'}.
                       "  HARD=".
                       $ref_quota->{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'HARDLIMIT_MiB'}.
                       "";
                print "+   -     -     -     -    +  -  -  +   -  +   -  +   -  +    -    -    -    +\n";
            }
        }
    } # end of share walk
    ############################################################
    # CLOUDQUOTA
    my $cloudcalc_display;
    my $cloudquota_percentage=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'PERCENTAGE'};
    if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'ACTION'}{'UPDATE'} eq "TRUE"){
        # append asterisk
        $cloudcalc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC_MB'}."*";
    } else {
        # append space
        $cloudcalc_display=$ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC_MB'}." ";
    }

    if($log_level>=2){
        # print extensive information
	print $line;
        printf "| %-77s|\n","CloudQuota for user ".$user." ($cloudquota_percentage% of $school share):";
        if ($ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'ACTION'}{'UPDATE'} eq "TRUE"){
            printf "|%11s%-67s|\n",
                   $cloudcalc_display,
                   " sophomorixCloudQuotaCalculated must be set to ".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC'};
        } else {
            printf "|%11s%-67s|\n",
                   $cloudcalc_display,
                   " sophomorixCloudQuotaCalculated was set to ".
                   $ref_quota->{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC'};
        }
    } else {
        # print single line
	printf "| %-25s| %-7s|%6s|%32s |\n",
               "$user($role:$cloudquota_percentage%)",
               "**CQ**",
               $cloudcalc_display,
               "($school)";
    }
}



sub _console_print_user_full {
    my ($ref_users,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="################################################################################\n";
    my $line= "--------------------------------------------------------------------------------\n";

    # UNKNOWN_USERS
    foreach my $user (@{ $ref_users->{'LISTS'}{'UNKNOWN_USERS'} }){
        print "\n";
        print $line1;
        print "Nothing known about user: $user\n";
        print $line1;
    }

    # DELETED_USERS
    my $user_count_deleted=0;
    my $user_count_deleted_max=$#{ $ref_users->{'LISTS'}{'DELETED_USERS'} }+1;
    foreach my $user (@{ $ref_users->{'LISTS'}{'DELETED_USERS'} }){
        $user_count_deleted++;
        print "\n";
        print $line1;
        print "Deleted user $user_count_deleted/$user_count_deleted_max: $user\n";
        print $line1;
        print "LOGFILES ($ref_users->{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'} Entries):\n";
        foreach my $epoch (@{ $ref_users->{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }){
            print "  ".$ref_users->{'USERS'}{$user}{'HISTORY'}{'EPOCH'}{$epoch}."\n";
        }
    }

    # USERS in AD
    my $user_count=0;
    foreach my $user (@{ $ref_users->{'LISTS'}{'USERS'} }){
        $user_count++;
        print "\n";
        print $line1;
        print "User $user_count/$ref_users->{'COUNTER'}{'TOTAL'} in AD: ",
              "$user in school $ref_users->{'USERS'}{$user}{'sophomorixSchoolname'}\n";
        print "$ref_users->{'USERS'}{$user}{'dn'}\n";
        print $line1;
        if (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_BINDUSERS'}{$ref_users->{'USERS'}{$user}{'sophomorixRole'}}){
            # its a bind user
            print "Bind DN for $user:\n",
                  "  $ref_users->{'USERS'}{$user}{'dn'}\n";
            print "PASSWORD for $user (PWDFileExists: $ref_users->{'USERS'}{$user}{'PWDFileExists'}):\n",
                  "  $ref_users->{'USERS'}{$user}{'PASSWORD'}\n";
            print $line;
        } elsif (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_ADMINISTRATORS'}{$ref_users->{'USERS'}{$user}{'sophomorixRole'}}){
            # its an adminisrator
            printf "%30s: %-40s\n","PWDFileExists",$ref_users->{'USERS'}{$user}{'PWDFileExists'};
            printf "%30s: %-40s\n","PASSWORD",$ref_users->{'USERS'}{$user}{'PASSWORD'};
            if ($ref_users->{'USERS'}{$user}{'PWDFileExists'} eq "TRUE"){
                printf "%30s: %-40s\n","PWDFile",$ref_users->{'USERS'}{$user}{'PWDFile'};
            }
            print $line;
        }
        printf "%30s: %-40s\n","displayName",$ref_users->{'USERS'}{$user}{'displayName'};
        printf "%30s: %-40s\n","sn",$ref_users->{'USERS'}{$user}{'sn'};
        printf "%30s: %-40s\n","givenName",$ref_users->{'USERS'}{$user}{'givenName'};
        printf "%30s: %-40s\n","sophomorixFirstnameASCII",$ref_users->{'USERS'}{$user}{'sophomorixFirstnameASCII'};
        printf "%30s: %-40s\n","sophomorixSurnameASCII",$ref_users->{'USERS'}{$user}{'sophomorixSurnameASCII'};

        printf "%30s: %-40s\n","sophomorixFirstnameInitial",$ref_users->{'USERS'}{$user}{'sophomorixFirstnameInitial'};
        printf "%30s: %-40s\n","sophomorixSurnameInitial",$ref_users->{'USERS'}{$user}{'sophomorixSurnameInitial'};

        printf "%30s: %-40s\n","sophomorixUserToken",$ref_users->{'USERS'}{$user}{'sophomorixUserToken'};

        printf "%30s: %-40s\n","sophomorixBirthdate",$ref_users->{'USERS'}{$user}{'sophomorixBirthdate'};
        printf "%30s: %-40s\n","sophomorixUnid",$ref_users->{'USERS'}{$user}{'sophomorixUnid'};
        printf "%30s: %-40s\n","sophomorixAdminClass",$ref_users->{'USERS'}{$user}{'sophomorixAdminClass'};
        printf "%30s: %-40s\n","sophomorixExitAdminClass",$ref_users->{'USERS'}{$user}{'sophomorixExitAdminClass'};
        printf "%30s: %-40s\n","sophomorixSchoolname",$ref_users->{'USERS'}{$user}{'sophomorixSchoolname'};
        printf "%30s: %-40s\n","sophomorixAdminFile",$ref_users->{'USERS'}{$user}{'sophomorixAdminFile'};
        printf "%30s: %-40s\n","sophomorixComment",$ref_users->{'USERS'}{$user}{'sophomorixComment'};
        printf "%30s: %-40s\n","sophomorixFirstPassword",$ref_users->{'USERS'}{$user}{'sophomorixFirstPassword'};
        printf "%30s: %-40s\n","sophomorixExamMode",$ref_users->{'USERS'}{$user}{'sophomorixExamMode'};
        print $line;
        printf "%30s: %-40s\n","sophomorixRole",$ref_users->{'USERS'}{$user}{'sophomorixRole'};
        printf "%30s: %-40s\n","sophomorixStatus",$ref_users->{'USERS'}{$user}{'sophomorixStatus'};
        printf "%30s: %-40s\n","sophomorixCreationDate",$ref_users->{'USERS'}{$user}{'sophomorixCreationDate'};
        printf "%30s: %-40s\n","sophomorixTolerationDate",$ref_users->{'USERS'}{$user}{'sophomorixTolerationDate'};
        printf "%30s: %-40s\n","sophomorixDeactivationDate",$ref_users->{'USERS'}{$user}{'sophomorixDeactivationDate'};
        printf "%30s: %-40s\n","userAccountControl",$ref_users->{'USERS'}{$user}{'userAccountControl'};
        print $line;
        printf "%30s: %-40s\n","mail",$ref_users->{'USERS'}{$user}{'mail'};

        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'proxyAddresses'} } ){
            printf "%30s: %-40s\n","proxyAddresses",$item;
	}


	
        printf "%30s: %-40s\n","sophomorixMailQuota",$ref_users->{'USERS'}{$user}{'sophomorixMailQuota'};
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixMailQuotaCalculated'}){
            printf "%30s: %-40s\n","sophomorixMailQuotaCalculated",
                $ref_users->{'USERS'}{$user}{'sophomorixMailQuotaCalculated'};
        } else {
            printf "%30s: %-40s\n","sophomorixMailQuotaCalculated","(undef)";
        }

        print $line;
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixQuota'} } ){
            printf "%30s: %-40s\n","sophomorixQuota",$item;
	}
        printf "%30s: %-40s\n","sophomorixCloudQuotaCalculated",$ref_users->{'USERS'}{$user}{'sophomorixCloudQuotaCalculated'};

        print $line;
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixWebuiPermissions'} } ){
            printf "%30s: %-40s\n","sophomorixWebuiPermissions",$item;
	}
        print "sophomorixWebuiPermissionsCalculated:\n";
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixWebuiPermissionsCalculated'} } ){
            print "   $item\n";
	}

        # custom
        print "------------- sophomorixCustom: ------------------------------------------------\n";
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixCustom1'}){
            printf "%30s: %-40s\n","sophomorixCustom1",$ref_users->{'USERS'}{$user}{'sophomorixCustom1'};
        }
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixCustom2'}){
            printf "%30s: %-40s\n","sophomorixCustom2",$ref_users->{'USERS'}{$user}{'sophomorixCustom2'};
        }
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixCustom3'}){
            printf "%30s: %-40s\n","sophomorixCustom3",$ref_users->{'USERS'}{$user}{'sophomorixCustom3'};
        }
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixCustom4'}){
            printf "%30s: %-40s\n","sophomorixCustom4",$ref_users->{'USERS'}{$user}{'sophomorixCustom4'};
        }
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixCustom5'}){
            printf "%30s: %-40s\n","sophomorixCustom5",$ref_users->{'USERS'}{$user}{'sophomorixCustom5'};
        }
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixCustomMulti1'} } ){
            printf "%30s: %-40s\n","sophomorixCustomMulti1",$item;
	}
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixCustomMulti2'} } ){
            printf "%30s: %-40s\n","sophomorixCustomMulti2",$item;
	}
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixCustomMulti3'} } ){
            printf "%30s: %-40s\n","sophomorixCustomMulti3",$item;
	}
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixCustomMulti4'} } ){
            printf "%30s: %-40s\n","sophomorixCustomMulti4",$item;
	}
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixCustomMulti5'} } ){
            printf "%30s: %-40s\n","sophomorixCustomMulti5",$item;
	}


        # intrinsic
        print "---------- sophomorixIntrinsic: ------------------------------------------------\n";
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixIntrinsic1'}){
            printf "%30s: %-40s\n","sophomorixIntrinsic1",$ref_users->{'USERS'}{$user}{'sophomorixIntrinsic1'};
        }
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixIntrinsic2'}){
            printf "%30s: %-40s\n","sophomorixIntrinsic2",$ref_users->{'USERS'}{$user}{'sophomorixIntrinsic2'};
        }
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixIntrinsic3'}){
            printf "%30s: %-40s\n","sophomorixIntrinsic3",$ref_users->{'USERS'}{$user}{'sophomorixIntrinsic3'};
        }
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixIntrinsic4'}){
            printf "%30s: %-40s\n","sophomorixIntrinsic4",$ref_users->{'USERS'}{$user}{'sophomorixIntrinsic4'};
        }
        if (defined $ref_users->{'USERS'}{$user}{'sophomorixIntrinsic5'}){
            printf "%30s: %-40s\n","sophomorixIntrinsic5",$ref_users->{'USERS'}{$user}{'sophomorixIntrinsic5'};
        }
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixIntrinsicMulti1'} } ){
            printf "%30s: %-40s\n","sophomorixIntrinsicMulti1",$item;
	}
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixIntrinsicMulti2'} } ){
            printf "%30s: %-40s\n","sophomorixIntrinsicMulti2",$item;
	}
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixIntrinsicMulti3'} } ){
            printf "%30s: %-40s\n","sophomorixIntrinsicMulti3",$item;
	}
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixIntrinsicMulti4'} } ){
            printf "%30s: %-40s\n","sophomorixIntrinsicMulti4",$item;
	}
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'sophomorixIntrinsicMulti5'} } ){
            printf "%30s: %-40s\n","sophomorixIntrinsicMulti5",$item;
	}

        print $line;
        foreach my $item ( @{ $ref_users->{'USERS'}{$user}{'memberOf'} } ){
            print "memberOf: $item\n";
	}

        # samba stuff:
        print $line;
        if ($log_level>=2){
            printf "%19s: %-50s\n","objectSid",$ref_users->{'USERS'}{$user}{'objectSid'};
            #printf "%19s: %-50s\n","objectGUID","(binary)";
            #printf "%19s: %-50s\n","objectGUID",$ref_users->{'USERS'}{$user}{'objectGUID_BINARY'};
            printf "%19s: %-50s\n","homeDirectory",$ref_users->{'USERS'}{$user}{'homeDirectory'};
            printf "%19s: %-50s\n","homeDrive",$ref_users->{'USERS'}{$user}{'homeDrive'};

            printf "%19s: %-50s\n","accountExpires",$ref_users->{'USERS'}{$user}{'accountExpires'};
            printf "%19s: %-50s\n","badPasswordTime",$ref_users->{'USERS'}{$user}{'badPasswordTime'};
            printf "%19s: %-50s\n","badPwdCount",$ref_users->{'USERS'}{$user}{'badPwdCount'};
            printf "%19s: %-50s\n","pwdLastSet",$ref_users->{'USERS'}{$user}{'pwdLastSet'};

            printf "%19s: %-50s\n","lastLogoff",$ref_users->{'USERS'}{$user}{'lastLogoff'};
            printf "%19s: %-50s\n","lastLogon",$ref_users->{'USERS'}{$user}{'lastLogon'};
            printf "%19s: %-50s\n","logonCount",$ref_users->{'USERS'}{$user}{'logonCount'};
            printf "%19s: %-50s\n","sAMAccountType",$ref_users->{'USERS'}{$user}{'sAMAccountType'};
            printf "%19s: %-50s\n","userPrincipalName",$ref_users->{'USERS'}{$user}{'userPrincipalName'};

            printf "%19s: %-50s\n","uSNChanged",$ref_users->{'USERS'}{$user}{'uSNChanged'};
            printf "%19s: %-50s\n","uSNCreated",$ref_users->{'USERS'}{$user}{'uSNCreated'};

            printf "%19s: %-50s\n","codePage",$ref_users->{'USERS'}{$user}{'codePage'};
            printf "%19s: %-50s\n","countryCode",$ref_users->{'USERS'}{$user}{'countryCode'};
	}

        # unix stuff:
        if ($log_level>=2){
            printf "%19s: %-50s\n","unixHomeDirectory",$ref_users->{'USERS'}{$user}{'unixHomeDirectory'};
            printf "%19s: %-50s\n","primaryGroupID",$ref_users->{'USERS'}{$user}{'primaryGroupID'};
            print $line;
	}
        if ($log_level>=2 and $ref_users->{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'}>0){
            print "LOGFILES ($ref_users->{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'} Entries):\n";
            foreach my $epoch (@{ $ref_users->{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }){
                print "  ".$ref_users->{'USERS'}{$user}{'HISTORY'}{'EPOCH'}{$epoch}."\n";
            }
        } else {
            print "LOGFILES: $ref_users->{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'} Entries\n";
        }
    }
}




sub _console_print_device_full {
    my ($ref_devices,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="################################################################################\n";
    my $line= "--------------------------------------------------------------------------------\n";

    # DEVICES in AD
    my $device_count=0;
    foreach my $device (@{ $ref_devices->{'LISTS'}{'dnsNode'} }){
        $device_count++;
        # computer
        if (exists $ref_devices->{'DEVICES'}{$device}{'computer'}){
            print "\n";
            print $line1;
            print "Device $device_count/$ref_devices->{'COUNTER'}{'dnsNode'}{'TOTAL'} in AD: ",
                  "$device in school $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixSchoolname'}\n";
            print "$ref_devices->{'DEVICES'}{$device}{'computer'}{'dn'}\n";
            print $line1;
            printf "%29s: %-40s\n","sAMAccountName",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sAMAccountName'};
            printf "%29s: %-40s\n","cn",$ref_devices->{'DEVICES'}{$device}{'computer'}{'cn'};
            printf "%29s: %-40s\n","name",$ref_devices->{'DEVICES'}{$device}{'computer'}{'name'};
            printf "%29s: %-40s\n","sophomorixDnsNodename",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixDnsNodename'};
            printf "%29s: %-40s\n","displayName",$ref_devices->{'DEVICES'}{$device}{'computer'}{'displayName'};
            printf "%29s: %-40s\n","sophomorixAdminClass",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixAdminClass'};
            printf "%29s: %-40s\n","sophomorixSchoolname",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixSchoolname'};
            printf "%29s: %-40s\n","sophomorixAdminFile",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixAdminFile'};
            printf "%29s: %-40s\n","sophomorixComment",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixComment'};
            printf "%29s: %-40s\n","dNSHostName",$ref_devices->{'DEVICES'}{$device}{'computer'}{'dNSHostName'};
            print $line;
            printf "%29s: %-40s\n","sophomorixRole",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixRole'};
            printf "%29s: %-40s\n","sophomorixStatus",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixStatus'};
            printf "%29s: %-40s\n","sophomorixCreationDate",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCreationDate'};
            printf "%29s: %-40s\n","userAccountControl",$ref_devices->{'DEVICES'}{$device}{'computer'}{'userAccountControl'};
            #print $line;
            #printf "%29s: %-40s\n","mail",$ref_devices->{'DEVICES'}{$device}{'computer'}{'mail'};
    
            print $line;
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'servicePrincipalName'} } ){
                printf "%29s: %-40s\n","servicePrincipalName",$item;
        	}

            # custom
	    print "------------- sophomorixCustom: ------------------------------------------------\n";

            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom1'}){
                printf "%30s: %-40s\n","sophomorixCustom1",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom1'};
            }
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom2'}){
                printf "%30s: %-40s\n","sophomorixCustom2",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom2'};
            }
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom3'}){
                printf "%30s: %-40s\n","sophomorixCustom3",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom3'};
            }
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom4'}){
                printf "%30s: %-40s\n","sophomorixCustom4",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom4'};
            }
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom5'}){
                printf "%30s: %-40s\n","sophomorixCustom5",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustom5'};
            }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti1'} } ){
                printf "%30s: %-40s\n","sophomorixCustomMulti1",$item;
	    }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti2'} } ){
                printf "%30s: %-40s\n","sophomorixCustomMulti2",$item;
	    }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti3'} } ){
                printf "%30s: %-40s\n","sophomorixCustomMulti3",$item;
	    }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti4'} } ){
                printf "%30s: %-40s\n","sophomorixCustomMulti4",$item;
	    }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti5'} } ){
                printf "%30s: %-40s\n","sophomorixCustomMulti5",$item;
	    }

            # intrinsic
            print "---------- sophomorixIntrinsic: ------------------------------------------------\n";
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic1'}){
                printf "%30s: %-40s\n","sophomorixIntrinsic1",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic1'};
            }
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic2'}){
                printf "%30s: %-40s\n","sophomorixIntrinsic2",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic2'};
            }
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic3'}){
                printf "%30s: %-40s\n","sophomorixIntrinsic3",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic3'};
            }
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic4'}){
                printf "%30s: %-40s\n","sophomorixIntrinsic4",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic4'};
            }
            if (defined $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic5'}){
                printf "%30s: %-40s\n","sophomorixIntrinsic5",$ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic5'};
            }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti1'} } ){
                printf "%30s: %-40s\n","sophomorixIntrinsicMulti1",$item;
 	    }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti2'} } ){
                printf "%30s: %-40s\n","sophomorixIntrinsicMulti2",$item;
	    }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti3'} } ){
                printf "%30s: %-40s\n","sophomorixIntrinsicMulti3",$item;
	    }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti4'} } ){
                printf "%30s: %-40s\n","sophomorixIntrinsicMulti4",$item;
	    }
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti5'} } ){
                printf "%30s: %-40s\n","sophomorixIntrinsicMulti5",$item;
	    }

            print $line;
            foreach my $item ( @{ $ref_devices->{'DEVICES'}{$device}{'computer'}{'memberOf'} } ){
                print "memberOf: $item\n";
        	}

            # samba stuff:
            if ($log_level>=2){
                #printf "%19s: %-50s\n","homeDirectory",$ref_devices->{'DEVICES'}{$device}{'computer'}{'homeDirectory'};
                #printf "%19s: %-50s\n","homeDrive",$ref_devices->{'DEVICES'}{$device}{'computer'}{'homeDrive'};

                printf "%19s: %-50s\n","accountExpires",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'accountExpires'};
                printf "%19s: %-50s\n","badPasswordTime",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'badPasswordTime'};
                printf "%19s: %-50s\n","badPwdCount",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'badPwdCount'};
                printf "%19s: %-50s\n","pwdLastSet",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'pwdLastSet'};
                printf "%19s: %-50s\n","lastLogoff",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'lastLogoff'};
                printf "%19s: %-50s\n","lastLogon",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'lastLogon'};
                printf "%19s: %-50s\n","logonCount",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'logonCount'};

                if ($ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_RELEASE'} eq "17.10"){
                    #my $sid = Net::LDAP::SID->new($ref_devices->{'DEVICES'}{$device}{'objectSid'});

                    printf "%19s: %-50s\n","objectSid",
                        $ref_devices->{'DEVICES'}{$device}{'computer'}{'objectSid'};
                    printf "%19s: %-50s\n","objectGUID","(binary)";
                } else {
                    printf "%19s: %-50s\n","objectSid","(binary)";
                    printf "%19s: %-50s\n","objectGUID","(binary)";
                }

                printf "%19s: %-50s\n","sAMAccountType",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'sAMAccountType'};
                #printf "%19s: %-50s\n","userPrincipalName",
                #    $ref_devices->{'DEVICES'}{$device}{'computer'}{'userPrincipalName'};
                printf "%19s: %-50s\n","uSNChanged",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'uSNChanged'};
                printf "%19s: %-50s\n","uSNCreated",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'uSNCreated'};
                printf "%19s: %-50s\n","codePage",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'codePage'};
                printf "%19s: %-50s\n","countryCode",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'countryCode'};
        	}

            # unix stuff:
            if ($log_level>=2){
                #printf "%19s: %-50s\n","unixHomeDirectory",
                #    $ref_devices->{'DEVICES'}{$device}{'computer'}{'unixHomeDirectory'};
                printf "%19s: %-50s\n","primaryGroupID",
                    $ref_devices->{'DEVICES'}{$device}{'computer'}{'primaryGroupID'};
            }
        }

        ############################################################
        # dnsNode
        ##### LOOKUP
        print $line1;
        print "dnsNode (IP LOOKUP) for $device_count/$ref_devices->{'COUNTER'}{'dnsNode'}{'TOTAL'} in AD: ",
              "$device in school $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'sophomorixSchoolname'}\n";
        print "$ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dn'}\n";
        print $line;
        printf "%29s: %-40s\n","cn",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'cn'};
        printf "%29s: %-40s\n","name",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'name'};
        printf "%29s: %-40s\n","sophomorixDnsNodename",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'sophomorixDnsNodename'};
        printf "%29s: %-40s\n","sophomorixDnsNodetype",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'sophomorixDnsNodetype'};
        printf "%29s: %-40s\n","sophomorixRole",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'sophomorixRole'};
        printf "%29s: %-40s\n","sophomorixAdminFile",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'sophomorixAdminFile'};
        printf "%29s: %-40s\n","sophomorixSchoolname",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'sophomorixSchoolname'};
        printf "%29s: %-40s\n","sophomorixComputerIP",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'sophomorixComputerIP'};
        printf "%29s: %-40s\n","sophomorixComment",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'sophomorixComment'};

        # dnsRecord:
        printf "%29s: %-40s\n","dnsRecord","(binary, data follows, completely unchecked)";
        printf "%29s: %-40s\n","dnsRecord_DataLength",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_DataLength'};
        printf "%29s: %-40s\n","dnsRecord_Type",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_Type'};
        printf "%29s: %-40s\n","dnsRecord_Version",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_Version'};
        printf "%29s: %-40s\n","dnsRecord_Rank",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_Rank'};
        printf "%29s: %-40s\n","dnsRecord_Flags",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_Flags'};
        printf "%29s: %-40s\n","dnsRecord_Serial",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_Serial'};
        printf "%29s: %-40s\n","dnsRecord_TtlSeconds",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_TtlSeconds'};
        printf "%29s: %-40s\n","dnsRecord_Reserved",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_Reserved'};
        printf "%29s: %-40s\n","dnsRecord_TimeStamp",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_TimeStamp'};
        #printf "%29s: %-40s\n","dnsRecord_Data",
        #    $ref_devices->{'DEVICES'}{$device}{'dnsNode'}{$device}{'dnsRecord_Data'};
        printf "%29s: %-40s\n","dnsRecord_Data","todo ???";

        
        ##### REVERSE LOOKUP
        print $line1;
        print "dnsNode (REVERSE LOOKUP) for $device_count/$ref_devices->{'COUNTER'}{'dnsNode_REVERSE'}{'TOTAL'} in AD: ",
              "$device in school $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'sophomorixSchoolname'}\n";
        print "$ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dn'}\n";
        print $line;
        printf "%29s: %-40s\n","cn",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'cn'};
        printf "%29s: %-40s\n","name",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'name'};
        printf "%29s: %-40s\n","sophomorixDnsNodename",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'sophomorixDnsNodename'};
        printf "%29s: %-40s\n","sophomorixDnsNodetype",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'sophomorixDnsNodetype'};
        printf "%29s: %-40s\n","sophomorixRole",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'sophomorixRole'};
        printf "%29s: %-40s\n","sophomorixAdminFile",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'sophomorixAdminFile'};
        printf "%29s: %-40s\n","sophomorixSchoolname",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'sophomorixSchoolname'};
        printf "%29s: %-40s\n","sophomorixComputerIP",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'sophomorixComputerIP'};
        printf "%29s: %-40s\n","sophomorixComment",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'sophomorixComment'};

        # dnsRecord:
        printf "%29s: %-40s\n","dnsRecord","(binary, data follows, completely unchecked)";
        printf "%29s: %-40s\n","dnsRecord_DataLength",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_DataLength'};
        printf "%29s: %-40s\n","dnsRecord_Type",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_Type'};
        printf "%29s: %-40s\n","dnsRecord_Version",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_Version'};
        printf "%29s: %-40s\n","dnsRecord_Rank",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_Rank'};
        printf "%29s: %-40s\n","dnsRecord_Flags",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_Flags'};
        printf "%29s: %-40s\n","dnsRecord_Serial",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_Serial'};
        printf "%29s: %-40s\n","dnsRecord_TtlSeconds",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_TtlSeconds'};
        printf "%29s: %-40s\n","dnsRecord_Reserved",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_Reserved'};
        printf "%29s: %-40s\n","dnsRecord_TimeStamp",
            $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_TimeStamp'};
        #printf "%29s: %-40s\n","dnsRecord_Data",
        #    $ref_devices->{'DEVICES'}{$device}{'dnsNode_REVERSE'}{$device}{'dnsRecord_Data'};
        printf "%29s: %-40s\n","dnsRecord_Data","todo ???";
    }
}



sub _console_print_examusers {
    my ($ref_examusers,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    # one user per line

    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    my @rolelist=("teacher","student");
    my $line= "+-----------------+---------------+----------------------------------------------+\n";
    my $line2="+================================================================================+\n";

    foreach my $school (@school_list){
        &print_title(" $ref_examusers->{'COUNTER'}{$school} examuser(s) in school $school:");
        print $line;
        printf "| %-16s| %-14s| %-45s|\n","participant","supervisor", "participants displayName";
        print $line;
	foreach my $examuser ( @{ $ref_examusers->{'LISTS'}{'EXAMUSER_by_sophomorixSchoolname'}{$school}{'examuser'} } ){
	    printf "| %-16s| %-14s| %-38s\n",
                   $examuser,
                   $ref_examusers->{'EXAMUSERS'}{$examuser}{'sophomorixExamMode'},
	           $ref_examusers->{'EXAMUSERS'}{$examuser}{'displayName'};
	}
        print $line;
        print "$ref_examusers->{'COUNTER'}{$school} examuser(s) in school $school","\n";
	print "\n";
    } # school end
    print "Total number of examusers on this server: $ref_examusers->{'COUNTER'}{'TOTAL'}\n";
}



sub _console_print_users_v {
    my ($ref_users_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    # one user per line

    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }

    my @rolelist=("teacher","student");
    my $line= "+---------------+---+----------------+----------+--------------------------+\n";
    my $line2="+===========================================================================+\n";

    foreach my $school (@school_list){
        $count_string=$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'teacher'}+
	              $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'student'}.
                      " users (".$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'teacher'}.
                      " Teachers + ".
                      $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'student'}.
                      " Students)";
        &print_title("$count_string in school $school:");
        if ($ref_users_v->{'COUNTER'}{$school}{'TOTAL'}==0){
            next;
        }

        foreach my $role (@rolelist){
            print $line;
            my $role_display;
            if ($role eq "student"){
                $role_display="Students";
            } elsif ($role eq "teacher"){
                $role_display="Teachers";
            } else {
                $role_display=$role;
            }
	    printf "|%5s %-9s| S | AdminClass     | Role     | displayName              |\n",
                $ref_users_v->{'COUNTER'}{$school}{'by_role'}{$role},$role_display;
            if ($#{ $ref_users_v->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } >-1){
                print $line;
                foreach my $user ( @{ $ref_users_v->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } ){
                    #my $gcs  = Unicode::GCString->new($ref_users_v->{'USERS'}{$user}{'displayName'});
                    if ($role eq "schooladministrator"){
                        $role="sadmin";
                    }
                    if ($role eq "schoolbinduser"){
                        $role="sbind";
                    }
	  	    printf "| %-14s| %-2s| %-15s| %-9s| %-23s\n",
                        $user,
                        $ref_users_v->{'USERS'}{$user}{'sophomorixStatus'},
                        $ref_users_v->{'USERS'}{$user}{'sophomorixAdminClass'},
                        $role,
		        $ref_users_v->{'USERS'}{$user}{'displayName'};
                }
            }
            print $line;
        }
        print "$ref_users_v->{'COUNTER'}{$school}{'TOTAL'} user in $school",
              " (",
              "$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'teacher'} Teachers, ",
              "$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'student'} Students",
              ")\n";
    } # school end 
}



sub _console_print_admins_v {
    my ($ref_users_v,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    # one user per line
    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
    @school_list=($ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'},@school_list);

    my $line="+----------------------+-+-------------------------+------+--------------------------------+\n";

    foreach my $school (@school_list){
        my $count_admin;
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            $count_admin=$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'globaladministrator'}+
                          $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'globalbinduser'};
            
        } else {
            $count_admin=$ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schooladministrator'}+
                          $ref_users_v->{'COUNTER'}{$school}{'by_role'}{'schoolbinduser'};
        }

        &print_title("$count_admin administrators in school $school:");
        if ($count_admin==0){
            next;
        }
        print $line;
        print "| Administrator        |P| displayName             | Role | Comment                        |\n";
        print $line;
        foreach my $role ( @{ $ref_sophomorix_config->{'LISTS'}{'ALLADMINS'} } ){
            if ($#{ $ref_users_v->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } >-1){
                foreach my $user ( @{ $ref_users_v->{'LISTS'}{'USER_by_sophomorixSchoolname'}{$school}{$role} } ){
                    #my $gcs  = Unicode::GCString->new($ref_users_v->{'USERS'}{$user}{'displayName'});
		    my $role_display=$ref_sophomorix_config->{'LOOKUP'}{'ROLES_ALLADMINS'}{$role};
	  	    printf "| %-21s|%-1s| %-24s| %-4s | %-31s|\n",
                        $user,
                        substr($ref_users_v->{'USERS'}{$user}{'PWDFileExists'},0,1),,
                        $ref_users_v->{'USERS'}{$user}{'displayName'},
                        $role_display,
		        $ref_users_v->{'USERS'}{$user}{'sophomorixComment'};
                }
            }
        }
        print $line; 
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            print "P: Password file exists(T) or not(F)   gadm: globaladministrator   gbin: globalbinduser\n";
        } else {
            print "P: Password file exists(T) or not(F)   sadm: schooladministrator   sbin: schoolbinduser\n";
        }
        print "\n";
    } # school end 
}



sub _console_print_shares {
    my ($ref_share,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $count_share=0;
    my $count_school=0;
    my $line="+----------------------------------------------------------------------------+\n"; 

    # order shares before listing
    my @shares=(@{ $ref_share->{'LISTS'}{'GLOBAL'} },
                @{ $ref_share->{'LISTS'}{'SCHOOLS'} },
                @{ $ref_share->{'LISTS'}{'OTHER_SHARES'} });

    foreach my $share ( @shares ){
        $count_share++;
        print "$line";
        printf "| %2s) SMB-Share: %-60s|\n",$count_share,$share." (Type: ".$ref_share->{'SHARES'}{$share}{'TYPE'}.")";
        print "$line";

        if ($ref_share->{'SHARES'}{$share}{'TYPE'} eq "SCHOOL"){
            print"Configuration files: (*: exists, -:nonexisting)\n";
            foreach my $file ( @{ $ref_share->{'SHARES'}{$share}{'FILELIST'} } ){
                print "   ".$ref_share->{'SHARES'}{$share}{'FILE'}{$file}{'EXISTSDISPLAY'}." ".$file."\n";
            }
            print "SMB-share for school $share:\n";
        }
        printf "% 13s : %-50s \n",$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTSDISPLAY'},
                                  "SMB-share $share";
        printf "% 13s : %-50s \n",$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFSDISPLAY'},
                                  "msdfs root = ".$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFS'};
        printf "% 13s : %-50s \n",$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSERDISPLAY'},
                                  "aquota.user exists = ".$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSER'};
        printf "% 13s : %-50s \n",$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTASDISPLAY'},
                                  "smbcquotas -F => ".$ref_share->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTAS'};
        print "\n";
    }
}



sub _console_print_ui {
    my ($ref_ui,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $count_share=0;
    my $line="+----------------------------------------------------------------------------+\n";
    my @school_list;
    if ($school_opt eq ""){
        # prepend global as school
        @school_list=($ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'},
                      @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} });
    } else {
        @school_list=($school_opt);
    }

    my @rolelist=("globaladministrator","schooladministrator","teacher","student");

    foreach my $school (@school_list){
        print "\n";
        &print_title("SophomorixWebuiPermissionsCalculated updates in school $school:");
        foreach my $role (@rolelist){
            if ($#{ $ref_ui->{'LISTS_UPDATE'}{'USER_by_sophomorixSchoolname_by_sophomorixRole'}{$school}{$role} } >-1){
                print $line;
                printf "| %-70s|\n", $school." --> sophomorixRole: ".$role;
                print $line;
                foreach my $user ( @{ $ref_ui->{'LISTS_UPDATE'}{'USER_by_sophomorixSchoolname_by_sophomorixRole'}{$school}{$role} } ){
                    print " $user ($ref_ui->{'UI'}{'USERS'}{$user}{'displayName'},",
                          " $role, $ref_ui->{'UI'}{'USERS'}{$user}{'sophomorixAdminClass'}):\n"; 
                    print " sophomorixWebuiPermissionsCalculated: (old)\n";
                    my @oldlist = sort @{ $ref_ui->{'UI'}{'USERS'}{$user}{'sophomorixWebuiPermissionsCalculated'} };
                    foreach my $item ( @oldlist ){
                        print "    $item\n";
	            }
                    print " sophomorixWebuiPermissionsCalculated: (new)\n";
                    my @newlist = sort @{ $ref_ui->{'UI'}{'USERS'}{$user}{'CALCLIST'} };
                    foreach my $item ( @newlist ){
                        print "    $item\n";
	            }
                    print $line;
                }
	    }
        }
    } # end $school
    print "$ref_ui->{'LOOKUP'}{'COUNTER'}{'TOTAL'} users SophomorixWebuiPermissionsCalculated would be updated\n";
}



sub _console_print_mail_full {
    my ($ref_mail,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="#####################################################################\n";

    my @school_list;
    if ($school_opt eq ""){
        @school_list=@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
    } else {
        @school_list=($school_opt);
    }
    @school_list=($ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'},@school_list);
    foreach my $school (@school_list){
        &print_title("Mailaccounts/Maillists of school $school:");
        # there are 0 users
        if($#{ $ref_mail->{'LISTS'}{'USER_by_SCHOOL'}{$school} }==-1){
            print "     0 sophomorix users in school $school\n";
            next;
        }

        # there are users
        ############################################################
        # Walk through users
        print "Mailaccounts: (MAILLISTMEMBERS: *)\n";
        foreach my $user (@{ $ref_mail->{'LISTS'}{'USER_by_SCHOOL'}{$school} }){
            my $alias="ALIAS=FALSE";
            my $maillistmember_string;
            if ($ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'MAILLISTMEMBER'} eq "TRUE"){
                $maillistmember_string="*"; # *=TRUE
            } else {
                $maillistmember_string="-"; #-=FALSE
            }
            if ($ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIAS'} eq "TRUE"){
                $alias="ALIAS=".$ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'ALIASNAME'};
            }
            my $user_string="  ".$maillistmember_string." ".
                            $user.
                            " (".
                            $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAIL'}{'displayName'}.
                            ", ".
                            $ref_mail->{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'CALC'}.
                            " MiB, ".
                            $alias.
                            ")\n";
  
	    print $user_string;
        }
        print "\n";

        ############################################################
        # Walk through mailists
        foreach my $maillist ( @{ $ref_mail->{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} } ){
	    print "Maillist $maillist ($ref_mail->{'MAILLIST'}{$maillist}{'mail'}):\n";
            foreach my $member ( @{ $ref_mail->{'MAILLIST'}{$maillist}{'LIST'} } ){
	        print "  * $member\n";
            }
            print "\n";
        }
    } # end of school
}


sub _console_print_dirlisting {
    my ($ref_dirlist,$school_opt,$log_level,$ref_sophomorix_config)=@_;
    my $line1="#####################################################################\n";
    my $line2="---------------------------------------------------------------------\n";
    my $header="    owner gowner size/bytes            mod_time name\n";
    foreach my $sam (@{ $ref_dirlist->{'LISTS'}{'sAMAccountName'} }){
        print $line1;
        print "$sam: $ref_dirlist->{'sAMAccountName'}{$sam}{'SMB_PATH'}\n";
        my @dirlist=();
        my @filelist=();
        my @other=();
        foreach my $name (keys %{$ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'} }){
            if ($ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$name}{'TYPE'} eq "directory"){
                push @dirlist, $name;
	    } elsif ($ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$name}{'TYPE'} eq "file"){
                push @filelist, $name;
            }
        }
        @dirlist = sort @dirlist;
        @filelist = sort @filelist;

        print $line2;
        print "$ref_dirlist->{'sAMAccountName'}{$sam}{'COUNT'}{'directories'} Directories:\n";
        print $line2;
        print $header;
        foreach my $dir (@dirlist){
            my $mod=&epoch_to_ymdhms($ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$dir}{'TIME_MOD'});
            printf " %-1s %6s %6s %10s %19s %-35s\n",
                "d",
                $ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$dir}{'OWNER_ID'},
                $ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$dir}{'GOWNER_ID'},
                "---",
                $mod,
	        $dir;
        }
     
        print $line2;
        print "$ref_dirlist->{'sAMAccountName'}{$sam}{'COUNT'}{'files'} Files:\n";
        print $line2;
        print $header;
        foreach my $file (@filelist){
            my $mod=&epoch_to_ymdhms($ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$file}{'TIME_MOD'});
            printf " %-1s %6s %6s %10s %19s %-35s\n",
                "-",
                $ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$file}{'OWNER_ID'},
                $ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$file}{'GOWNER_ID'},
                $ref_dirlist->{'sAMAccountName'}{$sam}{'TREE'}{$file}{'SIZE_BYTES'},
                $mod,
	        $file;
#            print "  $file\n";
        }     
 

 
    }
}



# helper stuff
######################################################################
sub remove_from_list {
    # first argument: comma seperated elements to remove
    # other arguments: list elements
    my $option=shift;
    my @list = @_;
    my @removers=split(/,/,$option);
    my %seen=();
    my @stripped=();
    foreach $item (@removers) { $seen{$item} = 1 }
    foreach $item (@list) {
	if (not exists $seen{$item}){
            push(@stripped, $item);
       }
    }
    return @stripped;
}



sub remove_embracing_whitespace {
    my ($string)=@_;
    $string=~s/^\s+//g;# remove leading whitespace
    $string=~s/\s+$//g;# remove trailing whitespace
    return $string;    
}



sub remove_whitespace {
    my ($string)=@_;
    $string=~s/\s+//g;# remove whitespace anywhere
    return $string;    
}



sub extract_initial {
    my ($string)=@_;
    my $string_logical_chars = decode("utf8", $string); # decode in logical chars, to split by char, not byte
    my $result=$string_logical_chars;
    my @string = split /[-,\s\/]+/, $string_logical_chars; # split on whitespace and -
    foreach my $name (@string){
        my $initial=substr($name,0,1);
        $initial=$initial.".";
        $result=~s/$name/$initial/g; # replace name with initial in the complete string
    }
    my $result_utf8 = encode("utf8", $result); # encode back into utf8
    return $result_utf8;
}



sub ident_output {
    # idents multiline command output
    my ($string,$ident)=@_;
    my @lines=split(/\n/,$string);
    my @ident_lines=();
    foreach my $line (@lines){
        chomp($line);
        $line=~s/^(.*)/' ' x $ident . $1/e;
        push @ident_lines,$line;
    }
    my $string_ident=join("\n",@ident_lines);
    $string_ident=$string_ident."\n";
    return $string_ident;
}




# time stamps
######################################################################
sub ymdhms_to_date {
    my ($string)=@_;
    my ($ymdhms,$timezone)=split(/\./,$string);
    my ($year,$month,$day,$hour,$minute,$second)=unpack 'A4 A2 A2 A2 A2 A2',$ymdhms;
    my $date=$year."-".$month."-".$day." ".$hour.":".$minute.":".$second;
    return $date;
}



sub ymdhms_to_epoch {
    my ($string)=@_;
    my ($ymdhms,$timezone)=split(/\./,$string);
    #print "YMDHMS: $ymdhms\n";
    my ($year,$month,$day,$hour,$minute,$second)=unpack 'A4 A2 A2 A2 A2 A2',$ymdhms;
    #print "$year $month $day $hour $minute $second\n";
    my $epoch=timelocal($second, $minute, $hour, $day , ($month-1), $year);
    #print "epoch of $string is $epoch\n";
    return $epoch;
}



sub epoch_to_ymdhms {
    my ($epoch)=@_;
    
    my ($sec,$min,$hour,$day,$month,$year) = (localtime($epoch))[0,1,2,3,4,5];
    $year=$year+1900;
    $month=$month+1;
    my $string=$year."-".$month."-".$day."_".$hour.":".$min.":".$sec;
    return $string;
}



# sophomorix locking
######################################################################
sub unlock_sophomorix{
    &print_title("Removing lock in $DevelConf::lock_file");
    my $timestamp=&time_stamp_file();
    my $unlock_dir=$DevelConf::lock_logdir."/".$timestamp."_unlock";
    # make sure logdir exists
    if (not -e "$DevelConf::lock_logdir"){
        system("mkdir $DevelConf::lock_logdir");
    }

    if (-e $DevelConf::lock_file){
        # create timestamped dir
        if (not -e "$unlock_dir"){
            system("mkdir $unlock_dir");
        }
        
        # save sophomorix.lock
        system("mv $DevelConf::lock_file $unlock_dir");

        # saving last lines of command.log
        $command="tail -n 100  ${DevelConf::log_command} ".
	         "> ${unlock_dir}/command.log.tail";
        if($Conf::log_level>=3){
   	    print "$command\n";
        }
	system("$command");

        print "Created log data in ${unlock_dir}\n";
    } else {
        &print_title("Lock $DevelConf::lock_file did not exist");
    }
}



sub lock_sophomorix {
    #my ($type,$pid,@arguments) = @_;
    my ($type,$pid,$ref_arguments) = @_;
    # $type: lock (lock when not existing)
    # $type, steal when existing
    # $pid: steal only when this pid is in the lock file

    # prepare datastring to write into lockfile
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $lock="lock::${timestamp}::creator::$0";
#    foreach my $arg (@arguments){
    foreach my $arg ( @{ $ref_arguments}  ){    
        if ($arg eq "--skiplock"){
            $skiplock=1;
        }
        if ($arg eq ""){
   	    $lock=$lock." ''";
        } else {
	    $lock=$lock." ".$arg ;
        }
    }
    $lock=$lock."::$$"."::\n";

    if ($type eq "lock"){
        # lock , only when nonexisting
        if (not -e $DevelConf::lock_file){
           &print_title("Creating lock in $DevelConf::lock_file");
           open(LOCK,">$DevelConf::lock_file") || die "Cannot create lock file \n";
           print LOCK "$lock";
           close(LOCK);
        } else {
           print "Cold not create lock file (file exists already!)\n";
           exit 88;
        }
    } elsif ($type eq "steal"){
        # steal, only when existing with pid $pid
        my ($l_script,$l_pid)=&read_lockfile();
	if (-e $DevelConf::lock_file
           and $l_pid==$pid){
           &print_title("Stealing lock in $DevelConf::lock_file");
           open(LOCK,">$DevelConf::lock_file") || die "Cannot create lock file \n";
           print LOCK "$lock";
           close(LOCK);
           return 1;
       } else {
           print "Coldnt steal lock file (file vanished! or pid changed)\n";
           exit 88;
       }
    }
}



sub read_lockfile {
    my ($log_locked) = @_;
    open(LOCK,"<$DevelConf::lock_file") || die "Cannot create lock file \n";
    while (<LOCK>) {
        @lock=split(/::/);
    }
    close(LOCK);

    # write to command.log
    if (defined $log_locked){
       open(LOG,">>$DevelConf::log_command");
       print LOG "$log_locked";
       close(LOG);
    }

    my $locking_script=$lock[3];
    my $locking_pid=$lock[4];
    return ($locking_script,$locking_pid);
}

# read file into json object
######################################################################
sub read_sophomorix_add {
    my ($arg_ref) = @_;
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my %add=();
    my $ref_add=\%add;
    my @lines=();

    my $add_file=$ref_sophomorix_config->{'INI'}{'PATHS'}{'CHECK_RESULT'}."/sophomorix.add";
    if (not -e "$add_file"){
        print "Nothing to add: nonexisting $add_file\n";
        $add{'COUNTER'}{'TOTAL'}=0; 
        return $ref_add;
    }

    # read lines
    open(SOPHOMORIXADD,"$add_file") || die "ERROR: sophomorix.add not found!";
    while(<SOPHOMORIXADD>){
       if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
	   next;
       }
       push @lines, $_;
    }
    close(SOPHOMORIXADD);

    # sort lines
    my @sorted_lines = sort {
        my @a_fields = split /::/, $a;
        my @aa_fields = split /;/, $a_fields[2];

        my @b_fields = split /::/, $b;
        my @bb_fields = split /;/, $b_fields[2];

        $a_fields[1] cmp $b_fields[1]  # string sort on 1st field, then
            ||
        $aa_fields[2] cmp $bb_fields[2]  # string sort on 2nd field
            ||
        $aa_fields[1] cmp $bb_fields[1]  # string sort on 3rd field
    } @lines;

   foreach my $line (@sorted_lines){
       chomp($line);
       $count++;
       ($file,
        $class_group,
        $identifier,
        $sam,
        $password_wish,
        $uidnumber_migrate,
        $gidnumber_migrate,
        $unid,
        $school,
        $role,
        $surname_utf8,
        $firstname_utf8,
        $status,
        $creationdate,
        $tolerationdate,
        $deactivationdate,
        $sambantpassword,
        $userpassword,
        $mail,
        $webui_permissions_calculated_string,
       )=split("::",$line);

       push @{ $add{'LISTS'}{'ORDERED'} },$sam;
       push @{ $add{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school} },$sam;

       $add{'USER'}{$sam}{'FILE'}=$file;
       $add{'USER'}{$sam}{'ADMINCLASS'}=$class_group;
       $add{'USER'}{$sam}{'IDENTIFIER'}=$identifier;
       $add{'USER'}{$sam}{'SAM'}=$sam;
       $add{'USER'}{$sam}{'PWD_WISH'}=$password_wish;
       $add{'USER'}{$sam}{'UID_WISH'}=$uidnumber_migrate;
       $add{'USER'}{$sam}{'GID_WISH'}=$gidnumber_migrate;
       $add{'USER'}{$sam}{'UNID'}=$unid;
       $add{'USER'}{$sam}{'SCHOOL'}=$school;
       $add{'USER'}{$sam}{'ROLE'}=$role;
       $add{'USER'}{$sam}{'FIRSTNAME_UTF8'}=$firstname_utf8;
       $add{'USER'}{$sam}{'SURNAME_UTF8'}=$surname_utf8;
       $add{'USER'}{$sam}{'MAIL'}=$mail;
    }

    # counters
    $add{'COUNTER'}{'TOTAL'}=$#{ $add{'LISTS'}{'ORDERED'} }+1;
    foreach my $school (keys %{ $add{'LISTS'}{'ORDERED_by_sophomorixSchoolname'} }) {
        $add{'COUNTER'}{'SCHOOL'}{$school}=$#{ $add{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school} }+1;
    }
    return $ref_add;
}



sub read_sophomorix_update {
    my ($arg_ref) = @_;
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my %update=();
    my $ref_update=\%update;
    my @lines=();

    my $update_file=$ref_sophomorix_config->{'INI'}{'PATHS'}{'CHECK_RESULT'}."/sophomorix.update";
    if (not -e "$update_file"){
        print "Nothing to update: nonexisting $update_file\n";
        $update{'COUNTER'}{'TOTAL'}=0; 
        return $ref_update;
    }

    # read lines
    open(SOPHOMORIXUPDATE,"$update_file") || die "ERROR: sophomorix.update not found!";
    while(<SOPHOMORIXUPDATE>){
       if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
	   next;
       }
       push @lines, $_;
    }
    close(SOPHOMORIXUPDATE);


    my @sorted_lines = sort {
        my @a_fields = split /::/, $a;
        my @b_fields = split /::/, $b;
 
        $a_fields[1] cmp $b_fields[1]  # string sort on 1st field, then
          ||
        $a_fields[0] cmp $b_fields[0]  # string sort on 2nd field
    } @lines;

    foreach my $line (@sorted_lines){
        chomp($line);
        $count++;
        my ($sam,
            $unid_old,
            $unid_new,
            $surname_ascii_old,
            $surname_ascii_new,
            $firstname_ascii_old,
            $firstname_ascii_new,
            $birthdate_old,
            $birthdate_new,
            $surname_utf8_old,
            $surname_utf8_new,
            $firstname_utf8_old,
            $firstname_utf8_new,
            $filename_old,
            $filename_new,
            $status_old,
            $status_new,
            $role_old,
            $role_new,
            $class_old,
            $class_new,
            $school_old,
            $school_new,
            $surname_initial_utf8_old,
            $surname_initial_utf8_new,
            $firstname_initial_utf8_old,
            $firstname_initial_utf8_new,
            $mail_old,
            $mail_new,
            $webui_string_old,
            $webui_string_new,
            $homedirectory_old,
            $homedirectory_new,
            $homedirectory_old_rel,
            $homedirectory_new_rel,
           )=split(/::/,$line);

        my $name_ascii_new=$surname_ascii_new.", ".$firstname_ascii_new;
        my $name_utf8_new=$surname_utf8_new.", ".$firstname_utf8_new;

        push @{ $update{'LISTS'}{'ORDERED'} },$sam;
        if ($school_old eq $school_new or $school_new eq "---"){
            # add only if users stays in its school
            push @{ $update{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school_old} },$sam;
        } else {
            # school change
            push @{ $update{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{'global'} },$sam;
        }

        $update{'USER'}{$sam}{'UNID_OLD'}=$unid_old;
        $update{'USER'}{$sam}{'UNID_NEW'}=$unid_new;
        $update{'USER'}{$sam}{'BIRTHDATE_OLD'}=$birthdate_old;
        $update{'USER'}{$sam}{'BIRTHDATE_NEW'}=$birthdate_new;

        $update{'USER'}{$sam}{'SURNAME_ASCII_OLD'}=$surname_ascii_old;
        $update{'USER'}{$sam}{'SURNAME_ASCII_NEW'}=$surname_ascii_new;
        $update{'USER'}{$sam}{'FIRSTNAME_ASCII_OLD'}=$firstname_ascii_old;
        $update{'USER'}{$sam}{'FIRSTNAME_ASCII_NEW'}=$firstname_ascii_new;

        $update{'USER'}{$sam}{'SURNAME_UTF8_OLD'}=$surname_utf8_old;
        $update{'USER'}{$sam}{'SURNAME_UTF8_NEW'}=$surname_utf8_new;
        $update{'USER'}{$sam}{'FIRSTNAME_UTF8_OLD'}=$firstname_utf8_old;
        $update{'USER'}{$sam}{'FIRSTNAME_UTF8_NEW'}=$firstname_utf8_new;

        $update{'USER'}{$sam}{'SURNAME_INITIAL_UTF8_OLD'}=$surname_initial_utf8_old;
        $update{'USER'}{$sam}{'SURNAME_INITIAL_UTF8_NEW'}=$surname_initial_utf8_new;
        $update{'USER'}{$sam}{'FIRSTNAME_INITIAL_UTF8_OLD'}=$firstname_initial_utf8_old;
        $update{'USER'}{$sam}{'FIRSTNAME_INITIAL_UTF8_NEW'}=$firstname_initial_utf8_new;

        $update{'USER'}{$sam}{'FILE_OLD'}=$filename_old;
        $update{'USER'}{$sam}{'FILE_NEW'}=$filename_new;
        $update{'USER'}{$sam}{'STATUS_OLD'}=$status_old;
        $update{'USER'}{$sam}{'STATUS_NEW'}=$status_new;
        $update{'USER'}{$sam}{'ROLE_OLD'}=$role_old;
        $update{'USER'}{$sam}{'ROLE_NEW'}=$role_new;
        $update{'USER'}{$sam}{'CLASS_OLD'}=$class_old;
        $update{'USER'}{$sam}{'CLASS_NEW'}=$class_new;
        $update{'USER'}{$sam}{'SCHOOL_OLD'}=$school_old;
        $update{'USER'}{$sam}{'SCHOOL_NEW'}=$school_new;
        $update{'USER'}{$sam}{'MAIL_OLD'}=$mail_old;
        $update{'USER'}{$sam}{'MAIL_NEW'}=$mail_new;
        $update{'USER'}{$sam}{'WEBUI_STRING_OLD'}=$webui_string_old;
        $update{'USER'}{$sam}{'WEBUI_STRING_NEW'}=$webui_string_new;
        $update{'USER'}{$sam}{'HOMEDIRECTORY_OLD'}=$homedirectory_old;
        $update{'USER'}{$sam}{'HOMEDIRECTORY_NEW'}=$homedirectory_new;
        $update{'USER'}{$sam}{'HOMEDIRECTORY_OLD_REL'}=$homedirectory_old_rel;
        $update{'USER'}{$sam}{'HOMEDIRECTORY_NEW_REL'}=$homedirectory_new_rel;
    }

    # counters
    $update{'COUNTER'}{'TOTAL'}=$#{ $update{'LISTS'}{'ORDERED'} }+1;
    foreach my $school (keys %{ $update{'LISTS'}{'ORDERED_by_sophomorixSchoolname'} }) {
        $update{'COUNTER'}{'SCHOOL'}{$school}=$#{ $update{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school} }+1;
    }
    return $ref_update;  
}



sub read_sophomorix_kill {
    my ($arg_ref) = @_;
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my %kill=();
    my $ref_kill=\%kill;
    my @lines=();

    my $kill_file=$ref_sophomorix_config->{'INI'}{'PATHS'}{'CHECK_RESULT'}."/sophomorix.kill";
    if (not -e "$kill_file"){
        print "Nothing to kill: nonexisting $kill_file\n";
        $kill{'COUNTER'}{'TOTAL'}=0; 
        return $ref_kill;
    }

    # read lines
    open(SOPHOMORIXKILL,"$kill_file") || die "ERROR: sophomorix.kill not found!";
    while(<SOPHOMORIXKILL>){
       if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
	   next;
       }
       push @lines, $_;
    }
    close(SOPHOMORIXKILL);

    my @sorted_lines = sort {
        my @a_fields = split /::/, $a;
        my @b_fields = split /::/, $b;
 
        $a_fields[2] cmp $b_fields[2]  # string sort on 1st field, then
          ||
        $a_fields[1] cmp $b_fields[1]  # string sort on 2nd field
    } @lines;

    foreach my $line (@sorted_lines){
        chomp($line);
        my ($identifier,
            $sam,
            $adminclass,
            $school
           )=split(/::/,$line);

        push @{ $kill{'LISTS'}{'ORDERED'} },$sam;
        push @{ $kill{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school} },$sam;

        $kill{'USER'}{$sam}{'IDENTIFIER'}=$identifier;
        $kill{'USER'}{$sam}{'sophomorixSchoolname'}=$school;
        $kill{'USER'}{$sam}{'sophomorixAdminClass'}=$adminclass;
    }

    # counters
    $kill{'COUNTER'}{'TOTAL'}=$#{ $kill{'LISTS'}{'ORDERED'} }+1;
    foreach my $school (keys %{ $kill{'LISTS'}{'ORDERED_by_sophomorixSchoolname'} }) {
        $kill{'COUNTER'}{'SCHOOL'}{$school}=$#{ $kill{'LISTS'}{'ORDERED_by_sophomorixSchoolname'}{$school} }+1;
    }

    return $ref_kill;
}



# run hooks scripts
######################################################################
sub run_hook_scripts {
    my ($hook,$ref_result,$ref_sophomorix_config,$doit)=@_;
    if ($doit eq "TRUE"){
        # DO run all scripts
        &print_title("Running hook scripts $hook:");
    } else {
        # Not running scripts, just do what WOULD be done
        print "\n";
        &print_title("TEST: Running hook scripts $hook:");
    }
    # create list with global and schools
    my @list=($DevelConf::AD_global_ou,@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} });
    my %exe=();

    foreach my $school ( @list ){
        my $hookdir;
        my $logdir;
        if ($school eq $DevelConf::AD_global_ou){
            $hookdir=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'HOOKS'}{'DIR'}{$hook};
            $logdir=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'HOOKS'}{'LOGDIR'}{$hook};
	} else {
            $hookdir=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'HOOKS'}{'DIR'}{$hook};
            $logdir=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'HOOKS'}{'LOGDIR'}{$hook};
        }
        if ($doit ne "TRUE"){
            # TEST
            print "\n";
            print "School $school: Looking for hook scripts in:\n";
            print "  $hookdir\n";
        }
        if (-d $hookdir){
            my @scriptlist=();
	    opendir HOOK, $hookdir;
            foreach my $script (readdir HOOK){
                if ($script eq "." or $script eq ".."){next};
                my $path_abs=$hookdir."/".$script;
                if ( not $script=~m/^[a-zA-Z0-9-_\.]+$/){
                    if ($doit ne "TRUE"){
                        # TEST
                        print "    * Invalid characters: skipping hook script $script\n";
                    }
                    next;
                }
                if (-x $path_abs and -f $path_abs){
                    push @scriptlist, $path_abs;
                    $exe{$path_abs}{'EXECUTABLE'}="yes";
                    $exe{$path_abs}{'LOGFILE'}=$logdir."/".$script;
                } else {
                    if ($doit ne "TRUE"){
                        # TEST
                        print "    * Not an executable file: skipping $script\n";
                    }

                }
            }
            closedir(HOOK);
            @scriptlist = sort @scriptlist;
            my $executable_num=$#scriptlist+1;
            if ($executable_num>0){
                foreach my $executable (@scriptlist){
                    # create the command an run it
                    my $optstring;
                    if ($school eq $DevelConf::AD_global_ou){
                        $optstring="";
                    } else {
                        $optstring=$school." ";
                    }

                    my $logfile=$exe{$executable}{'LOGFILE'}.".log";
                    my $command="$executable $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'EPOCH'} $optstring>> $logfile 2>&1";
                    if ($doit eq "TRUE"){
                        print "Running: ".$command."\n";
                        $dirname  = dirname($logfile);
                        system("mkdir -p $dirname");
                        my $string=$hook.
                                   " -> DATE: ".
                                   $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_FILE'}.
                                   " (LOCALTIME)";
                        system("echo \"\n$string\" >> $logfile");
                        system($command);
                    } else {
                        print "    * I would run: ".$command."\n";
                    }
                }
            } else {
                if ($doit ne "TRUE"){
                    # TEST
                    print "    * no executable script\n";
                }
            }
        } else {
            if ($doit ne "TRUE"){
                # TEST
                print "    * no hook dir $hookdir\n";
	    }
        }
    }

}



# command execution 
######################################################################
sub call_sophomorix_command {
    my ($log_level,$json,$command)=@_;
    my $all_opt="";
    if ($log_level==2){
	$all_opt=$all_opt."v";
    } elsif ($log_level==3){
        $all_opt=$all_opt."vv";
    }
    if ($json==1){
        $all_opt=$all_opt."j";
    } elsif ($json==2){
        $all_opt=$all_opt."jj";
    } elsif ($json==3){
        $all_opt=$all_opt."jjj";
    }
    if ($all_opt ne ""){
        $all_opt="-".$all_opt;
    }
    my $full_command=$command." ".$all_opt;
    print "$full_command\n";
    system($full_command);
}



# reading configuration files
######################################################################
sub config_sophomorix_read {
    my ($ldap,$root_dse,$ref_result,$json)=@_;
    my %sophomorix_config=();

    my ($smb_admin_pass)=&Sophomorix::SophomorixSambaAD::AD_get_passwd($DevelConf::sophomorix_AD_admin,
                                                                $DevelConf::secret_file_sophomorix_AD_admin);
    # # UTC Time
    # # all UTC time values are derived from the same date call
    # { 
    #     my $time_stamp_AD_utc=`date --utc '+%Y%m%d%H%M%S'`;
    #     chomp($time_stamp_AD_utc);
    #     $time_stamp_AD_utc=$time_stamp_AD_utc.".0Z";
    #     my ($year,$month,$day,$hour,$minute,$second)=unpack 'A4 A2 A2 A2 A2 A2',$time_stamp_AD_utc;
    #     my $time_stamp_file_utc=$year."-".$month."-".$day."_".$hour."-".$minute."-".$second;
    #     my $time_stamp_log_utc=$year."-".$month."-".$day." ".$hour.":".$minute.":".$second;
    #     my $epoch_utc=timelocal($second, $minute, $hour, $day , ($month-1), $year);
    #     $sophomorix_config{'DATE'}{'UTC'}{'TIMESTAMP_AD'}=$time_stamp_AD_utc;
    #     $sophomorix_config{'DATE'}{'UTC'}{'TIMESTAMP_FILE'}=$time_stamp_file_utc;
    #     $sophomorix_config{'DATE'}{'UTC'}{'TIMESTAMP_LOG'}=$time_stamp_log_utc;
    #     $sophomorix_config{'DATE'}{'UTC'}{'EPOCH'}=$epoch_utc;
    # }

    # LOCAL Time
    # all LOCAL time values are derived from the same date call
    {
        my $time_stamp_AD=`date '+%Y%m%d%H%M%S'`;
        chomp($time_stamp_AD);
        $time_stamp_AD=$time_stamp_AD.".0Z";
        my ($year,$month,$day,$hour,$minute,$second)=unpack 'A4 A2 A2 A2 A2 A2',$time_stamp_AD;
        my $time_stamp_file=$year."-".$month."-".$day."_".$hour."-".$minute."-".$second;
        my $time_stamp_log=$year."-".$month."-".$day." ".$hour.":".$minute.":".$second;
        my $epoch=timelocal($second, $minute, $hour, $day , ($month-1), $year);
        $sophomorix_config{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}=$time_stamp_AD; # date format in AD
        $sophomorix_config{'DATE'}{'LOCAL'}{'TIMESTAMP_FILE'}=$time_stamp_file; # date format filenames
        $sophomorix_config{'DATE'}{'LOCAL'}{'TIMESTAMP_LOG'}=$time_stamp_log; # date format for loglines
        $sophomorix_config{'DATE'}{'LOCAL'}{'EPOCH'}=$epoch; # date format for calculation
    }
    #$sophomorix_config{'DATE'}{'EPOCH'}=time;

    # read available encodings from iconv --list
    my %encodings_set=();
    my $available_encodings = `iconv --list`;  #Backticks return a string.
    my @encodings_arr = split /\s+/, $available_encodings;
    foreach my $coding_orig (@encodings_arr){
        my $coding=$coding_orig;
        $coding=~s/\/\/$//g;# remove trailing whitespace
        #print "<$coding>\n";
        $sophomorix_config{'ENCODINGS'}{$coding}=$coding_orig;
        #$encodings_set{$coding}=$coding_orig;
    }

    # read sophomorix.ini
    &read_sophomorix_ini(\%sophomorix_config,$ref_result);
    # read lsbrelease
    &read_lsbrelease(\%sophomorix_config,$ref_result);
    # read smb.conf
    &read_smb_conf(\%sophomorix_config,$ref_result);
    # read default-ui-permissions.ini
    &read_ui(\%sophomorix_config,$ref_result);
    # read more samba stuff
    &read_smb_net_conf_list(\%sophomorix_config,$ref_result);
    &read_smb_domain_passwordsettings(\%sophomorix_config,$smb_admin_pass,$ref_result);

    #my %encodings_set = map {lc $_ => undef} @encodings_arr;

    # Adding some defaults: ????? better to move the defaults to an external file ?????
    # default school
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'CONF_FILE'}=
        $DevelConf::path_conf_sophomorix."/".$DevelConf::name_default_school."/school.conf"; 
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'TEMPLATES_LATEX_DIR'}=
                            $DevelConf::path_conf_sophomorix."/".$DevelConf::name_default_school."/".
                            $sophomorix_config{'INI'}{'LATEX'}{'TEMPLATES_CUSTOM_SUBDIR'};

    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'SCHOOL_LONGNAME'}=
        "School"; 
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'OU_TOP'}=
        "OU=".$DevelConf::name_default_school.",".$DevelConf::AD_schools_ou.",".$root_dse; 

    # Adding repdir absolute paths
    opendir REPDIR, $DevelConf::path_conf_devel_repdir or 
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$DevelConf::path_conf_devel_repdir." not found!");
    foreach my $file (readdir REPDIR){
        my $abs_path=$DevelConf::path_conf_devel_repdir."/".$file;
        my $Type;
        if ($file eq "."){next};
        if ($file eq ".."){next};
        $sophomorix_config{'REPDIR_FILES'}{$file}{'PATH_ABS'}=$abs_path;
    }
    closedir REPDIR;

    # add default school to school list
    push @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} }, $DevelConf::name_default_school; 

    ##################################################
    # sophomorix.conf
    # reading the master file
    my $ref_master_sophomorix=&read_master_ini($DevelConf::path_conf_master_sophomorix,$ref_result);
    my $ref_modmaster_sophomorix=&check_config_ini($ref_master_sophomorix,
                                                   $DevelConf::file_conf_sophomorix,
                                                   $ref_result,
                                                   \%sophomorix_config);
    &load_sophomorix_ini($ref_modmaster_sophomorix,\%sophomorix_config,$ref_result);

    # Working on the sections of sophomorix.ini 
    # part 1 (before knowing about schools)
    ###############################################
    # if you need process it differently for each school, move it to part 2
    foreach my $section  (keys %{$sophomorix_config{'INI'}}) {
        if ($section eq "LANG"){
            foreach my $keyname (keys %{$sophomorix_config{'INI'}{$section}}) {
                if ($keyname eq "LANG_ALLOWED"){
                    my @lang=split(/,/,$sophomorix_config{'INI'}{$section}{$keyname});
                    foreach my $lang (@lang){
                        $sophomorix_config{'LOOKUP'}{'LANG_ALLOWED'}{$lang}="allowed";
                    }
                }
            }
        }
    }

    ##################################################
    # SCHOOLS  
    # read the *.school.conf
    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
	# test if school is configured
	# share <school >must exist
	if (exists $sophomorix_config{'samba'}{'net_conf_list'}{$school}){
            if($Conf::log_level>=2){
	        &print_title("OK: $school share exists");
            }
	} else {
	    print "\n";
            print "ERROR: You have no share for the configured school $school\n";
            print "       You need a share $school with:\n";
            print "         * Full access with the same Administrator password\n";
            print "         * A fully working quota system on the share\n";
            print "       You can create the share with:\n";
            print "         * a local share with ??????? of the linuxmuster-base7 package\n";
            print "         * a remote share according to a Howto\n";
	    print "\n";
	    exit;
	}

	# <school>.school.conf must exist
	if (-f $sophomorix_config{'SCHOOLS'}{$school}{'CONF_FILE'}){
            if($Conf::log_level>=2){
	        &print_title("OK: $sophomorix_config{'SCHOOLS'}{$school}{'CONF_FILE'}");
            }
	} else {
	    print "\n";
            print "ERROR: $sophomorix_config{'SCHOOLS'}{$school}{'CONF_FILE'} nonexisting\n";
	    print "\n";
            print "Create the file from a template with the command:\n";
            print "   sophomorix-postinst $school\n";
	    print "\n";
	    exit;
        }   

        # cp ui stuff from UI to ROLES (schools)
        foreach my $ui_role (keys %{ $sophomorix_config{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS'} }){
            if ($ui_role eq "globaladministrator"){
                # skip, because its saved in $school
            } else {
                foreach my $mod (keys %{ $sophomorix_config{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS_LOOKUP'}{$ui_role} }){
                    $sophomorix_config{'ROLES'}{$school}{$ui_role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'}{$mod}=
                        $sophomorix_config{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS_LOOKUP'}{$ui_role}{$mod};
                }
            }
        }

	# read the config
        $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'}=
            "OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
                 if ($school eq $DevelConf::name_default_school){
                     # default-school
                     $sophomorix_config{'SCHOOLS'}{$school}{'SCHOOL'}=
                          $DevelConf::name_default_school;
                     $sophomorix_config{'SCHOOLS'}{$school}{'PREFIX'}="";
                     $sophomorix_config{'SCHOOLS'}{$school}{'POSTFIX'}="";
                 } else {
                     # *school
                     $sophomorix_config{'SCHOOLS'}{$school}{'SCHOOL'}=$school;
                     $sophomorix_config{'SCHOOLS'}{$school}{'PREFIX'}=$school."-";
                     $sophomorix_config{'SCHOOLS'}{$school}{'POSTFIX'}="-".$school;
                     $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'}=
                         $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'};
                 }

        # load the master ini
        my $ref_master=&read_master_ini($DevelConf::path_conf_master_school,$ref_result);
        my $conf_school=$sophomorix_config{'SCHOOLS'}{$school}{'CONF_FILE'};
        # modify the master
        my $ref_modmaster=&check_config_ini($ref_master,$conf_school,$ref_result,\%sophomorix_config);
        &load_school_ini($root_dse,$school,$conf_school,$ref_modmaster,\%sophomorix_config,$ref_result);
        # mountpoint
        $sophomorix_config{'SCHOOLS'}{$school}{'MOUNTPOINT'}=
            $sophomorix_config{'INI'}{'PATHS'}{'MOUNTPOINT'}."/schools/".$school;
        # lang of school
        if ($sophomorix_config{'SCHOOLS'}{$school}{'LANG'} eq ""){
            # use global as the lang
            $sophomorix_config{'SCHOOLS'}{$school}{'LANG'}=$sophomorix_config{'GLOBAL'}{'LANG'};
        } else {
            # test lang
            if (not exists $sophomorix_config{'LOOKUP'}{'LANG_ALLOWED'}{$sophomorix_config{'SCHOOLS'}{$school}{'LANG'}}){
                print "$sophomorix_config{'SCHOOLS'}{$school}{'LANG'}\n";
                print "$sophomorix_config{'LOOKUP'}{'LANG_ALLOWED'}\n";
                print "ERROR: Unallowed language $sophomorix_config{'SCHOOLS'}{$school}{'LANG'}\n";
                print "   in: $sophomorix_config{'SCHOOLS'}{$school}{'CONF_FILE'}\n\n";
                exit 88;
            }
        }
        # mailconf
        if ($sophomorix_config{'SCHOOLS'}{$school}{'MAILTYPE'} ne "none"){
            $sophomorix_config{'SCHOOLS'}{$school}{'MAILCONFDIR'}=
                $DevelConf::path_conf_sophomorix."/".$school."/".
                $sophomorix_config{'SCHOOLS'}{$school}{'MAILTYPE'};
            $sophomorix_config{'SCHOOLS'}{$school}{'MAILCONF'}=
                $DevelConf::path_conf_sophomorix."/".$school."/".
                $school.".".$sophomorix_config{'SCHOOLS'}{$school}{'MAILTYPE'}.".conf";
        } else {
            $sophomorix_config{'SCHOOLS'}{$school}{'MAILCONFDIR'}="none";
            $sophomorix_config{'SCHOOLS'}{$school}{'MAILCONF'}="none";
        }
        # hooks school
        my $abs_hook_dir=$DevelConf::path_conf_sophomorix."/".$school."/".$sophomorix_config{'INI'}{'HOOKS'}{'SUBDIR'};
        $sophomorix_config{'SCHOOLS'}{$school}{'HOOKS'}{'DIR'}{'ADD_HOOK_DIR'}=
            $abs_hook_dir."/".$sophomorix_config{'INI'}{'HOOKS'}{'ADD_HOOK_DIR'};
        $sophomorix_config{'SCHOOLS'}{$school}{'HOOKS'}{'LOGDIR'}{'ADD_HOOK_DIR'}=
            $sophomorix_config{'INI'}{'HOOKS'}{'LOGDIR'}."/".$school."/".$sophomorix_config{'INI'}{'HOOKS'}{'ADD_HOOK_DIR'};
        $sophomorix_config{'SCHOOLS'}{$school}{'HOOKS'}{'DIR'}{'UPDATE_HOOK_DIR'}=
            $abs_hook_dir."/".$sophomorix_config{'INI'}{'HOOKS'}{'UPDATE_HOOK_DIR'};
        $sophomorix_config{'SCHOOLS'}{$school}{'HOOKS'}{'LOGDIR'}{'UPDATE_HOOK_DIR'}=
            $sophomorix_config{'INI'}{'HOOKS'}{'LOGDIR'}."/".$school."/".$sophomorix_config{'INI'}{'HOOKS'}{'UPDATE_HOOK_DIR'};
        $sophomorix_config{'SCHOOLS'}{$school}{'HOOKS'}{'DIR'}{'KILL_HOOK_DIR'}=
            $abs_hook_dir."/".$sophomorix_config{'INI'}{'HOOKS'}{'KILL_HOOK_DIR'};
        $sophomorix_config{'SCHOOLS'}{$school}{'HOOKS'}{'LOGDIR'}{'KILL_HOOK_DIR'}=
            $sophomorix_config{'INI'}{'HOOKS'}{'LOGDIR'}."/".$school."/".$sophomorix_config{'INI'}{'HOOKS'}{'KILL_HOOK_DIR'};
    } # done with schools

    # GLOBAL
    $sophomorix_config{$DevelConf::AD_global_ou}{'OU_TOP'}=
        "OU=".$DevelConf::AD_global_ou.",".$root_dse;
    # read GLOBAL
    $sophomorix_config{$DevelConf::AD_global_ou}{'SCHOOL'}=$sophomorix_config{'INI'}{'GLOBAL'}{'SCHOOLNAME'};
    $sophomorix_config{$DevelConf::AD_global_ou}{'PREFIX'}="";
    # mountpoint
    $sophomorix_config{$DevelConf::AD_global_ou}{'MOUNTPOINT'}=
        $sophomorix_config{'INI'}{'PATHS'}{'MOUNTPOINT'}."/".$sophomorix_config{'INI'}{'GLOBAL'}{'SCHOOLNAME'};

    # hooks GLOBAL
    my $abs_hook_dir=$DevelConf::path_conf_sophomorix."/".$sophomorix_config{'INI'}{'HOOKS'}{'SUBDIR'};
    $sophomorix_config{$DevelConf::AD_global_ou}{'HOOKS'}{'DIR'}{'ADD_HOOK_DIR'}=
        $abs_hook_dir."/".$sophomorix_config{'INI'}{'HOOKS'}{'ADD_HOOK_DIR'};
    $sophomorix_config{$DevelConf::AD_global_ou}{'HOOKS'}{'LOGDIR'}{'ADD_HOOK_DIR'}=
        $sophomorix_config{'INI'}{'HOOKS'}{'LOGDIR'}."/".$sophomorix_config{'INI'}{'HOOKS'}{'ADD_HOOK_DIR'};

    $sophomorix_config{$DevelConf::AD_global_ou}{'HOOKS'}{'DIR'}{'UPDATE_HOOK_DIR'}=
        $abs_hook_dir."/".$sophomorix_config{'INI'}{'HOOKS'}{'UPDATE_HOOK_DIR'};
    $sophomorix_config{$DevelConf::AD_global_ou}{'HOOKS'}{'LOGDIR'}{'UPDATE_HOOK_DIR'}=
        $sophomorix_config{'INI'}{'HOOKS'}{'LOGDIR'}."/".$sophomorix_config{'INI'}{'HOOKS'}{'UPDATE_HOOK_DIR'};

    $sophomorix_config{$DevelConf::AD_global_ou}{'HOOKS'}{'DIR'}{'KILL_HOOK_DIR'}=
        $abs_hook_dir."/".$sophomorix_config{'INI'}{'HOOKS'}{'KILL_HOOK_DIR'};
    $sophomorix_config{$DevelConf::AD_global_ou}{'HOOKS'}{'LOGDIR'}{'KILL_HOOK_DIR'}=
        $sophomorix_config{'INI'}{'HOOKS'}{'LOGDIR'}."/".$sophomorix_config{'INI'}{'HOOKS'}{'KILL_HOOK_DIR'};

    # cp ui stuff from UI to ROLES (global)
    foreach my $mod (keys %{ $sophomorix_config{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS_LOOKUP'}{'globaladministrator'} }){
        $sophomorix_config{'ROLES'}{'global'}{'globaladministrator'}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'}{$mod}=
            $sophomorix_config{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS_LOOKUP'}{'globaladministrator'}{$mod};
    }

    # SCHOOL
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'OU_TOP'}=
        "OU=".$DevelConf::name_default_school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'SCHOOL'}=
        $DevelConf::name_default_school;
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'PREFIX'}="";
    # mountpoint
    $sophomorix_config{'SCHOOLS'}{$DevelConf::name_default_school}{'MOUNTPOINT'}=
        $sophomorix_config{'INI'}{'PATHS'}{'MOUNTPOINT'}."/schools/".$DevelConf::name_default_school;

    # Working on the sections of sophomorix.ini 
    # part 2 (school-list is known)
    ###############################################
    # if you need process it before reading schools, move it to part 1
    foreach my $section  (keys %{$sophomorix_config{'INI'}}) {
        if ($section eq "SCHOOLS"){
            # do something
        } elsif ($section eq "HOOKS"){
            # do something
        } elsif ($section eq "ROLE_USER"){
            # create LOOKUP for ROLES
            foreach my $keyname (keys %{ $sophomorix_config{'INI'}{'ROLE_USER'} }) {
                $sophomorix_config{'LOOKUP'}{'ROLES_ALL'}{$sophomorix_config{'INI'}{'ROLE_USER'}{$keyname}}=$keyname;
                $sophomorix_config{'LOOKUP'}{'ROLES_USER'}{$sophomorix_config{'INI'}{'ROLE_USER'}{$keyname}}{'KEYNAME'}=$keyname;
            }
        } elsif ($section eq "SYNC_MEMBER"){
            my @keepgroup=&ini_list($sophomorix_config{'INI'}{$section}{'KEEPGROUP'});
	    foreach my $group (@keepgroup) {
                # save in lookup table
                $sophomorix_config{'INI'}{$section}{'KEEPGROUP_LOOKUP'}{$group}="keepgroup";
            }
        } elsif ($section=~m/^computerrole\./){ 
            my ($string,$role)=split(/\./,$section);
            push @{ $sophomorix_config{'LISTS'}{'ROLE_DEVICE'} },$role;
            foreach my $keyname (keys %{$sophomorix_config{'INI'}{$section}}) {
                if ($keyname eq "DEVICE_SHORT"){
                    $sophomorix_config{'LOOKUP'}{'ROLES_ALL'}{$role}=$sophomorix_config{'INI'}{$section}{$keyname};
                    $sophomorix_config{'LOOKUP'}{'ROLES_DEVICE'}{$role}=$sophomorix_config{'INI'}{$section}{$keyname};
                } elsif ($keyname eq "COMPUTER_ACCOUNT"){
                    # ok, no warning
                } elsif ($keyname eq "HOST_GROUP"){
                    # ok, no warning
                } elsif ($keyname eq "HOST_GROUP_TYPE"){
                    my $value=$sophomorix_config{'INI'}{$section}{$keyname};
                    $sophomorix_config{'LOOKUP'}{'HOST_GROUP_TYPE'}{$value}=$role;
                } else {
                    print "WARNING: Do not know what to do with $keyname in section $section\n";
                }
            }
        } elsif ($section=~m/^administrator\./){ 
            # remember in lists
            my ($string,$name)=split(/\./,$section);
	    push @{ $sophomorix_config{'LISTS'}{'SCHOOLADMINISTRATORS'} },$sophomorix_config{'INI'}{$section}{'USER_ROLE'};
	    push @{ $sophomorix_config{'LISTS'}{'ALLADMINS'} },$sophomorix_config{'INI'}{$section}{'USER_ROLE'};
            $sophomorix_config{'LOOKUP'}{'ROLES_ADMINISTRATORS'}{$sophomorix_config{'INI'}{$section}{'USER_ROLE'}}=
                $sophomorix_config{'INI'}{$section}{'USER_SHORT'};
            $sophomorix_config{'LOOKUP'}{'ROLES_ALLADMINS'}{$sophomorix_config{'INI'}{$section}{'USER_ROLE'}}=
                $sophomorix_config{'INI'}{$section}{'USER_SHORT'};
        } elsif ($section=~m/^binduser\./){ 
            my ($string,$name)=split(/\./,$section);
            # remember in lists
	    push @{ $sophomorix_config{'LISTS'}{'BINDUSERS'} },$sophomorix_config{'INI'}{$section}{'USER_ROLE'};
	    push @{ $sophomorix_config{'LISTS'}{'ALLADMINS'} },$sophomorix_config{'INI'}{$section}{'USER_ROLE'};
            $sophomorix_config{'LOOKUP'}{'ROLES_BINDUSERS'}{$sophomorix_config{'INI'}{$section}{'USER_ROLE'}}=
                $sophomorix_config{'INI'}{$section}{'USER_SHORT'};
            $sophomorix_config{'LOOKUP'}{'ROLES_ALLADMINS'}{$sophomorix_config{'INI'}{$section}{'USER_ROLE'}}=
                $sophomorix_config{'INI'}{$section}{'USER_SHORT'};
        } elsif ($section=~m/^classfile\./){
            # doing nothing ?????
        } elsif ($section=~m/^userfile\./ or $section=~m/^devicefile\./){ 
            my ($string,$name,$extension)=split(/\./,$section);
            foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
                my $filename;
                if ($school eq $DevelConf::name_default_school){
                    $filename = $name.".".$extension;
                } else {
                    $filename = $school.".".$name.".".$extension;
                }
                if ($string eq "userfile"){
                    my $file_type="USER_FILE";
                    # role
                    $sophomorix_config{'FILES'}{$file_type}{$filename}{'sophomorixRole'}=
                        $sophomorix_config{'INI'}{$section}{'USER_ROLE'};
                    # type
                    $sophomorix_config{'FILES'}{$file_type}{$filename}{'sophomorixType'}=
                        $sophomorix_config{'INI'}{$section}{'GROUP_TYPE'};
                    # GROUP_OU
#                    $sophomorix_config{'INI'}{$section}{'GROUP_OU'}=
#                        &remove_embracing_whitespace($sophomorix_config{'INI'}{$section}{'GROUP_OU'});
                    $sophomorix_config{'FILES'}{$file_type}{$filename}{'GROUP_OU'}=
                        $sophomorix_config{'INI'}{$section}{'GROUP_OU'};
                    # field5
                    $sophomorix_config{'FILES'}{$file_type}{$filename}{'FIELD_5'}=
                        $sophomorix_config{'INI'}{$section}{'FIELD_5'};
                    # field6
                    $sophomorix_config{'FILES'}{$file_type}{$filename}{'FIELD_6'}=
                        $sophomorix_config{'INI'}{$section}{'FIELD_6'};
                    # force group
                    $sophomorix_config{'FILES'}{$file_type}{$filename}{'FORCE_GROUP'}=
                        $sophomorix_config{'INI'}{$section}{'FORCE_GROUP'};
                    # forced groupname
                    if (defined $sophomorix_config{'INI'}{$section}{'FORCE_GROUPNAME'}){
                        $sophomorix_config{'FILES'}{$file_type}{$filename}{'FORCE_GROUPNAME'}=
                            $sophomorix_config{'INI'}{$section}{'FORCE_GROUPNAME'};
                    } else {
                        $sophomorix_config{'FILES'}{$file_type}{$filename}{'FORCE_GROUPNAME'}="FALSE";
                    }
                    # forbidden groupname
                    if (defined $sophomorix_config{'INI'}{$section}{'FORBIDDEN_GROUP_BASENAME'}){
                        $sophomorix_config{'FILES'}{$file_type}{$filename}{'FORBIDDEN_GROUP_BASENAME'}=
                            $sophomorix_config{'INI'}{$section}{'FORBIDDEN_GROUP_BASENAME'};
                    } else {
                        #$sophomorix_config{'FILES'}{$file_type}{$filename}{'FORBIDDEN_GROUP_BASENAME'}="FALSE";
                    }
                    # MANMEMBEROF
                    my @manmember=&ini_list($sophomorix_config{'INI'}{$section}{'MANMEMBEROF'});
                    foreach my $manmember (@manmember){
                        $manmember=&replace_vars($manmember,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{$file_type}{$filename}{'MANMEMBEROF'} }, $manmember; 
                    }
                    # MEMBEROF
                    my @member=&ini_list($sophomorix_config{'INI'}{$section}{'MEMBEROF'});
                    foreach my $member (@member){
                        $member=&replace_vars($member,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{$file_type}{$filename}{'MEMBEROF'} }, $member; 
                    }
                    # SOPHOMORIXMEMBEROF
                    my @s_member=&ini_list($sophomorix_config{'INI'}{$section}{'SOPHOMORIXMEMBEROF'});
                    foreach my $s_member (@s_member){
                        $s_member=&replace_vars($s_member,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{$file_type}{$filename}{'SOPHOMORIXMEMBEROF'} }, $s_member; 
                    }
                    # MAILDOMAIN_BY_GROUP
		    if (defined $sophomorix_config{'FILES'}{$file_type}{$filename}{'MAILDOMAIN_BY_GROUP'} and
			$sophomorix_config{'FILES'}{$file_type}{$filename}{'MAILDOMAIN_BY_GROUP'} ne ""){
			my @entries=split(/,/,$sophomorix_config{'FILES'}{$file_type}{$filename}{'MAILDOMAIN_BY_GROUP'});
			foreach my $entry (@entries){
			    $entry=~s/ //g;
			    my ($class,$maildomain)=split(/=/,$entry);
			    $sophomorix_config{'FILES'}{$file_type}{$filename}{'MAILDOMAIN_BY_GROUP_LOOKUP'}{$class}=$maildomain;
			}
		    }
                } elsif ($string eq "devicefile"){
                    # role
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'sophomorixRole'}=
                        $sophomorix_config{'INI'}{$section}{'USER_ROLE'};
                    # type
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'sophomorixType'}=
                        $sophomorix_config{'INI'}{$section}{'GROUP_TYPE'};
                    # GROUP_OU
                    $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'GROUP_OU'}=
                        $sophomorix_config{'INI'}{$section}{'GROUP_OU'};
                    # MANMEMBEROF
                    my @manmember=&ini_list($sophomorix_config{'INI'}{$section}{'MANMEMBEROF'});
                    foreach my $manmember (@manmember){
                        $manmember=&replace_vars($manmember,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'MANMEMBEROF'} }, $manmember; 
                    }
                    # MEMBEROF
                    my @member=&ini_list($sophomorix_config{'INI'}{$section}{'MEMBEROF'});
                    foreach my $member (@member){
                        $member=&replace_vars($member,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'MEMBEROF'} }, $member; 
                    }
                    # SOPHOMORIXMEMBEROF
                    my @s_member=&ini_list($sophomorix_config{'INI'}{$section}{'SOPHOMORIXMEMBEROF'});
                    foreach my $s_member (@s_member){
                        $s_member=&replace_vars($s_member,\%sophomorix_config,$school);
                        push @{ $sophomorix_config{'FILES'}{'DEVICE_FILE'}{$filename}{'SOPHOMORIXMEMBEROF'} }, $s_member; 
                    }
                }
            }
        }
    }
    # sort some lits
    @{ $sophomorix_config{'LISTS'}{'ROLE_DEVICE'} } = sort @{ $sophomorix_config{'LISTS'}{'ROLE_DEVICE'} };
  

    # Working on the Lists of sophomorix.ini
    ###############################################
    # GLOBAL
    # OU for Administrators ????
    $sophomorix_config{$DevelConf::AD_global_ou}{ADMINS}{OU}=
        $sophomorix_config{'INI'}{'OU'}{'AD_management_ou'}.",".$sophomorix_config{$DevelConf::AD_global_ou}{OU_TOP};

    # GROUP in section GLOBAL
    foreach my $entry ( &Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'GLOBAL'}{'GROUP'}) ){
        my ($groupname,$grouptype,$sub_ou)=split(/\|/,$entry);
        my $cn_group="CN=".$groupname.",".$sub_ou.",".
            $sophomorix_config{$DevelConf::AD_global_ou}{'OU_TOP'};
        $sophomorix_config{$DevelConf::AD_global_ou}{'GROUP_CN'}{$cn_group}=$groupname;
        $sophomorix_config{$DevelConf::AD_global_ou}{'GROUP_OPTION'}{$groupname}=$cn_group;
        $sophomorix_config{$DevelConf::AD_global_ou}{'GROUP'}{$groupname}=
            $sub_ou.",".
            $sophomorix_config{$DevelConf::AD_global_ou}{'OU_TOP'};
        $sophomorix_config{$DevelConf::AD_global_ou}{'GROUP_TYPE'}{$groupname}=$grouptype;
    }
    # create rolegroup dn's
    foreach my $role (keys %{ $sophomorix_config{'LOOKUP'}{'ROLES_USER'} }) {
        my $rolegroup="role-".$role;
        $sophomorix_config{'LOOKUP'}{'ROLES_USER'}{$role}{'GLOBAL_rolegroup_dn'}=
            $sophomorix_config{$DevelConf::AD_global_ou}{'GROUP_OPTION'}{$rolegroup};
    }

    # GROUP in section SCHOOLS
    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
        $sophomorix_config{'SCHOOLS'}{$school}{'ADMINS'}{OU}=
            $sophomorix_config{'INI'}{'OU'}{'AD_management_ou'}.",".$sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'};
        foreach my $entry ( &Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'SCHOOLS'}{'GROUP'}) ){
            my ($groupname,$grouptype,$sub_ou)=split(/\|/,$entry);
            $groupname=&replace_vars($groupname,\%sophomorix_config,$school);
            my $cn_group="CN=".$groupname.",".$sub_ou.",".
                $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'};
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP_CN'}{$cn_group}=$groupname;
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP_OPTION'}{$groupname}=$cn_group;
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP'}{$groupname}=
                $sub_ou.",".
                $sophomorix_config{'SCHOOLS'}{$school}{'OU_TOP'};
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP_TYPE'}{$groupname}=$grouptype;
        }
    }

    # GROUPMEMBEROF in section GLOBAL
    foreach my $entry ( &Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'GLOBAL'}{'GROUPMEMBEROF'}) ){
        my ($membergroup,$group)=split(/\|/,$entry);
        $sophomorix_config{'GLOBAL'}{'GROUP_MEMBEROF'}{$membergroup}=$group;
    }

    # GROUPMEMBEROF in section SCHOOLS
    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
        foreach my $entry ( &Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'SCHOOLS'}{'GROUPMEMBEROF'}) ){
            my ($membergroup,$group)=split(/\|/,$entry);
            $membergroup=&replace_vars($membergroup,\%sophomorix_config,$school);
            $group=&replace_vars($group,\%sophomorix_config,$school);
            $sophomorix_config{'SCHOOLS'}{$school}{'GROUP_MEMBEROF'}{$membergroup}=$group;
        }
    }

    # create MANAGEMENTGROUPLIST from MANAGEMENTGROUP 
    my @managementgrouplist=&Sophomorix::SophomorixBase::ini_list($sophomorix_config{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUP'});
    $sophomorix_config{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'}=[ \@managementgrouplist ];

    # sorting some lists
    foreach my $school (keys %{$sophomorix_config{'SCHOOLS'}}) {
        @{ $sophomorix_config{'SCHOOLS'}{$school}{'FILELIST'} } = 
            sort @{ $sophomorix_config{'SCHOOLS'}{$school}{'FILELIST'} };
    }

    if ($#{ $sophomorix_config{'LISTS'}{'SCHOOLS'} }>0 ){
        @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} } = sort @{ $sophomorix_config{'LISTS'}{'SCHOOLS'} };
    }
    if ($#{ $sophomorix_config{'LISTS'}{'SCHOOLADMINISTRATORS'} }>0 ){
        @{ $sophomorix_config{'LISTS'}{'SCHOOLADMINISTRATORS'} } = sort @{ $sophomorix_config{'LISTS'}{'SCHOOLADMINISTRATORS'} };
    }
    if ($#{ $sophomorix_config{'LISTS'}{'BINDUSERS'} }>0 ){
        @{ $sophomorix_config{'LISTS'}{'BINDUSERS'} } = sort @{ $sophomorix_config{'LISTS'}{'BINDUSERS'} };
    }
    if ($#{ $sophomorix_config{'LISTS'}{'ALLADMINS'} }>0 ){
        @{ $sophomorix_config{'LISTS'}{'ALLADMINS'} } = sort @{ $sophomorix_config{'LISTS'}{'ALLADMINS'} };
    }
    return %sophomorix_config; 
}


 
sub replace_vars {
    my ($string,$ref_sophomorix_config,$school)=@_;
    my $replacement=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'PREFIX'};
    $string=~s/\@\@SCHOOLPREFIX\@\@/$replacement/g; 
#    $string=~s/\@\@SCHOOLNAME\@\@/$school/g; 
    $string=~s/\@\@SCHOOLNAME\@\@/$ref_sophomorix_config->{'INI'}{'VARS'}{'SCHOOLGROUP_PREFIX'}$school/g; 
    return $string;
}



sub read_smb_conf {
    my ($ref_sophomorix_config,$ref_result)=@_;
    &print_title("Reading $DevelConf::smb_conf","slim");
    if (not -e $DevelConf::smb_conf){
        print "\nERROR: $DevelConf::smb_conf not found!\n\n";
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$DevelConf::smb_conf." not found!");
        return;
    }
    tie %{ $ref_sophomorix_config->{'samba'}{'smb.conf'} }, 'Config::IniFiles',
        ( -file => $DevelConf::smb_conf, 
          -handle_trailing_comment => 1,
        );
    # add some calculated stuff
    # Domain DNS: i.e. DC=linuxmuster,DC=local or DC=LINUXMUSTER,DC=LOCAL
    my $domain=$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'realm'};
    $domain=~tr/A-Z/a-z/; # make lowercase
    my @dns=split(/\./,$domain);
    my $domain_dns = join(',DC=', @dns);
    $domain_dns="DC=".$domain_dns;
    my $server_dns=$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'netbios name'};
    $server_dns=~tr/A-Z/a-z/; # make lowercase
    $ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'DomainDNS'}=$domain_dns;
    $ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}=$server_dns;
}



sub read_ui {
    my ($ref_sophomorix_config,$ref_result)=@_;
    my $file=$ref_sophomorix_config->{'INI'}{'WEBUI'}{'INI'};
    &print_title("Reading $file","slim");
    if (-f $file){
        tie %{ $ref_sophomorix_config->{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS'} }, 'Config::IniFiles',
            ( -file => $file, 
              -handle_trailing_comment => 1,
            );
    } else {
        print "\n";
        print "ERROR: UI config file not found:\n";
        print "       $file\n";
        print "\n";
        exit;
    }

    # Test config file for double module paths
    foreach my $role (keys %{ $ref_sophomorix_config->{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS'} }) {
        my %seen=();
        my @perms=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS'}{$role}{'WEBUI_PERMISSIONS'});
        foreach my $perm (@perms){
            my ($mod_path,$setting)=&test_webui_permission($perm,$ref_sophomorix_config,$file,"none","","");
            if (exists $seen{$mod_path}){
                print "\nERROR: Module path $mod_path double in role $role\n\n";
                exit 88;
            } else {
                $ref_sophomorix_config->{'UI'}{'CONFIG'}{'WEBUI_PERMISSIONS_LOOKUP'}{$role}{$mod_path}=$setting;
                $seen{$mod_path}="seen";
            }
 
            # fill LOOKUP
            $ref_sophomorix_config->{'UI'}{'LOOKUP'}{'MODULES'}{$role}{$mod_path}="OK";
            $ref_sophomorix_config->{'UI'}{'LOOKUP'}{'MODULES'}{'ALL'}{$mod_path}="OK";
        }
    }
}



sub test_webui_permission {
    my ($perm,$ref_sophomorix_config,$file,$mode,$school,$role)=@_;
    $perm=~s/\s+$//g;# remove trailing whitespace
    my $mod_path=$perm;
    my $setting;
    if ($perm=~m/true$/){
        $mod_path=~s/true$//g;# remove true
        $setting="true";
    } elsif ($perm=~m/false$/){
        $mod_path=~s/false$//g;# remove false
        $setting="false";
    } else {
        print "\n";
        print "ERROR in $file:\n";
        print "   WEBUI_PERMISSIONS=$perm (neither false nor true at the end!\n\n";
        exit 88;
    }
    $mod_path=~s/\s+$//g;# remove trailing whitespace

    # do some more checks
    if ($mode eq "override"){
        # check if modpath is valid
        if (not exists $ref_sophomorix_config->{'UI'}{'LOOKUP'}{'MODULES'}{'ALL'}{$mod_path}){
            print "\n";
	    print "ERROR in $file:\n";
            print "    WEBUI_PERMISSIONS: <$mod_path> is not a valid module name\n\n";
            exit 88;
        }

        if (exists $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'}{$mod_path}){
            # override the school value
            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'}{$mod_path}=$setting;
	} else {
            print "\n";
	    print "ERROR in $file:\n";
            print "    WEBUI_PERMISSIONS: <$mod_path> not allowed in user role $role\n\n";
            exit 88;
	}
    } elsif ($mode eq "check"){
        # check if modpath is valid
        if (not exists $ref_sophomorix_config->{'UI'}{'LOOKUP'}{'MODULES'}{'ALL'}{$mod_path}){
            print "\n";
	    print "ERROR in $file:\n";
            print "    WEBUI_PERMISSIONS: <$mod_path> is not a valid module name\n\n";
            exit 88;
        }

        if (not exists $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'}{$mod_path}){
            print "\n";
	    print "ERROR in $file:\n";
            print "    <$mod_path> cannot be configured for a user with role $role\n\n";
            exit 88;
        }
    }
    return($mod_path,$setting);
}



sub read_sophomorix_ini {
    my ($ref_sophomorix_config,$ref_result)=@_;
    &print_title("Reading $DevelConf::sophomorix_ini","slim");
    if (not -e $DevelConf::sophomorix_ini){
        print "\nERROR: $DevelConf::sophomorix_ini not found!\n\n";
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$DevelConf::sophomorix_ini." not found!");
        return;
    }
    tie %{ $ref_sophomorix_config->{'INI'} }, 'Config::IniFiles',
        ( -file => $DevelConf::sophomorix_ini, 
          -handle_trailing_comment => 1,
        );
}



sub read_lsbrelease {
    my ($ref_sophomorix_config,$ref_result)=@_;
    open(LSB_RELEASE,"<$ref_sophomorix_config->{'INI'}{'LINUX'}{'LSB_RELEASE'}") || 
        die "Cannot find $ref_sophomorix_config->{'INI'}{'LINUX'}{'LSB_RELEASE'}\n";
    while (<LSB_RELEASE>){
        chomp();
        my ($key,$value)=split(/=/);
        $ref_sophomorix_config->{'linux'}{'lsb-release'}{$key}=$value;
    }
    close(LSB_RELEASE);
    $allowed_distrib_id=$ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_ID'};
    $distrib_id=$ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_ID'};
    $release=$ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_RELEASE'};
    if ($distrib_id ne $allowed_distrib_id){
	print "ERROR: sophomorix is best run on $allowed_distrib_id (You are using: $distrib_id)\n";
        exit 88;
    }
    if ($release==$ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_STABLE'} or
        $release==$ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_UPCOMING'} or
        $release==$ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_EXPERIMENTAL'}){
        &print_title("Distro-check: $distrib_id $release is OK","slim");

    } else {
	print "ERROR: sophomorix runs only on certain $allowed_distrib_id distributions:\n";
	print "       $ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_STABLE'} (STABLE)\n";
	print "       $ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_UPCOMING'} (UPCOMING)\n";
	print "       $ref_sophomorix_config->{'INI'}{'LINUX'}{'DISTRIB_EXPERIMENTAL'} (EXPERIMENTAL)\n";
        print "You have $distrib_id $release\n";
        exit 88;
    }
}



sub ini_list {
    my ($ref)=@_;
    # returns empty list if parameter not given
    if (not defined $ref){
        my @list=();
        return @list;
    }
    
    # returns one element list if parameter is key->value
    if ($#{ $ref }==-1 ){
        my @list=($ref);
        return @list;
    }

    # returns multi element list if parameter is specified multiple times
    return @{ $ref };

    # example code
    #my @list=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.global'}{'MEMBERSHIP'});
    #    foreach my $item (@list){
    #        print "ITEM: $item\n";
    #    }
}



sub read_smb_net_conf_list {
    my ($ref_sophomorix_config,$ref_result)=@_;
    &print_title("Parsing: net conf list");
    my ($fh, $tmpfile) = tempfile( DIR => "/tmp" );
    system("net conf list > $tmpfile");
    tie %{ $ref_sophomorix_config->{'samba'}{'net_conf_list'} }, 'Config::IniFiles',
        ( -file => $tmpfile, 
          -handle_trailing_comment => 1,
        );
    system("rm $tmpfile");
    # create sharelist
    foreach my $share (keys %{ $ref_sophomorix_config->{'samba'}{'net_conf_list'} }) {
        push @{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} }, $share; 
    }
    if ($#{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} } >0){
        @{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} }= sort @{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} };
    }
}



sub read_smb_domain_passwordsettings {
    my ($ref_sophomorix_config,$smb_admin_pass,$ref_result)=@_;
    &print_title("Asking domain passwordsettings from samba");
    my $string=`samba-tool domain passwordsettings show --password='$smb_admin_pass' -U $DevelConf::sophomorix_AD_admin`;
    my @lines=split(/\n/,$string);
    foreach my $line (@lines){
        my ($key,$value)=split(/:/,$line);
        if (defined $value){
            $key=&remove_embracing_whitespace($key);
            $key=~s/\)//g;
            $key=~s/\(//g;
            $key=~s/ /_/g;
            $value=&remove_embracing_whitespace($value);
            if($Conf::log_level>=3){
                print "   * <$key> ---> <$value>\n";
            }
            $ref_sophomorix_config->{'samba'}{'domain_passwordsettings'}{$key}=$value;
        }
    }
}



sub read_master_ini {
    my ($masterfile,$ref_result)=@_;
    my %master=();
    if($Conf::log_level>=2){
        &print_title("Reading $masterfile","slim");
    }
    if (not -e $masterfile){
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$masterfile." not found!");
        return;
        #print "\nERROR: $masterfile not found!\n\n";
        #exit;
    }
    tie %master, 'Config::IniFiles',
        ( -file => $masterfile, 
          -handle_trailing_comment => 1,
        );
    return \%master;
}



sub check_config_ini {
    my ($ref_school,$configfile,$ref_result,$ref_sophomorix_config)=@_;
    # take the master reference as school reference and overwrite it
    &print_title("Reading $configfile","slim");
    if (not -e $configfile){
        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$configfile." not found!");
        print "\nERROR: $configfile not found!\n\n";
        exit 88;
    }
    #print "Checking file $configfile\n";
    tie %config, 'Config::IniFiles',
        ( -file => $configfile, 
          -handle_trailing_comment => 1,
        );
    # walk through all settings in the fonfig
    foreach my $section ( keys %config ) {
        foreach my $parameter ( keys %{$config{$section}} ) {
            #print "Verifying if parameter $parameter is valid in section $section\n";
            if (exists $ref_school->{$section}{$parameter}){
                #print "parameter $section -> $parameter is valid OK\n";
                #print "  Master Value: $section = $ref_school->{$section}{$parameter}\n";
                #print "  $configfile: $section = $config{$section}{$parameter}\n";
                if ($ref_school->{$section}{$parameter}=~m/\|/){
                    # value syntax is <type>|<default>
                    my ($opt_type,$opt_default)=split(/\|/,$ref_school->{$section}{$parameter});
                    #print "$section is of type $opt_type, default is $opt_default\n";
                    if ($opt_type eq "BOOLEAN" or
			($parameter eq "RANDOM_PWD" and $config{$section}{$parameter} !~ m/^birthdate$|^dice$/)
		       ){
                        # value in master is BOOLEAN|<default>
                        my $opt_given=$config{$section}{$parameter};
                        $opt_given=~tr/A-Z/a-z/; # make lowercase
                        # overwrite  $ref_school
                        if ($opt_given eq "yes" or
                            $opt_given eq "on" or
                            $opt_given eq "true" or
                            $opt_given eq "1"
                           ){
                            $ref_school->{$section}{$parameter}=$ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_TRUE'};
                        } elsif ($opt_given eq "no" or
                                 $opt_given eq "off" or
                                 $opt_given eq "false" or
                                 $opt_given eq "0"
                                ){
                            $ref_school->{$section}{$parameter}=$ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_FALSE'};
                        }
		    } elsif ($parameter eq "RANDOM_PWD" and $config{$section}{$parameter} =~ m/^birthdate$|^dice$/) {
                        $ref_school->{$section}{$parameter}=$config{$section}{$parameter};
		    }
                } else {
                    # overwrite  $ref_school
                    $ref_school->{$section}{$parameter}=$config{$section}{$parameter};
                }

            } else {
		#print " * ERROR: ".$parameter." is NOT valid in section ".$section."\n";
                &result_sophomorix_add($ref_result,
                                       "ERROR",-1,
                                       $ref_parameter,
                                       $parameter.
                                       " is NOT valid in section ".
                                       $section.
                                       " of ".
                                       $configfile.
                                       "!");
                print "   * WARNING: $parameter is NOT valid in section $section\n";
            }
        }
    }

    # go through school config again. Set defaults from master
    foreach my $section ( keys %{ $ref_school } ) {
        foreach my $parameter ( keys %{ $ref_school->{$section} } ) {
            if ($ref_school->{$section}{$parameter}=~m/\|/){
                my ($opt_type,$opt_default)=split(/\|/,$ref_school->{$section}{$parameter});
                if ($opt_default eq "TRUE"){
                    $ref_school->{$section}{$parameter}=$ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_TRUE'};
                } elsif ($opt_default eq "FALSE"){
                    $ref_school->{$section}{$parameter}=$ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_FALSE'};
                }
            }
        }
    }
    return $ref_school;
}




sub load_school_ini {
    my ($root_dse,$school,$conf_school,$ref_modmaster,$ref_sophomorix_config,$ref_result)=@_;
    my $root_dns=&Sophomorix::SophomorixSambaAD::AD_dns_get($root_dse);
    foreach my $section ( keys %{ $ref_modmaster } ) {
	if ($section eq "school"){
            ##### school section ########################################################################
            # walk through parameters
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * SCHOOL $school: Para: $parameter -> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
                $ref_sophomorix_config->{'SCHOOLS'}{$school}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
            }
                # add more stuff
                foreach my $member ( @DevelConf::AD_schools_group_members ){
                    my ($group)=&Sophomorix::SophomorixSambaAD::AD_get_name_tokened($member,$school,"group");
                    push @{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'SCHOOLGROUP_MEMBERGROUPS'} }, $group;
                }
	} elsif ($section=~m/^classfile\./){
            # doing nothing ?????
	} elsif ($section=~m/^userfile\./ or $section=~m/^devicefile\./){ 
            ##### file.* section ########################################################################
	    my ($string,$name,$extension)=split(/\./,$section);
            my $filename;
            my $file_basename;
            my $prefix;
            my $postfix;
            my $ou_top;
            # calculate some things
            if ($school eq $DevelConf::name_default_school){
                $filename=$name.".".$extension;
                $prefix="";
                $postfix="";
                $ou_top=$ref_sophomorix_config->{'SCHOOLS'}{$DevelConf::name_default_school}{OU_TOP};
            } else {
                $filename=$school.".".$name.".".$extension;
                $prefix=$school."-";
                $postfix="-".$school;
                $ou_top=$ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP};
            }
            # # load parameters
            # foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
            #     if($Conf::log_level>=3){
            #         print "   * FILE $filename: $parameter ---> <".
            #               $ref_modmaster->{$section}{$parameter}.">\n";
            #     }
            #     $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{$parameter}=
            #         $ref_modmaster->{$section}{$parameter};
            # }

            if ($string eq "userfile"){
                my $file_type="USER_FILE";
                # load parameters
                foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                    if($Conf::log_level>=3){
                        print "   * FILE $filename: $parameter ---> <".
                              $ref_modmaster->{$section}{$parameter}.">\n";
                    }
                    $ref_sophomorix_config->{'FILES'}{$file_type}{$filename}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
                }

                # add some redundant stuff for convenience
                $ref_sophomorix_config->{'FILES'}{$file_type}{$filename}{'PATH_ABS_UTF8'}=
                    $DevelConf::path_conf_tmp."/".$filename.".utf8";
                $ref_sophomorix_config->{'FILES'}{$file_type}{$filename}{'PATH_ABS_REPORT_OFFICE'}=
                    $ref_sophomorix_config->{'INI'}{'PATHS'}{'REPORT_OFFICE'}."/report.office.".$filename;
                # save unchecked filter script for error messages
                $ref_sophomorix_config->{'FILES'}{$file_type}{$filename}{FILTERSCRIPT_CONFIGURED}=
                    $ref_sophomorix_config->{'FILES'}{$file_type}{$filename}{FILTERSCRIPT};
            }

            if ($name eq "students"){
                if (defined $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{CLASSNAME_MAP} and
		    $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{CLASSNAME_MAP} ne ""){
		    @classname_map=split(/,/,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{CLASSNAME_MAP});
		    foreach my $map (@classname_map){
			($old_classname,$new_classname)=split(/=/,$map);
			$old_classname=&remove_embracing_whitespace($old_classname);
			$new_classname=&remove_embracing_whitespace($new_classname);
			$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{CLASSNAME_MAP_KEY_VALUE}{$old_classname}=
			    $new_classname;
		    }
		}
	    }

            if ($name eq "students" or
                $name eq "parents" or
                $name eq "staff" or
                $name eq "extrastudents"or
                $name eq "teachers"
		){
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'SCHOOL'}=$school;
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'OU_TOP'}=$ou_top;
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'FILETYPE'}="users";
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'PREFIX'}=$prefix;
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'POSTFIX'}=$postfix;
                my $path_abs=$DevelConf::path_conf_sophomorix."/".$school."/".$filename;
                $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'PATH_ABS'}=$path_abs;
                push @{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'FILELIST'} },$path_abs;
            } elsif ($name eq "devices"){
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'FILETYPE'}="devices";
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'SCHOOL'}=$school;
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'OU_TOP'}=$ou_top;
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'PREFIX'}=$prefix;
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'POSTFIX'}=$postfix;
                my $path_abs=$DevelConf::path_conf_sophomorix."/".$school."/".$filename;
                $ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'PATH_ABS'}=$path_abs;
                push @{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'FILELIST'} },$path_abs;
            }

            # test filterscript for userfiles
            if ($string eq "userfile"){
                if (defined $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT}){
                    # save unchecked filter script for error messages
                    $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT_CONFIGURED}=
                        $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT};
	            my $filter_script=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT};
                    if ($filter_script eq "---"){
                        #$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT}=$filter_script;
 	            } else {
                        # test if first part of configured value is a file and executable
                        my ($executable,@options)=split(/ +/,$filter_script);
                        if (-f $executable and -x $executable and $executable=~m/^\//){
                            # first part of configured value is a file and executable
                            $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT}=$filter_script;
                        } else {
                            $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{FILTERSCRIPT}="ERROR_FILTERSCRIPT";
                            &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,
                                "FILTERSCRIPT=".$filter_script." -> FILTERSCRIPT must be an absolute path to an executable script");
                        }
			#exit;
                    }
                }
                # test encoding
                if (defined $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING}){
                    my $enc=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING};
                    if (exists $ref_sophomorix_config->{'ENCODINGS'}{$enc} or 
                        $enc eq "auto"){
                    } else {
                        $ref_sophomorix_config{'FILES'}{'USER_FILE'}{$filename}{ENCODING}="ERROR_ENCODING";
                        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,
                              "ENCODING ".$enc." not listed by 'iconv --list' and not 'auto'");
                    }
                }
                # test if encoding force is yes/no
                if (defined $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE}){
                    if($ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE} eq 
                        $ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_TRUE'} or
                        $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE} eq 
                        $ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_FALSE'} 
                      ){
                        # OK
                    } else {
                        &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,
                            "ENCODING_FORCE=".
                            $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{ENCODING_FORCE}.
                            " -> ENCODING_FORCE accepts only 'True' or 'False'");
                    }
                }
            }
	} elsif ($section=~m/^classfile\./){ 
            # doing nothing ????
	} elsif ($section=~m/^role\./){ 
            ##### role.* section ########################################################################
	    my ($string,$name)=split(/\./,$section);
	    my $role=$name; # student, ...
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * ROLE $role: $parameter ---> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
#                $ref_sophomorix_config->{'ROLES'}{$school}{$role}{$parameter}=
#                    $ref_modmaster->{$section}{$parameter};
                if ($parameter eq "WEBUI_PERMISSIONS"){
                    # override WEBUI_PERMISSIONS ##############################
                    my @perms=split(/,/,$ref_modmaster->{$section}{$parameter});
                    # override value in 
                    foreach my $perm (@perms){
                        my ($mod_path,$setting)=&test_webui_permission($perm,
                                                                       $ref_sophomorix_config,
                                                                       $conf_school,
                                                                       "override",
                                                                       $school,
                                                                       $role);
		    }
                } elsif ($parameter eq "MAILDOMAIN"){
                    if ($ref_modmaster->{$section}{$parameter} eq ""){
                        $ref_sophomorix_config->{'ROLES'}{$school}{$role}{$parameter}=$root_dns;
		    } else {
                        $ref_sophomorix_config->{'ROLES'}{$school}{$role}{$parameter}=
                            $ref_modmaster->{$section}{$parameter};
                    }
                } elsif ($parameter eq "MAIL_LOCAL_PART_MAP"){
		    if ($ref_modmaster->{$section}{$parameter} ne ""){
                        my (@values)=split(/,/,$ref_modmaster->{$section}{$parameter});
  		        foreach my $value (@values){
			    my ($sam,$mail_local_part_new)=split(/=/,$value);
			    $sam=&remove_embracing_whitespace($sam);
			    $mail_local_part_new=&remove_embracing_whitespace($mail_local_part_new);
                            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_MAP_LOOKUP'}{$sam}{'MAIL_LOCAL_PART'}=
                                $mail_local_part_new;
                            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_MAP_LOOKUP'}{$sam}{'USED'}="FALSE";
   		        }
		    }
                } else {
                    $ref_sophomorix_config->{'ROLES'}{$school}{$role}{$parameter}=
                        $ref_modmaster->{$section}{$parameter};
                }
            }
	} elsif ($section=~m/^type\./){ 
            ##### type.* section ########################################################################
	    my ($string,$name)=split(/\./,$section);
            my $typename;
            if ($school eq $DevelConf::name_default_school){
                $typename=$name;
            } else {
                $typename=$school."-".$name;
            }
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * TYPE $typename: $parameter ---> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
                $ref_sophomorix_config->{'TYPES'}{$typename}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
            }
	} elsif ($section=~m/^managementgroup\./){ 
            ##### managementgroup.* section ########################################################################
	    my ($string,$name)=split(/\./,$section);
            my $managementgroupname;
            if ($school eq $DevelConf::name_default_school){
                $managementgroupname=$name;
            } else {
                $managementgroupname=$school."-".$name;
            }
            foreach my $parameter ( keys %{ $ref_modmaster->{$section}} ) {
                if($Conf::log_level>=3){
                    print "   * MANAGEMENTGROUP $managementgroupname: $parameter ---> <".
                          $ref_modmaster->{$section}{$parameter}.">\n";
                }
                $ref_sophomorix_config->{'MANAGEMENTGROUPS'}{$managementgroupname}{$parameter}=
                    $ref_modmaster->{$section}{$parameter};
            }
        } else {
            ##### unnown section ########################################################################
            &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,
                "Section ".$section." -> unknown, not processed");
            #print "ERROR: Section $section: unknown, not processed\n\n";
            #exit 88;
        }
    }
    # create ui lists from UI_LOOKUP to UI
    foreach my $ui_role (keys %{ $ref_sophomorix_config->{'ROLES'}{$school} }){
        foreach my $mod (keys %{ $ref_sophomorix_config->{'ROLES'}{$school}{$ui_role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'} }){
           push @{ $ref_sophomorix_config->{'ROLES'}{$school}{$ui_role}{'UI'}{'WEBUI_PERMISSIONS'} },
               $mod." ".$ref_sophomorix_config->{'ROLES'}{$school}{$ui_role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'}{$mod};
        }
        # sort
	if ($#{ $ref_sophomorix_config->{'ROLES'}{$school}{$ui_role}{'UI'}{'WEBUI_PERMISSIONS'}  }>0 ){
            @{ $ref_sophomorix_config->{'ROLES'}{$school}{$ui_role}{'UI'}{'WEBUI_PERMISSIONS'} } = 
                sort @{ $ref_sophomorix_config->{'ROLES'}{$school}{$ui_role}{'UI'}{'WEBUI_PERMISSIONS'} };
	}
    }
}



sub load_sophomorix_ini {
    my ($ref_modmaster_sophomorix,$ref_sophomorix_config,$ref_result)=@_;
    foreach my $section ( keys %{ $ref_modmaster_sophomorix } ) {
        if ($section eq "global"){
            foreach my $parameter ( keys %{ $ref_modmaster_sophomorix->{$section}} ) {
                if ($Conf::log_level>=3){
                    print "   * $section: $parameter ---> <".
                          $ref_modmaster_sophomorix->{$section}{$parameter}.">\n";
                }
                if ($parameter eq "SCHOOLS"){
		    my @schools=split(/,/,$ref_modmaster_sophomorix->{$section}{$parameter});
                    foreach my $school (@schools){
                        if ($school eq $DevelConf::name_default_school){
                            # ignore this, already configured
                            next;
                        }
                        $school=&remove_embracing_whitespace($school);
                        push @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} }, $school; 
                        $ref_sophomorix_config->{'SCHOOLS'}{$school}{'CONF_FILE'}=
                            $DevelConf::path_conf_sophomorix."/".$school."/".$school.".school.conf";
                        $ref_sophomorix_config->{'SCHOOLS'}{$school}{'TEMPLATES_LATEX_DIR'}=
                            $DevelConf::path_conf_sophomorix."/".$school."/".
                            $ref_sophomorix_config->{'INI'}{'LATEX'}{'TEMPLATES_CUSTOM_SUBDIR'};
                    }
                } else {
                    $ref_sophomorix_config->{$DevelConf::AD_global_ou}{$parameter}=
                        $ref_modmaster_sophomorix->{$section}{$parameter};
                }
            }
        } else {
            ##### unnown section ########################################################################
            &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,"Section ".$section.": unknown, not processed");
            return;
            #print "ERROR: Section $section: unknown, not processed\n\n";
            #exit 88;
        }
    }
}



# working with the JSON result hash
######################################################################
sub result_sophomorix_init {
    my ($scriptname)=@_;
    my %sophomorix_result=();
    $sophomorix_result{'SCRIPTNAME'}=$scriptname;
    $sophomorix_result{'JSONINFO'}="RESULT";
    $sophomorix_result{'JSONCOMMENT'}="---";
    @{ $sophomorix_result{'OUTPUT'} }=();
    return %sophomorix_result; 
}



sub result_sophomorix_add {
    # $type: ERROR|WARNUNG
    # $num: -1, no number, else look in ERROR|WARNING db
    # $ref_parameter: list of parameters to be fitted in db string
    # $message: used if errnumber is not found in db
    my ($ref_result,
        $type, # ERROR OR WARNING
        $num,  # error number (for lookup), -1: dont search
        $ref_parameter,
        $message)=@_;

#    print "LIST of parameters:\n";
#    foreach my $para ( @{ $ref_parameter}  ){ 
#        print "$para\n";
#    } 
    if ($type eq "ERROR" or $type eq "WARNING" ){
        # get error from db, update $message_de, $message_en
        push @{ $ref_result->{'OUTPUT'} }, 
            {TYPE       => $type, 
             NUMBER     => $num,
             MESSAGE_EN => $message,
             MESSAGE_DE => $message,
             #ARGUMENTS => $ref_parameter,
            };
    } else {
        push @{ $ref_result->{'OUTPUT'} }, 
            {TYPE           => "UNKNOWN", 
             INTERNAL_ERROR => "unknown type ".$type."in  result_sophomorix_add",
            };
        print "Unknown result type $type";
    }
}



sub result_sophomorix_add_log {
    # $type: ERROR|WARNUNG
    # $num: -1, no number, else look in ERROR|WARNING db
    # $ref_parameter: list of parameters to be fitted in db string
    # $message: used if errnumber is not found in db
    my ($ref_result,$log_message) = @_;
    my %out_hash=();
    $out_hash{'TYPE'}="LOG";
    $out_hash{'LOG'}=$log_message;
    push @{ $ref_result->{'OUTPUT'} },{%out_hash};

#    push @{ $ref_result->{'OUTPUT'} }, 
#        {TYPE => "LOG", 
#         LOG  => $log_message
#        };
}


sub result_sophomorix_add_summary {
 my ($arg_ref) = @_;
    my $ref_result = $arg_ref->{sophomorix_result};
    my $name = $arg_ref->{NAME};
    my $title = $arg_ref->{TITLE};
    my $result = $arg_ref->{RESULT};
    my $result_type = $arg_ref->{RESULT_TYPE};
    my $description_pre  = $arg_ref->{DESCRIPTION_PRE};
    my $description_post = $arg_ref->{DESCRIPTION_POST};
    my $format_type = $arg_ref->{FORMAT_TYPE};
    my $file = $arg_ref->{FILE};
    my $encoding = $arg_ref->{ENCODING};

    if ($name eq "HEADER"){
        my %header = (TITLE => $title);
        push @{ $ref_result->{'SUMMARY'} }, {$name => \%header};
    } else {
        my %hash=();
        if (defined $result){
            $hash{'RESULT'}=$result;
        }
        if (defined $result_type){
            $hash{'RESULT_TYPE'}=$result_type;
        }
        if (defined $description_pre){
            $hash{'DESCRIPTION_PRE'}=$description_pre;
        }
        if (defined $description_post){
            $hash{'DESCRIPTION_POST'}=$description_post;
        }
        if (defined $format_type){
            $hash{'FORMAT_TYPE'}=$format_type;
        }
        if (defined $file){
            $hash{'FILE'}=$file;
        }
        if (defined $encoding){
            $hash{'ENCODING'}=$encoding;
        }
        push @{ $ref_result->{'SUMMARY'} }, {$name => \%hash};
    }
}



sub result_sophomorix_check_exit {
    my ($ref_result,$ref_sophomorix_config,$json)=@_;
    my $log=0;
    my $warn=0;
    my $err=0;
    # count results
    foreach my $line ( @{ $ref_result->{'OUTPUT'}}  ){
	#print "$line\n";
        if ($line->{'TYPE'} eq "ERROR"){
            $err++;
        } elsif ($line->{'TYPE'} eq "WARNING"){
            $warn++;
        } elsif ($line->{'TYPE'} eq "LOG"){
            $log++;
        } else {

        }
    } 
    # check if i need to exit
    if ($err>0 or $warn>0){
        $ref_result->{'JSONCOMMENT'}="Configuration check failed";
        &result_sophomorix_print($ref_result,$ref_sophomorix_config,$json);
        exit;
    } else {
        &print_title("$err ERRORS, $warn WARNINGS -> let's go");
    }
}



sub result_sophomorix_print {
    my ($ref_result,$ref_sophomorix_config,$json)=@_;
      if ($json==0){
          # be quiet
          print "Calling console printout\n";
          # print OUTPUT
          foreach my $line ( @{ $ref_result->{'OUTPUT'}}  ){
              if ($line->{'TYPE'} eq "LOG"){
	          printf "%-7s%3s: %-65s \n",$line->{'TYPE'},"",$line->{'LOG'};
              } else {
	          printf "%-7s%3s: %-65s \n",$line->{'TYPE'},$line->{'NUMBER'},$line->{'MESSAGE_EN'};
              }
          } 
          # print RESULT
          foreach my $line ( @{ $ref_result->{'SUMMARY'}}  ){
              foreach my $name ( keys %{ $line } ) {
		  #print "Name: $name\n";
                  if ($name eq "HEADER"){
                      print "##### ".$line->{$name}{'TITLE'}."\n";
                  } elsif ($line->{$name}{'FORMAT_TYPE'}==0){ # just print RESULT
                      #print "Format 0\n";
                      print "RESULT    : ".$line->{$name}{'RESULT'}."\n";
                  } elsif ($line->{$name}{'FORMAT_TYPE'}==1){
                      #print "Format 1\n";
                      printf "%6s %-65s \n",$line->{$name}{'RESULT'},$line->{$name}{'DESCRIPTION_POST'};
                  } elsif ($line->{$name}{'FORMAT_TYPE'}==2){
                      #print "Format 2\n";
                      print $line->{$name}{'DESCRIPTION_PRE'}.": ".$line->{$name}{'RESULT'}."\n";
	          } else {
                      print "Format unknown\n";
                  }
              }
          }
      } elsif ($json==1){
          # pretty output
          my $json_obj = JSON->new->allow_nonref;
          my $utf8_pretty_printed = $json_obj->pretty->encode( $ref_result );
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} "# JSON-begin\n";
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} "$utf8_pretty_printed\n";
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} "# JSON-end\n";
      } elsif ($json==2){
          # compact output
          my $json_obj = JSON->new->allow_nonref;
          my $utf8_json_line   = $json_obj->encode( $ref_result  );
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} "# JSON-begin\n";
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} "$utf8_json_line\n";
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} "# JSON-end\n";
      } elsif ($json==3){
          &print_title("DUMP: ".$ref_result->{'JSONCOMMENT'});
          print {$ref_sophomorix_config->{'INI'}{'VARS'}{'JSON_RESULT'}} Dumper( $ref_result );
      }
}



# other
######################################################################

sub filelist_fetch {
    # listing existing files of the given FILETYPE
    my ($arg_ref) = @_;
    my $filetype = $arg_ref->{filetype};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $file_type;

    if ($filetype eq "devices"){
	$file_type="DEVICE_FILE";
    } elsif ($filetype eq "users"){
	$file_type="USER_FILE";
    } else {
        print "ERROR: unknown filetype $filetype\n";
        exit 88;
    }

    my @filelist=();
    if($Conf::log_level>=2){
        &print_title("Testing the following files for handling:");
    }
    foreach my $file (keys %{$ref_sophomorix_config->{'FILES'}{$file_type}}) {
        my $abs_path=$ref_sophomorix_config->{'FILES'}{$file_type}{$file}{'PATH_ABS'};
        my $filetype_real=$ref_sophomorix_config->{'FILES'}{$file_type}{$file}{'FILETYPE'};
        if (not defined $abs_path){next}; # i.e. vampire.csvFILES
        
        if (-e $abs_path and $filetype_real eq $filetype){
            push @filelist, $abs_path;
            if($Conf::log_level>=2){
                print "  ** $abs_path (existing)\n";
            }
        } else {
            if($Conf::log_level>=2){
                if (not -e $abs_path){
                    print "   - $abs_path (nonexisting)\n";
                } elsif ($filetype_real ne $filetype){
                    print "   + $abs_path (existing but wrong filetype)\n";
                }
            }
        }
    }
    @filelist = sort @filelist;
    return @filelist;
}



sub rewrite_smb_path {
    my ($smb_dir,$ref_sophomorix_config)=@_;
    $smb_dir_new=$smb_dir; 
    my ($dnsdomain,$school,@path)=split(/\//,$smb_dir_new);
    if ($ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'FILESYSSMBCLIENT_SERVER_FIX'} eq "TRUE"){
        if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}{'msdfs root'} and
            exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}{'msdfs proxy'} ){
            if ($ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}{'msdfs root'} eq "yes"){
                $server_share=$ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}{'msdfs proxy'};
                print "OLD: $smb_dir_new\n";
                $smb_dir_new=~s/smb:\/\///g;

                $server_share=~s/^\\//g;# remove leading \
                $server_share=~s/^\///g;# remove leading /
                $server_share=~s/\\/\//g;# convert \ to /

                $smb_dir_new=join("/",$server_share,@path);
                $smb_dir_new="smb://".$smb_dir_new;
                print "NEW: $smb_dir_new\n";
            }
        }
    }
    return $smb_dir_new;
}



sub smbclient_dirlist {
    my ($arg_ref) = @_;
    my $share = $arg_ref->{sharename};
    my $share_subdir = $arg_ref->{share_subdir};
    my $home_dir = $arg_ref->{home_dir};
    my $home_subdir = $arg_ref->{home_subdir};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $sam = $arg_ref->{user};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    # we need for smbclient:
    #     sharename (mandatory)
    #     share_subdir for the cd part
    #        calculated by:
    #           home_dir

    my %tree=();
    my $ref_tree=\%tree;
    my $server;
    my $tmp;
    my $count_dirs=0;
    my $count_files=0;

    
    if (defined $home_dir and not defined $share_subdir){
        # extract share_subdir from complete dir
        $server="//$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}/$share";
        ($tmp,$share_subdir)=split(/$share/,$home_dir);
    }

    if (defined $home_dir and defined $home_subdir){
        # append subdir
	$share_subdir=$share_subdir."\\".$home_subdir;
    }

    
    #print "share: $share\n";
    #print "server: $server\n";
    #print "share_subdir: $share_subdir\n";
    #print "home_dir: $home_dir\n";
    #print "home_subdir: $home_subdir\n";
    #print "user: $sam\n";

    $server="//$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}/$share";
    $tree{'SMB_PATH'}="smb:".$server.$share_subdir;

    # scan the contents
    my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
        " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin.
        "%'******'".
        " $server"." ".
        $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT_PROTOCOL_OPT'}.
        " -c 'cd $share_subdir; ls'";

    my ($return_value,@out_lines)=&Sophomorix::SophomorixBase::smb_command($smbclient_command,$smb_admin_pass);
    
    if (not $return_value==0){
        # command failed
    }
    
    foreach my $status (@out_lines){
        my $smb_name="";

        # check if a directory was found
	if ($status=~m/cd/ and $status=~m/NT_STATUS_OBJECT_NAME_NOT_FOUND/){
	    $tree{'ERROR'}="NT_STATUS_OBJECT_NAME_NOT_FOUND: Could not cd into SMB_PATH";
	    last;
	}
        # simple and works, but fails with  " D ", ... in filename
        #my (@list_tmp)=split(/( D | N | A )/,$status); # split with 1 chars of space before/after

        # best effort is to split at: whitespace D|N|A whitespace 0|0-9 whitespace
        my (@list_tmp)=split(/(\s+D\s+0\s+|\s+N\s+[0-9]+\s+|\s+A\s+[0-9]+\s+)/,$status); # split with 1 chars of space before/after


        foreach my $item (@list_tmp){
            my $smb_type="";
            if ($item=~m/\s+D\s+0\s+/){
                # directory
                $smb_type="DIR";
                $smb_name=&Sophomorix::SophomorixBase::remove_embracing_whitespace($smb_name);
                if ($smb_name eq "." or 
                    $smb_name eq ".."
                   ){
                    last;
                }

		# old
                #$ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER'}{$smb_name}{'TYPE'}="d";
                push @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} }, $smb_name;
                # new
		$count_dirs++;
                $tree{'TREE'}{$smb_name}{'TYPE'}="d";
                push @{ $tree{'LIST'} }, $smb_name;
                 
                last;
            } elsif ($item=~m/\s+N\s+[0-9]+\s+/ or $item=~m/\s+A\s+[0-9]+\s+/){
                # node/files
                $smb_type="FILE";
                $smb_name=&Sophomorix::SophomorixBase::remove_embracing_whitespace($smb_name);
		#$ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER'}{$smb_name}{'TYPE'}="f";
                #push @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} }, $smb_name; 

                $count_files++;
                $tree{'TREE'}{$smb_name}{'TYPE'}="f";
                push @{ $tree{'LIST'} }, $smb_name;
		
                last;
            } else {
                $smb_name=$smb_name.$item;
            }      
        }
    }

    # save counters
    $tree{'COUNT'}{'directories'}=$count_dirs;
    $tree{'COUNT'}{'files'}=$count_files;
    # sort
    if ($#{ $tree{'LIST'} }>0 ){
        @{ $tree{'LIST'} } = sort @{ $tree{'LIST'} };
    }
    #print Dumper (\%tree);
    #print Dumper ($ref_tree);
    return $ref_tree;
}



sub dir_listing_user {
    # directory listing for supervisor of session only
    my ($root_dns,$sam,$smb_dir,$school,$smb_admin_pass,$ref_sessions,$ref_sophomorix_config)=@_;

    # smbclient dir listing
    # empty for a start
    $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER'}=();
    $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'}=();

    # extract subdir in schoolshare
    my $server="//$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}/$school";
    my ($tmp,$sub_path)=split(/$school\//,$smb_dir);

    # scan the contents
    my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
        " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin.
        "%'******'".
        " $server"." ".
        $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT_PROTOCOL_OPT'}.
        " -c 'cd $sub_path; ls'";
    my ($return_value,@out_lines)=&Sophomorix::SophomorixBase::smb_command($smbclient_command,$smb_admin_pass);

    foreach my $status (@out_lines){
        my $smb_name="";

        # simple and works, but fails with  " D ", ... in filename
        #my (@list_tmp)=split(/( D | N | A )/,$status); # split with 1 chars of space before/after

        # best effort is to split at: whitespace D|N|A whitespace 0|0-9 whitespace
        my (@list_tmp)=split(/(\s+D\s+0\s+|\s+N\s+[0-9]+\s+|\s+A\s+[0-9]+\s+)/,$status); # split with 1 chars of space before/after


        foreach my $item (@list_tmp){
            my $smb_type="";
            if ($item=~m/\s+D\s+0\s+/){
                # directory
                $smb_type="DIR";
                $smb_name=&Sophomorix::SophomorixBase::remove_embracing_whitespace($smb_name);
                if ($smb_name eq "." or 
                    $smb_name eq ".."
                   ){
                    last;
                }

                $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER'}{$smb_name}{'TYPE'}="d";
                push @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} }, $smb_name; 
                last;
            } elsif ($item=~m/\s+N\s+[0-9]+\s+/ or $item=~m/\s+A\s+[0-9]+\s+/){
                # node/files
                $smb_type="FILE";
                $smb_name=&Sophomorix::SophomorixBase::remove_embracing_whitespace($smb_name);
		$ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER'}{$smb_name}{'TYPE'}="f";
                push @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} }, $smb_name; 

                last;
            } else {
                $smb_name=$smb_name.$item;
            }      
        }

        if ($smb_name eq "" or 
            ($smb_name=~m/blocks of size/ and $smb_name=~m/available/)){
            next;
        }
    }

    # sort
    if ($#{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} }>0 ){
        @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} } = 
        sort @{ $ref_sessions->{'TRANSFER_DIRS'}{$sam}{'TRANSFER_LIST'} };
}


  #   # this will be removed #######################################################################################
  #   # rewrite smb_dir with msdfs root
  #   $smb_dir=&rewrite_smb_path($smb_dir,$ref_sophomorix_config);

  #   print "      * fetching filelist of user $sam  ($smb_dir)\n";
  #   my $smb = new Filesys::SmbClient(username  => $DevelConf::sophomorix_file_admin,
  #                                    password  => $smb_admin_pass,
  #                                    debug     => 0);
  #   # empty for a start
  #   $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER'}=();
  #   $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER_LIST'}=();
  #   my $fd = $smb->opendir($smb_dir);
  #   while (my $file = $smb->readdir_struct($fd)) {
  #       if ($file->[1] eq "."){next};
  #       if ($file->[1] eq ".."){next};
  #       if ($file->[0] == 7) {
  #       #print "Directory ",$file->[1],"\n";
  #       $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER'}{$file->[1]}{'TYPE'}="d";
  #       push @{ $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER_LIST'} }, $file->[1]; 
  #   } elsif ($file->[0] == 8) {
  #       #print "File ",$file->[1],"\n";
  #       $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER'}{$file->[1]}{'TYPE'}="f";
  #       push @{ $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER_LIST'} }, $file->[1]; 
  #   } else {

  #   }
  # }
  # # sort
  # if ($#{ $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER_LIST'} }>0 ){
  #     @{ $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER_LIST'} } = 
  #       sort @{ $ref_sessions->{'TRANSFER_DIRS3'}{$sam}{'TRANSFER_LIST'} };
  # }
  # #close($fd); # ?????????????? gives error
  #   # this will be removed #######################################################################################
}



sub quota_listing_session_participant {
    # quota listng for participant only
    my ($participant,$session,$supervisor,$ref_sessions)=@_;
    print "      * fetching quota of participant $participant  --> todo\n";

    # session ids
    $ref_sessions->{'id'}{$session}{'PARTICIPANTS'}{$participant}{'quota'}{'/dev/sda1'}{'COMMENT'}="Home";
    $ref_sessions->{'id'}{$session}{'PARTICIPANTS'}{$participant}{'quota'}{'/dev/sda1'}{'hardlimit'}="xxx MB";


    # supervisors
    $ref_sessions->{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$session}{'PARTICIPANTS'}
                   {$participant}{'quota'}{'/dev/sda1'}{'hardlimit'}="xxx MB";
    $ref_sessions->{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$session}{'PARTICIPANTS'}
                   {$participant}{'quota'}{'/dev/sda1'}{'comment'}="Home";
}



# sophomorix logging to command.log
######################################################################
sub log_script_start {
    my $stolen=0;
    my ($ref_arguments,$ref_result,$ref_sophomorix_config) = @_;

    my $skiplock=0;
    # scripts that are locking the system
    my $log=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_LOG'}."::start::  $0";
    my $log_locked=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_LOG'}."::locked:: $0";
    my $count=0;

    foreach my $arg ( @{ $ref_arguments}  ){ 
        $count++;
        # count numbers arguments beginning with 1
        # @arguments numbers arguments beginning with 0
        if ($arg eq "--skiplock"){
            $skiplock=1;
        }

        # change argument of option to xxxxxx if password is expected
        if (exists $DevelConf::forbidden_log_options{$arg}){
            $ { $ref_arguments }[$count]="xxxxxx";
            # $arguments[$count]="xxxxxx";
        }

        if ($arg eq ""){
   	    $log=$log." ''";
   	    $log_locked=$log_locked." ''";
        } else {
	    $log=$log." ".$arg ;
	    $log_locked=$log_locked." ".$arg ;
        }
    }

    $log=$log."::$$"."::\n";
    $log_locked=$log_locked."::$$"."::\n";

    open(LOG,">>$DevelConf::log_command");
    print LOG "$log";
    close(LOG);
    my $try_count=0;
    my $max_try_count=5;

    # exit if lockfile exists
    while (-e $DevelConf::lock_file and $skiplock==0){
        my @lock=();
        $try_count++; 
        my ($locking_script,$locking_pid)=&read_lockfile($log_locked);
        if ($try_count==1){
           &print_title("sophomorix locked (${locking_script}, PID: $locking_pid)");
        }
        my $ps_string=`ps --pid $locking_pid | grep $locking_pid`;
        $ps_string=~s/\s//g; 

        if ($ps_string eq ""){
            # locking process nonexisting
	    print "PID $locking_pid not running anymore\n";
	    print "   I'm stealing the lockfile\n";
            $stolen=&lock_sophomorix("steal",$locking_pid,$ref_arguments);
            last;
        } else {
	    print "Process with PID $locking_pid is still running\n";
        }

        if ($try_count==$max_try_count){
            &print_title("try again later ...");
            exit 88;
        } else {
            sleep 1;
        }
    }
    
    if (exists ${DevelConf::lock_scripts}{$0} 
           and $stolen==0
           and $skiplock==0){
	&lock_sophomorix("lock",0,$ref_arguments);
    }
    &print_title("$0 started ...");
}



sub log_script_end {
    my ($ref_arguments,$ref_result,$ref_sophomorix_config,$json) = @_;
    # log script end uses its own time (calculate how long a script was running)
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $log="${timestamp}::end  ::  $0";
    my $count=0;
   foreach my $arg ( @{ $ref_arguments}  ){    
        $count++;
        # count numbers arguments beginning with 1
        # @arguments numbers arguments beginning with 0
        # change argument of option to xxxxxx if password is expected
        if (exists $DevelConf::forbidden_log_options{$arg}){
            $ { $ref_arguments }[$count]="xxxxxx";
        }
	$log=$log." ".$arg ;
    }
    $log=$log."::"."$$"."::\n";
    open(LOG,">>$DevelConf::log_command");
    print LOG "$log";
    close(LOG);
    # remove lock file
    if (-e $DevelConf::lock_file
         and exists ${DevelConf::lock_scripts}{$0}){
	unlink $DevelConf::lock_file;
        &print_title("Removing lock in $DevelConf::lock_file");    

    }
    #&nscd_start();
    # flush_cache tut nur bei laufendem nscd
    #&nscd_flush_cache();
    &print_title("$0 terminated regularly");
    &result_sophomorix_add_log($ref_result,"$0 terminated regularly");
    # output the result object
    &result_sophomorix_print($ref_result,$ref_sophomorix_config,$json);
    exit;
}



sub log_script_exit {
    my ($message,        # what to print to the log file/console
        $return,         # return 0: normal end, return=1 unexpected end
        $unlock,         # unlock (unused)
        $skiplock,       # skiplock (unused)
        $ref_arguments,  # arguments of calling script
        $ref_result,     # reference to result hash
        $ref_sophomorix_config,
        $json,
        $ref_parameter,  # replacement parameter list for error scripts
        )=@_;

    # log script exit uses its own time (calculate how long a script was running)
    my $timestamp = `date '+%Y-%m-%d %H:%M:%S'`;
    chomp($timestamp);
    my $log="${timestamp}::exit ::  $0";

    # get correct message
    if ($return!=0){
        if ($return==1){
            # use message given by option 1)
        } else {
            #$message = &Sophomorix::SophomorixAPI::fetch_error_string($return);
        }
    } 
    foreach my $arg ( @{ $ref_arguments}  ){  
        # count numbers arguments beginning with 1
        # @arguments numbers arguments beginning with 0
        # change argument of option to xxxxxx if password is expected
        if (exists $DevelConf::forbidden_log_options{$arg}){
            $ { $ref_arguments }[$count]="xxxxxx";
        }
	$log=$log." ".$arg ;
    }
    $log=$log."::"."$$"."::$message\n";
    open(LOG,">>$DevelConf::log_command");
    print LOG "$log";
    close(LOG);
    # remove lock file
    if (-e $DevelConf::lock_file
         and exists ${DevelConf::lock_scripts}{$0}){
        &print_title("Removing lock in $DevelConf::lock_file");
        #&unlock_sophomorix();
        unlink $DevelConf::lock_file;
    }
    if ($message ne ""){
        &print_title("$message");
    }
    # put message in json object
    &result_sophomorix_add($ref_result,"ERROR",-1,$ref_parameter,$message);

    # output the result object
    &result_sophomorix_print($ref_result,$ref_sophomorix_config,$json);
    exit $return;
}



sub log_user_add {
    my ($arg_ref) = @_;
    my $sam = $arg_ref->{sAMAccountName};
    my $role = $arg_ref->{sophomorixRole};
    my $school = $arg_ref->{sophomorixSchoolname};
    my $lastname = $arg_ref->{lastname};
    my $firstname = $arg_ref->{firstname};
    my $adminclass = $arg_ref->{adminclass};
    my $unid = $arg_ref->{unid};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $log_line="ADD::".$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'EPOCH'}."::".
                 $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}."::".
                 $school."::".$sam."::".$lastname."::".$firstname."::".$adminclass."::".
                 $role."::".$unid."::\n";
    my $logfile=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_ADD'};

    system ("mkdir -p $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}");

    open (LOG,">>$logfile");
    print LOG $log_line;
    close(LOG);
}



sub log_user_update {
    my ($arg_ref) = @_;
    my $sam = $arg_ref->{sAMAccountName};
    my $unid = $arg_ref->{unid};
    my $school_old = $arg_ref->{school_old};
    my $school_new = $arg_ref->{school_new};
    my $update_log_string = $arg_ref->{update_log_string};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    $update_log_string=~s/,$//g;# remove trailing ,
    my $log_line="UPDATE::".$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'EPOCH'}."::".
                 $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}."::".
                 $school_old."::".$school_new."::".$sam."::".$unid."::".$update_log_string."::\n";
    my $logfile=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_UPDATE'};

    system ("mkdir -p $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}");

    open (LOG,">>$logfile");
    print LOG $log_line;
    close(LOG);
}



sub log_user_kill {
    my ($arg_ref) = @_;
    my $sam = $arg_ref->{sAMAccountName};
    my $role = $arg_ref->{sophomorixRole};
    my $school = $arg_ref->{sophomorixSchoolname};
    my $lastname = $arg_ref->{lastname};
    my $firstname = $arg_ref->{firstname};
    my $adminclass = $arg_ref->{adminclass};
    my $unid = $arg_ref->{unid};
    my $home_delete_string = $arg_ref->{home_delete_string};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $log_line="KILL::".$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'EPOCH'}."::".
                 $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}."::".
                 $school."::".$sam."::".$lastname."::".$firstname."::".$adminclass."::".
                 $role."::".$unid."::HOME_DELETED=".$home_delete_string."::\n";
    my $logfile=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_KILL'};

    system ("mkdir -p $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}");

    open (LOG,">>$logfile");
    print LOG $log_line;
    close(LOG);
}


sub log_group_add {
    my ($arg_ref) = @_;
    my $group = $arg_ref->{sAMAccountName};
    my $type = $arg_ref->{sophomorixType};
    my $school = $arg_ref->{sophomorixSchoolname};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $log_line="ADD::".$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'EPOCH'}."::".
                 $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}."::".
                 $school."::".$group."::".$type."::\n";
    my $logfile=$ref_sophomorix_config->{'INI'}{'GROUPLOG'}{'GROUP_LOGDIR'}."/".
	$ref_sophomorix_config->{'INI'}{'GROUPLOG'}{'GROUP_ADD'};

    system ("mkdir -p $ref_sophomorix_config->{'INI'}{'GROUPLOG'}{'GROUP_LOGDIR'}");

    open (LOG,">>$logfile");
    print LOG $log_line;
    close(LOG);
}


sub log_group_kill {
    my ($arg_ref) = @_;
    my $group = $arg_ref->{sAMAccountName};
    my $type = $arg_ref->{sophomorixType};
    my $school = $arg_ref->{sophomorixSchoolname};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $log_line="KILL::".$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'EPOCH'}."::".
                 $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}."::".
                 $school."::".$group."::".$type."::\n";
    my $logfile=$ref_sophomorix_config->{'INI'}{'GROUPLOG'}{'GROUP_LOGDIR'}."/".
	$ref_sophomorix_config->{'INI'}{'GROUPLOG'}{'GROUP_KILL'};

    system ("mkdir -p $ref_sophomorix_config->{'INI'}{'GROUPLOG'}{'GROUP_LOGDIR'}");

    open (LOG,">>$logfile");
    print LOG $log_line;
    close(LOG);
}



sub get_login_avoid {
    # avoid logins of recently killed users
    my ($ref_sophomorix_config)=@_;
    my %login_avoid=();
    my $logfile=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	        $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_KILL'};
    my $reuse_limit=86400*$ref_sophomorix_config->{'INI'}{'LOGIN_REUSE'}{'REUSE_LIMIT_DAYS'};
    if (not -f $logfile){
        # nothing foun
        return \%login_avoid;
    }
    open (KILL,"<$logfile");
    while(<KILL>){
        chomp();
        my ($type,$epoch,$time_AD,$school,$login,$last,$first,$class,$role,$unid) = split(/::/);
        my $unused_sec=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'EPOCH'}-$epoch;
        #print "$login unused for $unused_sec seconds (Min. limit for re-use is $reuse_limit)\n";
        if ($unused_sec<$reuse_limit){
            $login_avoid{'AVOID_LOGINS'}{$login}{'UNUSED'}=$unused_sec;
        }
    }
    close(KILL);
    return \%login_avoid;
}



sub create_test_login {
    # $ref_AD_check --> $ref_forbidden_logins
    my ($school,
        $identifier_ascii,
        $file,
        $login_wish,
        $ref_forbidden_logins,
        $ref_login_avoid,
        $line_num,
        $ref_users_file,
        $ref_sophomorix_config)=@_;
    my ($surname_login,$firstname_login,$birthdate)=split(";", $identifier_ascii);
    my $login_check_ok; # the approved login name

    $surname_login=~s/-//g;  # remove minus
    $surname_login=~s/\.//g; # remove dots
    $surname_login=~s/ //g;  # remove whitespace
    $surname_login=~tr/A-Z/a-z/; # only small letters
    $surname_login=~s/[^a-zA-Z0-9]//; # ignore non a-z

    $firstname_login=~s/-//g; # remove minus
    $firstname_login=~s/\.//g; # remove dots
    $firstname_login=~s/ //g;  # remove whitespace
    $firstname_login=~tr/A-Z/a-z/; # only small letters
    $firstname_login=~s/[^a-zA-Z0-9]//; # ignore non a-z

    my $login_name_to_check;
    if ($login_wish eq "---"){
        ############################################################
        # login creation
        if ($ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'FIRSTNAME_CHARS'}==0 and 
            $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SURNAME_CHARS'}==0){
	    my $error_message="File '".$file."' is not configured for auto login creation.";
            return ("---",$error_message);
        }
        # firstname+surname or surname+firstname
        if ( $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SURNAME_FIRSTNAME_REVERSE'} eq 
                 $ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_TRUE'}){
            $login_part_2=substr($surname_login,0,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SURNAME_CHARS'});
            $login_part_1=substr($firstname_login,0,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'FIRSTNAME_CHARS'});
        } else {
            $login_part_1=substr($surname_login,0,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SURNAME_CHARS'});
            $login_part_2=substr($firstname_login,0,$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'FIRSTNAME_CHARS'});
        }

        ############################################################
        # test proposed login
        $login_name_to_check="$login_part_1"."$login_part_2";
        if (not exists $ref_forbidden_logins->{'FORBIDDEN'}{$login_name_to_check} and
            not exists $ref_login_avoid->{'AVOID_LOGINS'}{$login_name_to_check} ){
            # not forbidden an not to be avoided -> use it!
            $login_check_ok=$login_name_to_check;
        } else {
            # if login is not OK: add 1,2,3,... until OK
            my $login_name_to_check_mod=$login_name_to_check;
            my $i=1; # start for appending numbers
            while (exists $ref_forbidden_logins->{'FORBIDDEN'}{$login_name_to_check_mod} or
                   exists $ref_login_avoid->{'AVOID_LOGINS'}{$login_name_to_check_mod} ){
                # Append number
                $login_name_to_check_mod="$login_name_to_check"."$i";
                $i=$i+1;
            }
            # Nun kann modifizierter Loginname benutzt werden
            $login_check_ok=$login_name_to_check_mod;
        } 
    } else {
        ############################################################
        # check wish login
        $login_char_length = length $login_wish;
        if (not $login_wish=~m/^[a-z0-9-_]+$/){
#	    my $error_message="'".$login_wish."' contains invalid characters for a login name! (Allowed are: a-z0-9-_) ".
#                              "| $file LINE $line_num: $ref_users_file->{$file}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}";
	    my $error_message="'".$login_wish."' contains invalid characters for a login name! (Allowed are: a-z0-9-_) ".
                              "| $file LINE $line_num: $ref_users_file->{$school}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}";
            return ("---",$error_message);
        } elsif ($login_char_length<2){
#	    my $error_message="'".$login_wish."' is to short for a login name! (Minimum number of characters for a login name is 2) ".
#                              "| $file LINE $line_num: $ref_users_file->{$file}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}";
	    my $error_message="'".$login_wish."' is to short for a login name! (Minimum number of characters for a login name is 2) ".
                              "| $file LINE $line_num: $ref_users_file->{$school}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}";
            return ("---",$error_message);
        } elsif (not $login_wish=~m/^[[:alnum:]]+/){
#	    my $error_message="'".$login_wish."' does not begin with an alpha-numeric character ".
#                              "| $file LINE $line_num: $ref_users_file->{$file}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}";
	    my $error_message="'".$login_wish."' does not begin with an alpha-numeric character ".
                              "| $file LINE $line_num: $ref_users_file->{$school}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}";
             return ("---",$error_message);
        } elsif (exists $ref_forbidden_logins->{'FORBIDDEN'}{$login_wish}){
#	    my $error_message="Login ".$ref_forbidden_logins->{'FORBIDDEN'}{$login_wish}."' ".
#                              "| $file LINE $line_num: $ref_users_file->{$file}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}";
	    my $error_message="Login ".$ref_forbidden_logins->{'FORBIDDEN'}{$login_wish}."' ".
                              "| $file LINE $line_num: $ref_users_file->{$school}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}";
            return ("---",$error_message);
        } elsif (exists $ref_login_avoid->{'AVOID_LOGINS'}{$login_wish}){
            # non reusable login
            my $days=int($ref_login_avoid->{'AVOID_LOGINS'}{$login_wish}{'UNUSED'}/86400);
            # put in result hash ?????
	    print "\n   WARNING: $login_wish was used $days days ago (Not recommended to re-use $login_wish already)\n\n"; 
#	    print "        LINE: $ref_users_file->{$file}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}\n";
	    print "        LINE: $ref_users_file->{$school}{'identifier_ascii'}{$identifier_ascii}{LINE_OLD}\n";
	    print "              ($file LINE $line_num)\n";
        }
        $login_check_ok=$login_wish;
    }

    # the found loginname is added to the forbidden logins from now on
    $ref_forbidden_logins->{'FORBIDDEN'}{$login_check_ok}="new";
    return ($login_check_ok,"---");
}



# backup stuff before modifying
######################################################################
# option 2: add, move, kill, update
# option 3: before, after
# option 4: cp should be correct
#  what is this mv for: &backup_auk_file($zeit,"add","after","mv");
sub backup_auk_file {
    my ($str,$str2,$ref_sophomorix_config) = @_;
    my $input=$ref_sophomorix_config->{'INI'}{'PATHS'}{'CHECK_RESULT'}."/sophomorix.".$str;
    my $output=${DevelConf::path_log_user}."/".
        $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_FILE'}.
        ".sophomorix.".$str."-".$str2;

    # Verarbeitete Datei mit Zeitstempel versehen
    if (-e "${input}"){
        system("cp ${input} ${output}");
        system("chown root:root ${output}");
        system("chmod 600 ${output}");
    }
}



# run smb commands
sub smbpasswd_command {
    my ($smb_command)=@_;
    my $smb_command_out=`$smb_command 2>&1`; # redirect STDERR to STDOUT
    my $smb_command_return=${^CHILD_ERROR_NATIVE}; # return of value of last command
    my @returned_lines=split("\n",$smb_command_out);
    return ($smb_command_return,@returned_lines);
}



sub smb_command {
    my ($smb_display_command,$smb_admin_pass)=@_;
    # Parameter:
    # $smb_display_command contains: ****** (6 asterisks) as password placeholder
    # $smb_admin_pass replaces ******
    my $smb_command=$smb_display_command;
 
    # assemble real command
    $smb_command=~s/\*\*\*\*\*\*/$smb_admin_pass/;

    ############################################################
    # run the command
    $smb_command_out=`$smb_command`;
    my $smb_command_return=${^CHILD_ERROR_NATIVE}; # return of value of last command
    my @returned_lines=split("\n",$smb_command_out);
    chomp($smb_command_out);
    my $smb_command_out_ident=&ident_output($smb_command_out,8);

    if( 
        ($smb_command_return==0 and $smb_command_out eq "") or
        ($smb_command_return==0 and $smb_command_out=~m/Deleted user /) or
        ($smb_command_return==0 and $smb_command_out=~m/Deleted group /) or
        ($smb_command_return==0 and $smb_command_out=~m/successfully/) or
        ($smb_command_return==0 and $smb_command_out=~m/directory/) or
        ($smb_command_return==0 and $smb_command_out=~m/File:/) or
        ($smb_command_return==0 and $smb_command_out=~m/blocks available/) or
        ($smb_command_return==0 and $smb_command_out=~m/Default Soft Limit/) or
        ($smb_command_return==0 and $smb_command=~m/\/usr\/bin\/smbcquotas/)
      ){
        # empty output or "succesfully" in samba-tool
        print "OK ($smb_command_return): $smb_display_command\n";
        if($Conf::log_level>1){
            print "     COMMAND:\n";
            print "        $smb_display_command\n";
            print "     RETURN VALUE: $smb_command_return\n";
            print "     MESSAGE:\n";
            print $smb_command_out_ident;
        }
    } elsif ($smb_command_return==0 and $smb_command_out=~m/NT_STATUS_OBJECT_NAME_COLLISION/){
        # Errors that are warnings: smbclient NT_STATUS_OBJECT_NAME_COLLISION  -> file exists already
        print "OK: smb command ($smb_command_return: NT_STATUS_OBJECT_NAME_COLLISION --> file(s) existed already)\n";
        if($Conf::log_level>1){
            print "     COMMAND:\n";
            print "        $smb_display_command\n";
            print "     RETURN VALUE: $smb_command_return\n";
            print "     MESSAGE:\n";
            print $smb_command_out_ident;
        }
    } elsif ($smb_command_return==256 and $smb_command_out=~m/NT_STATUS_NO_SUCH_FILE listing/){
        # This is OK
        print "OK: smb command ($smb_command_return: NT_STATUS_NO_SUCH_FILE listing--> made sure file nonexisting)\n";
        if($Conf::log_level>1){
            print "     COMMAND:\n";
            print "        $smb_display_command\n";
            print "     RETURN VALUE: $smb_command_return\n";
            print "     MESSAGE:\n";
            print $smb_command_out_ident;
        }
    } else {
        print "ERROR: smb command\n";
        print "     COMMAND:\n";
        print "        $smb_display_command\n";
        print "     RETURN VALUE: $smb_command_return\n";
        print "     ERROR MESSAGE:\n";
        print $smb_command_out_ident;
        &result_sophomorix_add($ref_sophomorix_result,"ERROR",-1,$ref_parameter,"FAILED ($smb_command_return): $smb_display_command");
    }
    return ($smb_command_return,@returned_lines);
}



sub smb_file_rewrite {
    my ($unix_path,
        $smb_share,
        $smb_top_path,
        $uuid,
        $smb_low_path,
        $mode,
        $root_dns,
        $school,
        $smb_admin_pass,
        $ref_sophomorix_config)=@_;

    my $source_dir = dirname($unix_path);
    my $source_file = basename($unix_path);

    if ($mode eq "COPY"){
        # upload file via smb protocol
        my $smbclient_command_put=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
            " -U ".$DevelConf::sophomorix_file_admin.
            "%'******'".
            " //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/$smb_share ".
            " -c 'lcd \"$source_dir\"; cd \"$smb_top_path/$uuid/$smb_low_path\"; prompt; put \"$source_file\" ; exit;'";
        print "$smbclient_command_put\n";
        my ($return_value_put,@out_lines_put)=&Sophomorix::SophomorixBase::smb_command($smbclient_command_put,$smb_admin_pass);
    } elsif ($mode eq "REWRITE"){
        my ($fh,$tmp) = tempfile( DIR => $ref_sophomorix_config->{'PATHS'}{'TMP_SMB'}, UNLINK =>  1 );
        my $tmp_dir  = dirname($tmp);
        my $tmp_file  = basename($tmp);
	my $teachergroup;
	if ($school eq $DevelConf::name_default_school){
            $teachergroup="teachers";
	} else {
            $teachergroup=$school."-teachers";
	}

        open(SOURCE, "<$unix_path") or die "File $unix_path not found";
        open(TMP, ">$tmp") or die "File $tmp not found";
        while(<SOURCE>){
            my $line=$_;
            # replacements
            $line=~s/\@\@SCHOOL\@\@/$school/g; 
            $line=~s/\@\@ROOTDNS\@\@/$root_dns/g; 
            $line=~s/\@\@SERVER\@\@/$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}/g; 
            $line=~s/\@\@TEACHERGROUP\@\@/$teachergroup/g; 
            print TMP "$line";
        }

        # upload file via smb protocol
        my $smbclient_command_put=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
            " -U ".$DevelConf::sophomorix_file_admin.
            "%'******'".
            " //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/$smb_share ".
            " -c 'lcd \"$tmp_dir\"; cd \"$smb_top_path/$uuid/$smb_low_path\"; prompt; put \"$tmp_file\" \"$source_file\" ; exit;'";
        print "$smbclient_command_put\n";
        my ($return_value_put,@out_lines_put)=&Sophomorix::SophomorixBase::smb_command($smbclient_command_put,$smb_admin_pass);
        close(TMP);
        close(SOURCE);
    }
}



# acl stuff
######################################################################
sub NTACL_set_file {
    my ($arg_ref) = @_;
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $ntacl = $arg_ref->{ntacl};
    my $smbpath = $arg_ref->{smbpath};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $user = $arg_ref->{user};
    my $group = $arg_ref->{group};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $ntacl_abs=$DevelConf::path_conf_devel_ntacl."/".$ntacl.".template";
    if ($ntacl eq "noacl" or $ntacl eq "nontacl"){
        if($Conf::log_level>1){
            print "   Skipping ACL/NTACL creation for $smbpath (no acl file given)\n";
        }
        return;
    } elsif (not -r $ntacl_abs){ # -r: readable
        print "\nERROR: $ntacl_abs not found/readable\n\n";
        exit 88;
    } 
    my $smbcacls_option="";
    open(NTACL,"<$ntacl_abs");
    my $line_count=0;
    while (<NTACL>) {
        $_=~s/\s+$//g;# remove trailing whitespace
        if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
            next;
        }
        if (/^CONTROL:/){
            # do something special for CONTROL line
            #print "*** skipping $_\n";
            next;
        }
        
        my $line=$_;
        $line_count++;
        chomp($line);
        # replacements in line go here
        $line=~s/\@\@WORKGROUP\@\@/$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}/;

        if ($user ne ""){
            $line=~s/\@\@USER\@\@/$user/;
        }
        if ($group ne ""){
            $line=~s/\@\@GROUP\@\@/$group/;
        }
        if ($school ne ""){
            my $prefix=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'PREFIX'};
#            $line=~s/\@\@SCHOOLNAME\@\@/$school/;
            $line=~s/\@\@SCHOOLNAME\@\@/$ref_sophomorix_config->{'INI'}{'VARS'}{'SCHOOLGROUP_PREFIX'}$school/; # s_ (This is the group name in the NTACL)
            $line=~s/\@\@SCHOOLPREFIX\@\@/$prefix/;
        }

        # create multiple lines? from one line
        if ($line_count==1){
            $smbcacls_option=$line;
        } else {
            $smbcacls_option=$smbcacls_option.",".$line;
        }
    }
    $smbcacls_option="\"".$smbcacls_option."\"";
    my $server_share="//".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/".$school;

    if ($ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCACLS_SERVER_FIX'} eq "TRUE"){
        if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}{'msdfs root'} and
            exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}{'msdfs proxy'} ){
            if ($ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}{'msdfs root'} eq "yes"){
                $server_share=$ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school}{'msdfs proxy'};
            }
        }
    }

    my $smbcacls_base_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCACLS'}.
                              " -U ".$DevelConf::sophomorix_file_admin."%'******' ".
                              $server_share." ".$smbpath." --set ";
    my $smbcacls_display_command=$smbcacls_base_command.$smbcacls_option;

    # assemble real command
    my $smbcacls_command=$smbcacls_display_command;
    $smbcacls_command=~s/\*\*\*\*\*\*/$smb_admin_pass/;
    ############################################################
    # run the command
    $smbcacls_out=`$smbcacls_command`;
    my $smbcacls_return=${^CHILD_ERROR_NATIVE}; # return of value of last command
    close(NTACL);

    ############################################################
    # add linebreak to display
    $smbcacls_display_command=~s/--set/\n      --set/;
    my $smbcacls_out_ident=&ident_output($smbcacls_out,8);
    if($smbcacls_return==0){
        print "OK ($smbcacls_return): smbcacls-NTACL on //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/$school $smbpath\n";
        if($Conf::log_level>1){
            print "     COMMAND:\n";
            print "        $smbcacls_display_command\n";
            print "     RETURN VALUE: $smbcacls_return\n";
            print "     ERROR MESSAGE:\n";
            print $smbcacls_out_ident;
        }
    } else {
        print "ERROR: smbcacls-NTACL on //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/$school $smbpath\n";
        print "     COMMAND:\n";
        print "        $smbcacls_display_command\n";
        print "     RETURN VALUE: $smbcacls_return\n";
        print "     ERROR MESSAGE:\n";
        print $smbcacls_out_ident;
        &result_sophomorix_add($ref_sophomorix_result,"ERROR",-1,$ref_parameter,"FAILED ($smbcacls_return): $smbcacls_display_command");
    }
}



# ?????? deprecated ???
sub old_ACL_set_file_obsolete {
    # $path and $aclname are mandatory
    # $workgroup will be later mandatory 
    my ($arg_ref) = @_;
    my $workgroup = $arg_ref->{workgroup};
    my $path = $arg_ref->{path};
    my $aclname = $arg_ref->{aclname};
    #my $role = $arg_ref->{role};
    #my $type = $arg_ref->{type};

    # replacements
    my $school = $arg_ref->{school};
    my $user = $arg_ref->{user};
    my $group = $arg_ref->{group};
 
    my $source="";
    my $tmp="";
    if (not defined $workgroup){
        $workgroup=LINUXMUSTER;
    }

    if (defined $aclname){
        $source=$DevelConf::path_conf_devel_acl."/".$aclname.".acl.template";
        $tmp=$DevelConf::path_conf_tmp."/".$aclname.".acl";
    } else {
        print "";
        &Sophomorix::SophomorixBase::log_script_exit(
            "acl_name, role or type is mandatory when setting ACL's!",1,1,0,@arguments);
    }

    if (not -e $source){
        &Sophomorix::SophomorixBase::log_script_exit(
            "acl template $source not found!",1,1,0,@arguments);
    }

    # replacements
    my $replace="";
    $replace=$replace." -e 's/\@\@WORKGROUP\@\@/${workgroup}/g'"; 
    if (defined $user){
        $replace=$replace." -e 's/\@\@USER\@\@/${user}/g'"; 
    }
    if (defined $group){
        $replace=$replace." -e 's/\@\@GROUP\@\@/${group}/g'"; 
    }
    if (defined $school){
        $replace=$replace." -e 's/\@\@SCHOOL\@\@/${school}-/g'"; 
    }

    # patch the acl into tmp
    $sed_command="sed $replace $source > $tmp";
    print "$sed_command\n";
    system($sed_command);

    if($Conf::log_level>=2){
        print "\nPatched ACL:\n\n";
        system("cat $tmp");
        print "\n";
    }

    # apply acl from tmp to path
    $setfacl="setfacl --set-file=".$tmp." ".$path;
    print "$setfacl\n";
    system($setfacl);
}



# password stuff
######################################################################
sub get_passwd_charlist {
   # characters for passwords
   # avoid: 1,i,l,I,L,j
   # avoid: 0,o,O
   # avoid: Capital letters, that can be confused with 
   #        small letters: C,I,J,K,L,O,P,S,U,V,W,X,Y,Z 
   my @zeichen=('a','b','c','d','e','f','g','h','i','j','k',
                'm','n','o','p','q','r','s','t','u','v',
                'w','x','y','z',
                'A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T',
                'U','V','W','X','Y','Z',
                '2','3','4','5','6','7','8','9',
                '!','$','&','(',')','?'
                );
   return @zeichen;
}



sub get_plain_password {
    my ($role,$file,$random,$length,$birthdate,$ref_sophomorix_config,@password_chars)=@_;
    my $password="";
    if ( $random eq $ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_TRUE'} or $random eq "birthday") {
        $password=&create_plain_password($random,$length,$birthdate,@password_chars);
    } elsif ( $random eq "dice") {
        if ($ref_sophomorix_config->{'samba'}{'domain_passwordsettings'}{'Password_complexity'} ne "off") {
            die "Error: Samba password complexity not disabled!\n" .
                "In order to use dice passwords, Samba must be configured to allow non-complex passwords using\n" .
                "'samba-tool domain passwordsettings set --complexity=off'\n";
        }
        if (! -e "/usr/local/bin/diceware") {
            die "Error: diceware not installed.\nIn order to use dice passwords, diceware must be installed:\n'pip3 install diceware'\n";
        }
        my $words = $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'DICE_WORDS'};
        my $lang  = $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'DICE_LANG'};
        if (! -e "/usr/local/lib/python3.10/dist-packages/diceware/wordlists/wordlist_$lang.txt") {
            die "Error: Wordlist /usr/local/lib/python3.10/dist-packages/diceware/wordlists/wordlist_$lang.txt does not exists.\n";
        }
        my $sepopt="";
        if ($ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'DICE_SEPARATOR'} ne "") {
            $sepopt="-d '$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'DICE_SEPARATOR'}'";
        }
        my $capsopt="";
        if ($ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'DICE_CAPS'} eq $ref_sophomorix_config->{'INI'}{'VARS'}{'BOOLEAN_FALSE'}) {
            $capsopt="--no-caps"
        }
        do {
            $password=`diceware $sepopt $capsopt -n $words -w $lang`;
            my $rc = $?>>8;
            if ($rc != 0) {
                die "Error: diceware terminated with rc $rc\n";
            }
            chomp($password);
            print "Info: diced password too short. Dicing again.\n";
        } while (length($password) < $ref_sophomorix_config->{'samba'}{'domain_passwordsettings'}{'Minimum_password_length'});
    } else {
        if ($ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'DEFAULT_NONRANDOM_PWD'} eq ""){
            if ($role eq "teacher") {
                $password=$DevelConf::teacher_password_default;
            } else {
                $password=$DevelConf::student_password_default;
            }
        } else {
            $password=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'DEFAULT_NONRANDOM_PWD'};
        }
    }
    return $password;
}



sub create_plain_password {
    my ($random,$num,$birthdate,@password_chars)=@_;
    my $password="";
    if ($random eq "birthday"){
        my @letters = ('A'..'Z');
        my $random_letter = $letters[int rand @letters];
        $password=$random_letter.$birthdate;
    } else {
        until ($password=~m/[!\$&\(\)?]/ and 
               $password=~m/[a-z]/ and 
               $password=~m/[A-Z]/ and
               $password=~m/[0-9]/
              ){
            $password="";
            for ($i=1;$i<=$num;$i++){
                $password=$password.$password_chars[int (rand $#password_chars+1)];
            }
	    #print "Password to test: $password\n";
        }
    }
    #print "Password OK: $password\n";
    return $password;
}



# filesystem
######################################################################
sub smb_share_subpath_from_homedir_attr {
    my ($homedir_attr,$school)=@_;
    my ($server,$sub_path)=split(/\/$school\//,$homedir_attr);
    my $share=$server."/".$school;
    return($share,$sub_path);
}


sub get_homedirectory {
    my ($root_dns,$school,$group_basename,$user,$role,$ref_sophomorix_config)=@_;
    my $homedirectory;  # as needed to fill the attribute 'homeDirectory (using \\)
    my $unix_home;      # (works only if share is on the same server)
    my $smb_rel_path;   # option for smbclient
    
    my $school_smbshare;
    if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
        $school_smbshare=$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
    } else {
        $school_smbshare=$school;
    }
    my $unc="//".$root_dns."/".$school_smbshare;
    my $smb_server="//".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/".$school_smbshare; 

    my $dns=$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{$ref_sophomorix_config->{'INI'}{'VARS'}{'HOMEDIRECTORY_HOST'}};
    
    if ($role eq "student"){
        $smb_rel_path="students/".$group_basename."/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\students\\".$group_basename."\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/students/".$group_basename."/".$user;
    } elsif ($role eq "staff"){
        $smb_rel_path="staff/".$group_basename."/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\staff\\".$group_basename."\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/staff/".$group_basename."/".$user;
    } elsif ($role eq "teacher"){
        $smb_rel_path="teachers/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\teachers\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/teachers/".$user;
    } elsif ($role eq "parent"){
        $smb_rel_path="parents/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\parents\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/parents/".$user;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_ROLE'}){
        # examuser
        if ($group_basename eq ""){
            # no subdir
            $smb_rel_path=$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."/".$user;
            $homedirectory="\\\\".$dns."\\".$school_smbshare."\\".
                $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."\\".$user;
            $unix_home=$DevelConf::homedir_all_schools."/".$school."/".
                $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."/".$user;
        } else {
            # with subdir
            $smb_rel_path=$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."/".$group_basename."/".$user;
            $homedirectory="\\\\".$dns."\\".$school_smbshare."\\".
                $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."\\".$group_basename."\\".$user;
            $unix_home=$DevelConf::homedir_all_schools."/".$school."/".
                $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_DIR'}."/".$group_basename."/".$user;
        }
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        $smb_rel_path="management/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\management\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/management/".$user;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        $smb_rel_path="management/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\management\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/management/".$user;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        $smb_rel_path="management/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\management\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/management/".$user;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        $smb_rel_path="management/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\management\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/management/".$user;
    } else {
        $smb_rel_path="unknown/".$group_basename."/".$user;
        $homedirectory="\\\\".$dns."\\".$school_smbshare."\\unknown\\".$group_basename."\\".$user;
        $unix_home=$DevelConf::homedir_all_schools."/".$school."/unknown/".$group_basename."/".$user;
    }
    return ($homedirectory,$unix_home,$unc,$smb_rel_path,$smb_server);
}



sub analyze_smbcquotas_out {
    my ($smbcquotas_out,$user) = @_;

    my ($full_user,$quota_data)=split(/:/,$smbcquotas_out);
    # extract full user/quota user from part before colon(:)
    $full_user=~s/\/$//; # remove trailing whitespace
    my ($realm,$quota_user)=split(/\\/,$full_user);

    my $used;
    my $soft_limit;
    my $hard_limit;
    my $used_mib;
    my $soft_limit_mib;
    my $hard_limit_mib;

    if ($full_user=~m/NT_STATUS_ACCESS_DENIED/){
        # ERROR fetching quota
        $quota_user=$user;
        $used="NT_STATUS_ACCESS_DENIED";
        $soft_limit="NT_STATUS_ACCESS_DENIED";
        $hard_limit="NT_STATUS_ACCESS_DENIED";
        $used_mib="NT_STATUS_ACCESS_DENIED";
        $soft_limit_mib="NT_STATUS_ACCESS_DENIED";
        $hard_limit_mib="NT_STATUS_ACCESS_DENIED";

    } else {
        # extract quota data from part after colon(:)
        $quota_data=~s/\s+//g;
        ($used,$soft_limit,$hard_limit)=split(/\//,$quota_data);

        $used_mib=round(10*$used/1024/1024)/10;

        if ($soft_limit eq "NOLIMIT"){
            $soft_limit="NO LIMIT";
            $soft_limit_mib="NO LIMIT";
        } else {
            $soft_limit_mib=round(10*$soft_limit/1024/1024)/10;
        }

        if ($hard_limit eq "NOLIMIT"){
            $hard_limit="NO LIMIT";
            $hard_limit_mib="NO LIMIT";
        } else {
            $hard_limit_mib=round(10*$hard_limit/1024/1024)/10;
        }
    }

    # debug output
    #print "HERE full: $full_user \n";
    #print "HERE user: $quota_user \n";
    #print "HERE used: $used \n";
    #print "HERE sl:   $soft_limit \n";
    #print "HERE hl:   $hard_limit \n";
    #print "HERE used: $used_mib \n";
    #print "HERE sl:   $soft_limit_mib \n";
    #print "HERE hl:   $hard_limit_mib \n";
    #print $smbcquotas_out;

    return ($full_user,
            $quota_user,
            $colon,
            $used,
            $soft_limit,
            $hard_limit,
            $used_mib,
            $soft_limit_mib,
            $hard_limit_mib,
           );
}



sub get_sharedirectory {
    my ($root_dns,$school,$group,$type,$ref_sophomorix_config)=@_;
    my $smb_share; # as needed for perl module 'homeDirectory (using //)
    my $unix_dir; # unix-path (works only if share is on the same server)
    my $smb_rel_path_share; # option for smbclient

    my $school_smbshare=$school;
    if ($school eq "---"){
        $school=$DevelConf::name_default_school;
        $school_smbshare=$DevelConf::name_default_school;
    } elsif ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
        $school_smbshare=$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
    } else {
        $school_smbshare=$school;
    }

    my $unc="//".$root_dns."/".$school_smbshare;

    if ($type eq "project"){
        $smb_rel_path_share="/share/projects/".$group;
        $smb_rel_path_homes=""; # not needed
        $smb_share="smb://".$root_dns."/".$school_smbshare."/".$smb_rel_path_share;
        $unix_dir="/srv/samba/schools/".$school."/share/projects/".$group;
    } elsif  ($type eq "adminclass" or $type eq "extraclass"){
        my $group_basename=&get_group_basename($group,$school);
        $smb_rel_path_share="share/classes/".$group_basename;
        $smb_rel_path_homes="students/".$group_basename;
        $smb_share="smb://".$root_dns."/".$school_smbshare."/".$smb_rel_path_share;
        $unix_dir="/srv/samba/schools/".$school."/share/classes/".$group_basename;
    } else {
        $smb_rel_path_share="unknown";
        $smb_rel_path_homes="unknown";
        $smb_share="unknown";
        $unix_dir="unknown";
    }

    return ($smb_share,$unix_dir,$unc,$smb_rel_path_share,$smb_rel_path_homes);
}



sub get_group_basename {
    my ($group,$school)=@_;
    $group=~s/^${school}-//;
    return $group;
}



# others
######################################################################
# error, when options are not given correctly
sub check_options{
    my ($parse_ergebnis,$ref_sophomorix_result,$json,$ref_options) = @_;
    # $ref_options contains 
    #   * all options given on command line (lowercase top level keys)
    #   * CONFIG-key: info about options from the script source:
    #
    #     CONFIG-->ACTION--><object>="create,update"
    #        defines actions in this script and what object they need, i.e. a group
    #        Example: $options{'CONFIG'}{'ACTION'}{'GROUP'}="create,update";
    #           options create/update are options that need a GROUP object
    #
    #     CONFIG-->ONE_OF--><object>="opt1,opt2"
    #        defines by which options an object MUST be defined
    #        Example: $options{'CONFIG'}{'ONE_OF'}{'GROUP'}="class,group";
    #           options class/group are options that MUST provide a GROUP object
    #
    #     CONFIG-->SOME_OF--><object>="opt1,opt2"
    #        defines by which option CAN be given to an object
    #
    #     CONFIG-->DEPENDS--><option>="opt"
    #        defines that option <option> needs option opt
    #        Example: $options{'CONFIG'}{'DEPENDS'}{'gidnumber-migrate'}="create";
    #           option gidnumber-migrate is only useful, when option create is also given


    # get effective/real userID
    $ref_options->{'RUNTIME'}{'EFFECTIVE_UID'}=$<;
    $ref_options->{'RUNTIME'}{'REAL_UID'}=$>;
    $ref_options->{'RUNTIME'}{'SUDO_USER'}=$ENV{'SUDO_USER'};
    if (not defined $ref_options->{'RUNTIME'}{'SUDO_USER'}){
        $ref_options->{'RUNTIME'}{'SUDO_USER'}="root";
    }


    print "Command line::\n";
    #print Dumper ($ref_options);

    if (not defined $Conf::log_level){
	$Conf::log_level=1;
    }
    if (not $parse_ergebnis==1){
        my @list = split(/\//,$0);
        my $scriptname = pop @list;
        print "\nYou have made a mistake, when specifying options.\n"; 
        print "See error message above. \n\n";
        print "... $scriptname is terminating.\n\n";
        exit 88;
    } else {
        if($Conf::log_level>=3){
            print "All options  were recognized.\n";
        }
    }


    my $warn_count=0;
    my %tmp=();
    ############################################################
    # known options
    # --help
    $ref_options->{'CONFIGURED'}{'help'}="TRUE";
    ############################################################
    # set default for --verbose
    $ref_options->{'CONFIGURED'}{'verbose'}="TRUE";
    $ref_options->{'MODIFIER_OPTIONS'}{'verbose'}="TRUE";
    if (defined $ref_options->{'verbose'}){
        $Conf::log_level=$ref_options->{'verbose'}+1;
    }
    $ref_options->{'verbose'}=$Conf::log_level;

    ############################################################
    # set default for --json
    $ref_options->{'CONFIGURED'}{'json'}="TRUE";
    $ref_options->{'MODIFIER_OPTIONS'}{'json'}="TRUE";
    if (not defined $ref_options->{'json'}){
        $ref_options->{'json'}=0;
    }

    ############################################################
    # set default for --info
    $ref_options->{'CONFIGURED'}{'info'}="TRUE";
    if (not defined $ref_options->{'info'}){
       $ref_options->{'info'}=0;
    }

    ############################################################
    # school option is an modifier option
    $ref_options->{'CONFIGURED'}{'school'}="TRUE";
    $ref_options->{'MODIFIER_OPTIONS'}{'school'}="TRUE";

    ############################################################
    # skip-school-creation option is an modifier option
    $ref_options->{'CONFIGURED'}{'skip-school-creation'}="TRUE";
    $ref_options->{'MODIFIER_OPTIONS'}{'skip-school-creation'}="TRUE";

    ############################################################
    # work on SINGLE
    #print STDERR Dumper($ref_options->{'CONFIG'});
    foreach my $sub (keys %{ $ref_options->{'CONFIG'}{'SINGLE'} }){
        my $option_string=$ref_options->{'CONFIG'}{'SINGLE'}{$sub};
	my @options=split(/,/,$option_string);
	foreach my $option (@options){
            $ref_options->{'CONFIGURED'}{$option}="TRUE";
            $ref_options->{'ACTIONS'}{$option}="SINGLE";
        }
    }

    ############################################################
    # work on MAYBE
    foreach my $object (keys %{ $ref_options->{'CONFIG'}{'MAYBE'} }){
	my $option_string=$ref_options->{'CONFIG'}{'MAYBE'}{$object};
	my @options=split(/,/,$option_string);
	 foreach my $option (@options){
	     $tmp{'CONFIG'}{'MAYBE'}{$object}{$option}="config";
             $ref_options->{'CONFIGURED'}{$option}="TRUE";
             #print "OBJECT $object provided by option $option (SINGLE)\n";
	     $tmp{'PROVIDED'}{$object}{'MAYBE'}{$option}="provided";
	 }
    }
 
    ############################################################
    # work on ONE_OF
    foreach my $object (keys %{ $ref_options->{'CONFIG'}{'ONE_OF'} }){
	my $option_string=$ref_options->{'CONFIG'}{'ONE_OF'}{$object};
	my @options=split(/,/,$option_string);
	 foreach my $option (@options){
	     $tmp{'CONFIG'}{'ONE_OF'}{$object}{$option}="config";
             $ref_options->{'CONFIGURED'}{$option}="TRUE";
             #print "OBJECT $object provided by option $option (SINGLE)\n";
	     $tmp{'PROVIDED'}{$object}{'ONE_OF'}{$option}="provided";
	 }
    }
 
    ############################################################
    # work on SOME_OF
    foreach my $object (keys %{ $ref_options->{'CONFIG'}{'SOME_OF'} }){
	my $option_string=$ref_options->{'CONFIG'}{'SOME_OF'}{$object};
	my @options=split(/,/,$option_string);
	 foreach my $option (@options){
	     $tmp{'CONFIG'}{'SOME_OF'}{$object}{$option}="config";
             $ref_options->{'CONFIGURED'}{$option}="TRUE";
             #print "OBJECT $object provided by option $option (SINGLE)\n";
	     $tmp{'PROVIDED'}{$object}{'SOME_OF'}{$option}="provided";
	 }
    }
 
    ############################################################
    # work on ACTION
    foreach my $object (keys %{ $ref_options->{'CONFIG'}{'ACTION'} }){
	my $option_string=$ref_options->{'CONFIG'}{'ACTION'}{$object};
	my @options=split(/,/, $option_string);
	 foreach my $option (@options){
             $ref_options->{'CONFIGURED'}{$option}="TRUE";
             $ref_options->{'ACTIONS'}{$option}="TRUE";
             print "ACTION $option needs object $object\n";
	     foreach my $opt ( keys %{ $tmp{'PROVIDED'}{$object}{'MAYBE'} } ){
                 print "   * Option $option needs MAYBE $opt\n";
	         $ref_options->{'DEPENDENCIES'}{$option}{'MAYBE'}{$opt}="maybe";
	     }
	     foreach my $opt ( keys %{ $tmp{'PROVIDED'}{$object}{'ONE_OF'} } ){
                 print "   * Option $option needs ONE_OF $opt\n";
	         $ref_options->{'DEPENDENCIES'}{$option}{'ONE_OF'}{$opt}="one_of";
	     }
	     foreach my $opt ( keys %{ $tmp{'PROVIDED'}{$object}{'SOME_OF'} } ){
                 print "   * Option $option needs SOME_OF $opt\n";
	         $ref_options->{'DEPENDENCIES'}{$option}{'SOME_OF'}{$opt}="one_of";
	     }
	 }
    }

    ############################################################
    # work option dependencies
    foreach my $option (keys %{ $ref_options->{'CONFIG'}{'DEPENDS'} }){
	my $dependant_string=$ref_options->{'CONFIG'}{'DEPENDS'}{$option};
	my @dependants=split(/,/, $dependant_string);
	foreach my $dependant (@dependants){
            $ref_options->{'DEPENDENCIES'}{$option}{'ALWAYS'}{$dependant}="always";  
	}
    }
    
    #print "tmp_hash:\n";
    #print Dumper (\%tmp);
    #print "options_hash:\n";
    #print Dumper ($ref_options);

    my $action_count=0;
    foreach my $opt_given (keys %{$ref_options}) {
        # go through all option given on command line
	if ($opt_given eq "CONFIG" or
            $opt_given eq "CONFIGURED" or
            $opt_given eq "ACTIONS" or
            $opt_given eq "MODIFIER_OPTIONS" or
            $opt_given eq "DEPENDENCIES" or
            $opt_given eq "RUNTIME" or
            $opt_given eq "SCRIPTNAME"){
            next;
	}
	if (not exists $ref_options->{'CONFIGURED'}{$opt_given}){
	    print "\nWARNING OF UNCONFIGURED OPTION: $opt_given\n\n";
	    $warn_count++;
	} elsif (exists $ref_options->{'MODIFIER_OPTIONS'}{$opt_given}){
	    print "Option $opt_given is a modifier option\n";
	} elsif (exists $ref_options->{'ACTIONS'}{$opt_given}){
	    $action_count++;
	    print "Option $opt_given is an ACTION  option ($ref_options->{'ACTIONS'}{$opt_given})\n";

            # test if single action is the only action
            if ($ref_options->{'ACTIONS'}{$opt_given} eq "SINGLE"){
                foreach my $act (keys %{$ref_options->{'ACTIONS'} }) {
                    if ($act eq $opt_given){
                        next;
                    }
                    if (exists $ref_options->{$act}){
                        print "\nERROR: SINGLE ACTION OPTION $opt_given does not allow other ACTION OPTION $act\n\n";
                        exit;
                    }
                }
            } 

	    # do some dependency tests ???
            foreach my $test (keys %{$ref_options->{'DEPENDENCIES'}{$opt_given} }) {
	        print "Working on $test\n";
                if ($test eq "ALWAYS"){
		    foreach my $dep (keys 
                        %{$ref_options->{'DEPENDENCIES'}{$opt_given}{'ALWAYS'} }) {
			if (not exists $ref_options->{$dep}){
                            print "\nERROR: Option --$dep needed ".
                                  "by option --$opt_given\n\n";
			    exit;
			}
                    }
		} elsif ($test eq "MAYBE"){
		    my $count=0;
                    foreach my $dep_opt (keys 
                        %{$ref_options->{'DEPENDENCIES'}{$opt_given}{$test} }) {
			if (exists $ref_options->{$dep_opt}){
                            # dependant options given
			    $count++;
			}
                    }
                    print "  * $test options tested succesfully ($count)\n";
		} elsif ($test eq "ONE_OF"){
		    my $count=0;
                    foreach my $dep_opt (keys 
                        %{$ref_options->{'DEPENDENCIES'}{$opt_given}{$test} }) {
			if (exists $ref_options->{$dep_opt}){
                            # dependant options given
			    $count++;
			}
                    }
		    if ($count==1){
                        print "  * $test options tested succesfully ($count)\n";
                    } else {
			print "\n";
                        print "ERROR: $opt_given needs ONE ($count found)".
                              " of the following options:\n";
                        foreach my $dep_opt (keys 
			    %{$ref_options->{'DEPENDENCIES'}{$opt_given}{$test} }) {
			    print "   * $dep_opt\n";
			}
			exit;
		    }
		} elsif ($test eq "SOME_OF"){
		    my $count=0;
                    foreach my $dep_opt (keys 
                        %{$ref_options->{'DEPENDENCIES'}{$opt_given}{$test} }) {
			if (exists $ref_options->{$dep_opt}){
                            # dependant options given
			    $count++;
			}
                    }
		    if ($count>0){
                        print "  * $test options tested succesfully ($count)\n";
                    } else {
			print "\n";
                        print "ERROR: $opt_given needs SOME ($count found)".
                              " of the following options:\n";
                        foreach my $dep_opt (keys 
			    %{$ref_options->{'DEPENDENCIES'}{$opt_given}{$test} }) {
			    print "   * $dep_opt\n";
			}
			exit;
		    }
                }		    
            }    
        } else {
	    print "Hmmh. do not know what to do with option $opt_given\n";
	}
    }
    if ($action_count==0){
        # no action defined, switch to info
	print "* forcing info mode\n";
        $ref_options->{'info'}=1;
    }

    print "Option combinations successfully checked\n";
    # delete unneeded stuff
    delete $ref_options->{'DEPENDENCIES'};
    delete $ref_options->{'MAYBE'};
    delete $ref_options->{'CONFIGURED'};
    delete $ref_options->{'CONFIG'};
    delete $ref_options->{'ACTIONS'};
    delete $ref_options->{'SINGLE'};
    delete $ref_options->{'MODIFIER_OPTIONS'};
    if ($warn_count>0){
        print "options_hash:\n";
        print STDERR Dumper ($ref_options);
        print "\nERROR: The options you gave are considered insane/bullshit\n\n";
        print STDERR "\nERROR: The options you gave are considered insane/bullshit\n\n";
        exit 88;
    }
    #exit; # ??????????
}



# dns queries
######################################################################
sub dns_query_ip {
    my ($res,$host)=@_;
    my $reply = $res->search($host);
    if ($reply) {
        foreach my $rr ($reply->answer) {
            next unless $rr->type eq "A";
            return ($rr->address,"IP FOUND");
        }
    } else {
        my $result=$res->errorstring;
        # no reply: query failed
        if ($res->errorstring eq "NOERROR"){
            $result="Query successful, but no entry for ".$host." (".$res->errorstring.")";
        }
        return ($result,$res->errorstring);
    }
}



# LANG stuff
######################################################################
sub get_lang_from_config {
    my ($school,$ref_sophomorix_config)=@_;
    my $lang;
    if (exists $ref_sophomorix_config->{'SCHOOLS'}{$school}{'LANG'}){
        $lang=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'LANG'}
    } elsif (exists $ref_sophomorix_config->{'GLOBAL'}{'LANG'}) {
        $lang=$ref_sophomorix_config->{'GLOBAL'}{'LANG'};
    } else {
        print "\nERROR: Could not determine a language\n\n";
        exit 88;
    }
    return $lang;
}



# latex stuff
######################################################################
sub string_to_latex { # old name: latexize_string
    # make string usable by latex (convert)
    my ($string) = @_;

    my $string_logical_chars = decode("utf8", $string); # decode in logical chars, to split by char, not byte
    $latex_string  = latex_encode($string_logical_chars);

    # not sure if the following line is needed
    $latex_string = encode("utf8", $latex_string); # encode back into utf8

    return $latex_string;

    # # own replacements, before usung module
    # #replace existing \   with   \textbackslash{}
    # $string=~s/\\/\\textbackslash\{\}/g;

    # # here a \ added again as escape characters:
    # #replace  _   with   \_
    # $string=~s/_/\\_/g;
    # #replace  $   with   \$
    # $string=~s/\$/\\\$/g;
    # #replace  #   with   \#
    # $string=~s/\#/\\\#/g;
    # #replace  &   with   \&
    # $string=~s/\&/\\\&/g;
    # #replace  %   with   \%
    # $string=~s/\%/\\\%/g;
    # #replace  {   with   \{
    # $string=~s/\{/\\\{/g;
    # #replace  }   with   \}
    # $string=~s/\}/\\\}/g;
    # # [] seem to work
    # return $string; 
}



# string
############################################################
sub append_dollar {
    my ($string)=@_;
    if ($string=~m/\$$/){
        # OK, ends with \$
    } else {
        # append $
        $string=$string."\$";
    }
    return $string;
}



sub detach_dollar {
    my ($string)=@_;
    if ($string=~m/\$$/){
        # detach $
        $string=~s/\$$//;
    } else {
        # OK, no $ at the end
    }
    return $string;
}



sub read_encoding_data {
    my %encoding_data=();
    foreach my $enc_to_check ( @DevelConf::enc_to_check ){
        push @{ $encoding_data{'TO_CHECK'} }, $enc_to_check;

        $encoding_data{'DATAFILES'}{'FIRSTNAMES'}{$enc_to_check}=
            ${DevelConf::path_encoding_data}."/firstnames.".$enc_to_check.".txt";
        $encoding_data{'DATAFILES'}{'LASTNAMES'}{$enc_to_check}=
            ${DevelConf::path_encoding_data}."/lastnames.".$enc_to_check.".txt";
        $encoding_data{'DATAFILES'}{'FIRSTNAME_ERRORS'}{$enc_to_check}=
            ${DevelConf::path_encoding_data}."/firstname_errors.".$enc_to_check.".txt";
        $encoding_data{'DATAFILES'}{'LASTNAME_ERRORS'}{$enc_to_check}=
            ${DevelConf::path_encoding_data}."/lastname_errors.".$enc_to_check.".txt";
    }

    # firstnames
    foreach my $enc (keys %{ $encoding_data{'DATAFILES'}{'FIRSTNAMES'} }) {
        my $file_abs=$encoding_data{'DATAFILES'}{'FIRSTNAMES'}{$enc};
        open(DATAFILE, "$file_abs") ||
             die "Error: $! $file_abs not found!";
        while (<DATAFILE>){
            chomp();
            s/^ //g; # remove spaces oat beginning of line
            if(/^\#/){ # ignore commented lines
               next;
	    }
            if($_ eq ""){
                next;
            }
            my ($first,$first_new) = split(/:/);
            $encoding_data{'FIRSTNAME_DATA'}{$enc}{$first}=0;
        }
        if($Conf::log_level>=3){
            print "   Reading $file_abs for encoding: $enc\n";
        }
        close(DATAFILE);
    }

    # firstname errors
    foreach my $enc (keys %{ $encoding_data{'DATAFILES'}{'FIRSTNAME_ERRORS'} }) {
        my $file_abs=$encoding_data{'DATAFILES'}{'FIRSTNAME_ERRORS'}{$enc};
        open(DATAFILE, "$file_abs") ||
             die "Error: $! $file_abs not found!";
        while (<DATAFILE>){
             chomp();
            s/^ //g; # Leerzeichen am Zeilenangfang entfernen
            if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
                next;
            }
            if($_ eq ""){
                next;
            }
            my ($error,$message) = split(/:/);
            $message=~s/^\s+ //g;
            $encoding_data{'FIRSTNAME_ERRORS'}{$enc}{$error}=$message;
        }
        if($Conf::log_level>=3){
            print "   Reading $file_abs for errors: $enc\n";
        }
        close(DATAFILE);
    }

    # lastnames
    foreach my $enc (keys %{ $encoding_data{'DATAFILES'}{'LASTNAMES'} }) {
        my $file_abs=$encoding_data{'DATAFILES'}{'LASTNAMES'}{$enc};
        open(DATAFILE, "$file_abs") ||
             die "Error: $! $file_abs not found!";
        while (<DATAFILE>){
            chomp();
            s/^ //g; # Leerzeichen am Zeilenangfang entfernen
            if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
               next;
	    }
            if($_ eq ""){
                next;
            }
            my ($last,$last_new) = split(/:/);
            $encoding_data{'LASTNAME_DATA'}{$enc}{$last}=0;
        }
        if($Conf::log_level>=3){
            print "   Reading $file_abs for encoding: $enc\n";
        }
        close(DATAFILE);
    }

    # lastname errors
    foreach my $enc (keys %{ $encoding_data{'DATAFILES'}{'LASTNAME_ERRORS'} }) {
        my $file_abs=$encoding_data{'DATAFILES'}{'LASTNAME_ERRORS'}{$enc};
        open(DATAFILE, "$file_abs") ||
             die "Error: $! $file_abs not found!";
        while (<DATAFILE>){
            chomp();
            s/^ //g; # Leerzeichen am Zeilenangfang entfernen
            if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
               next;
	    }
            if($_ eq ""){
                next;
            }
            my ($error,$message) = split(/:/);
            $message=~s/^\s+ //g;
            $encoding_data{'LASTNAME_ERRORS'}{$enc}{$error}=$message;
        }
        if($Conf::log_level>=3){
            print "   Reading $file_abs for errors: $enc\n";
        }
        close(DATAFILE);
    }
    return \%encoding_data;
}



sub analyze_encoding {
    my ($file,
        $file_tmp,
        $show_special_char_lines,
        $non_umlaut,
        $ref_encoding_data,
        $ref_encoding_check_results,
        $ref_sophomorix_config,
        $ref_sophomorix_result)=@_;
    # $file ist for printout and path in config hash only
    # $file_tmp will be analyzed
    my $filename = basename($file);
    my $filename_tmp = basename($file_tmp);
    my $nonstandard_name_count=0;

    foreach my $enc (@{ $ref_encoding_data->{'TO_CHECK'} }){
        $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{$enc}=0;
        $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_errors'}{$enc}=0;
        $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{$enc}=0;
        $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_errors'}{$enc}=0;
    }
    $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{'none'}=0;
    $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_errors'}{'none'}=0;
    $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{'none'}=0;
    $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_errors'}{'none'}=0;
    $ref_encoding_check_results->{$file}{'RESULT'}="unknown";

    # start to analyze file_tmp
    if($Conf::log_level>=2){
        &Sophomorix::SophomorixBase::print_title("Encode-analyze $filename_tmp","slim");
    }
    open(DATAFILE, "$file_tmp") ||
         die "Error: $! $file_tmp not found!";
    my $count=0;
    while (<DATAFILE>){
        $count++;
        chomp();
        s/^ //g; # Leerzeichen am Zeilenangfang entfernen
        if(/^\#/){ # # am Anfang bedeutet Kommentarzeile
            next;
        }
        if ($_ eq ""){ # ignore empty line
            next;
        }

        ####################################
        if ($show_special_char_lines==1){
            if ($_=~/[^a-zA-Z0-9\-\.;_\/\s]/) {
                push @{ $ref_encoding_check_results->{$file}{'SPECIAL_CHAR_LINES'} }, "Line ".$count.":  ".$_;
                push @special_char_lines, "Line ".$count."   ".$_;
                $ref_encoding_check_results->{$file}{'SPECIAL_CHAR_LINES_NUMBERED'}{$count}=$_;
                #$special_char_lines{$count}=$line;
            }
        }

        my $line=$_;
        chomp($line);
        my $semikolon_count=$line=~tr/;//;
        if ($semikolon_count<3){
            &log_script_exit("$filename: Not 3 Semicolons in $line",1,1,0,
                     \@arguments,\%sophomorix_result,$ref_sophomorix_config,$json);
        }

        # add trailing ; if not there
        if (not $line=~m/;$/){
            $line=$line.";";
        }
        my ($class,$lastname,$firstname,$date) = split(/;/);

        # firstname
        # split firstname-field into single firstnames
        # split at 'space' and '-'
        $firstname=&remove_embracing_whitespace($firstname);
        my @firstnames=split(/[ ,-]/, $firstname); # split for double names
        foreach my $first (@firstnames){
            # ASCII Test
            if ($first=~/[^a-zA-Z0-9\-_'.]/) {
                $nonstandard_name_count++; 
                # continue with non-standard(~non-ascii) chars
                my $hit_count=0;
                my $error_count=0;
                foreach my $enc (@{ $ref_encoding_data->{'TO_CHECK'} }){
                    my $conv = Text::Iconv->new($enc,"utf8");
                    my $first_utf8 = $conv->convert($first);
                    # check for positive hits (known, valid firstnames)
                    if (exists $ref_encoding_data->{FIRSTNAME_DATA}{$enc}{$first}){
		       
                        # remember hits
	                push @{ $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'data_hits'} },
                                { first => "$first",
                                  first_utf8 => "$first_utf8",
                                  line => "$_"};
                        # count hits
                        my $old=$ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{$enc};
                        my $new=$old+1;
                        $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{$enc}=$new;
                        $hit_count++;
                    }
                    # check for errors
                    if (exists $ref_encoding_data->{FIRSTNAME_ERRORS}{$enc}{$first}){
                        # remember errors
	                push @{ $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'data_errors'} },
                                { first => "$first",
                                  first_utf8 => "$first_utf8",
                                  line => "$_"};
                        # count errors
                        my $old=$ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_errors'}{$enc};
                        my $new=$old+1;
                        $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_errors'}{$enc}=$new;
                        $hit_count++;
                    }
                }
                # non-hits and non-errors (unknown firstnames)
                if ($hit_count==0 and $error_count==0){
                    # remember unknown names
                    push @{ $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'data_unknown'} },
                           { first => "$first",
                             line => "$_"};
                    # count unknown names
                    my $old=$ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{'none'};
                    my $new=$old+1;
                    $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{'none'}=$new;
		    $ref_sophomorix_result->{'FILES'}{$file}{'UNKNOWN_FIRSTNAMES'}{$first}="LINE $count";
                }
            }
        }

        # lastname
        # split lastname-field into single lastnames
        # split at 'space' and '-'
        $lastname=&remove_embracing_whitespace($lastname);
        my @lastnames=split(/[ ,-]/, $lastname); # split for double names
        foreach my $last (@lastnames){
            # ASCII Test
            if ($last=~/[^a-zA-Z0-9\-_'.]/) {
                $nonstandard_name_count++;
                # continue with non-standard(~non-ascii) chars
                my $hit_count=0;
                my $error_count=0;
                foreach my $enc (@{ $ref_encoding_data->{'TO_CHECK'} }){
                    my $conv = Text::Iconv->new($enc,"utf8");
                    my $last_utf8 = $conv->convert($last);

                    # check for positive hits (known, valid firstnames)
                    if (exists $ref_encoding_data->{LASTNAME_DATA}{$enc}{$last}){
                        # remember hits
	                push @{ $ref_encoding_check_results->{$file}{'LASTNAMES'}{'data_hits'} },
                                { last => "$last",
                                  last_utf8 => "$last_utf8",
                                  line => "$_"};
                        # count hits
                        my $old=$ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{$enc};
                        my $new=$old+1;
                        $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{$enc}=$new;
                        $hit_count++;
                    }
                    # check for errors
                    if (exists $ref_encoding_data->{LASTNAME_ERRORS}{$enc}{$last}){
                        # remember errors
	                push @{ $ref_encoding_check_results->{$file}{'LASTNAMES'}{'data_errors'} },
                                { last => "$last",
                                  last_utf8 => "$last_utf8",
                                  line => "$_"};
                        # count errors
                        my $old=$ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_errors'}{$enc};
                        my $new=$old+1;
                        $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_errors'}{$enc}=$new;
                        $hit_count++;
                    }
                }
                # non-hits and non-errors (unknown lastnames)
                if ($hit_count==0 and $error_count==0){
                    # remember unknown names
                    push @{ $ref_encoding_check_results->{$file}{'LASTNAMES'}{'data_unknown'} },
                           { last => "$last",
                             line => "$_"};
                    # count unknown names
                    my $old=$ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{'none'};
                    my $new=$old+1;
                    $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{'none'}=$new;
		    $ref_sophomorix_result->{'FILES'}{$file}{'UNKNOWN_LASTNAMES'}{$last}="LINE $count";
                }
            }
        }
    }

    # calculate sum of hits
    my $oldsum=0;
    foreach my $enc (@{ $ref_encoding_data->{'TO_CHECK'} }){
        my $sum=
            $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{$enc}+
	    $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_errors'}{$enc}+
            $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{$enc}+
	    $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_errors'}{$enc};
        $ref_encoding_check_results->{$file}{'TOTAL_POINTS'}{$enc}=$sum;
        if($sum > $oldsum){
            $ref_encoding_check_results->{$file}{'RESULT'}=$enc;
        }
    }

    # calculate result
    if ($nonstandard_name_count==0){
        # none non ascii names encountered -> treat as UTF8 for convenience
        $ref_encoding_check_results->{$file}{'RESULT'}="UTF8";
        $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'ENCODING_CHECKED'}="UTF8";
        $ref_encoding_check_results->{$file}{'SURE'}="TRUE";
	$ref_sophomorix_result->{'FILES'}{$file}{'SURE'}="TRUE";
    } else {
        # test if result is sure (TRUE/FALSE)
        my $enc_nonzero=0;
         foreach my $enc (@{ $ref_encoding_data->{'TO_CHECK'} }){
	    if ($ref_encoding_check_results->{$file}{'TOTAL_POINTS'}{$enc}>0){
	        $enc_nonzero++;
	    }
        }

        if ($enc_nonzero==1){
            $ref_encoding_check_results->{$file}{'SURE'}="TRUE";
  	    $ref_sophomorix_result->{'FILES'}{$file}{'SURE'}="TRUE";
        } else {
            # more than one encoding has matches
            #print Dumper ($ref_encoding_check_results);
            if ($ref_encoding_check_results->{$file}{'RESULT'} eq "UTF8"){
                # utf8 must be 100% correct
                $ref_encoding_check_results->{$file}{'SURE'}="FALSE";
  	        $ref_sophomorix_result->{'FILES'}{$file}{'SURE'}="FALSE";
            } else {
                # save results in shor name vars
                $win_1252_first=$ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{'WINDOWS-1252'};
                $win_1252_first_err=$ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_errors'}{'WINDOWS-1252'};
                $win_1252_last=$ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{'WINDOWS-1252'};
                $win_1252_last_err=$ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_errors'}{'WINDOWS-1252'};

                $iso8859_1_first=$ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{'ISO_8859-1'};
                $iso8859_1_first_err=$ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_errors'}{'ISO_8859-1'};
                $iso8859_1_last=$ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{'ISO_8859-1'};
                $iso8859_1_last_err=$ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_errors'}{'ISO_8859-1'};

                # one encoding wins, if it wins/equals in all 4 categories
                if ($win_1252_first >= $iso8859_1_first and
                    $win_1252_first_err >= $iso8859_1_first_err and
                    $win_1252_last >= $iso8859_1_last and
                    $win_1252_last_err >= $iso8859_1_last_err
                   ) {
                       $ref_encoding_check_results->{$file}{'SURE'}="TRUE";
      	               $ref_sophomorix_result->{'FILES'}{$file}{'SURE'}="TRUE";
                } elsif ($iso8859_1_first >= $win_1252_first and
                         $iso8859_1_first_err >= $win_1252_first_err and
                         $iso8859_1_last >= $win_1252_last and
                         $iso8859_1_last_err >= $win_1252_last_err
	     	        ){
                            $ref_encoding_check_results->{$file}{'SURE'}="TRUE";
      	                    $ref_sophomorix_result->{'FILES'}{$file}{'SURE'}="TRUE";
                } else {
                    $ref_encoding_check_results->{$file}{'SURE'}="FALSE";
      	            $ref_sophomorix_result->{'FILES'}{$file}{'SURE'}="FALSE";

	        }
            }
        }

        # save result in config hash
        $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename}{'ENCODING_CHECKED'}=
	     $ref_encoding_check_results->{$file}{'RESULT'};
	$ref_sophomorix_result->{'FILES'}{$file}{'ENCODING_CHECKED'}=$ref_encoding_check_results->{$file}{'RESULT'};
    }
    if($Conf::log_level>=2){
        print "$file_tmp --> $ref_encoding_check_results->{$file}{'RESULT'}\n";
    }

    if ($show_special_char_lines==1){
        my $count=0;
        print "\n";
        &print_title("Special char lines in $filename (utf8-encoded):");
	foreach my $line ( @{ $ref_encoding_check_results->{$file}{'SPECIAL_CHAR_LINES'} } ){
            my $conv = Text::Iconv->new($ref_encoding_check_results->{$file}{'RESULT'},"utf8");
            my $line_utf8 = $conv->convert($line);
            if ($non_umlaut==1){
                # äöüÄÖÜß works because its unicode
                if ($line_utf8=~/[^äöüÄÖÜßa-zA-Z0-9\-\.;_\/\s]/) { 
                    $count++;
                    print "$count)  $line_utf8\n";
                }
            } else {
                    $count++;
                    print "$count)  $line_utf8\n";
            }
        }
        print "\n";
    }

    return ($ref_encoding_check_results->{$file}{'RESULT'},$ref_encoding_check_results);
}



sub print_analyzed_encoding {
    my ($file,$ref_encoding_check_results,$ref_encoding_data) = @_;
    my $line1="================================================================================\n";
    my $line2="--------------------------------------------------------------------------------\n";
    my $line3="+------------------------------------------------------------------------------+\n";
    print "\nEncoding check result for:\n";
    print "   $file\n";

    # print valid firstnames
    if($Conf::log_level>=2){
        print "\nValid firstnames: ",
              "($ref_encoding_check_results->{$file}{'RESULT'} ---> utf8)\n";
        print $line1;
        foreach my $item ( @{ $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'data_hits'} } ){
            printf  "%-20s %-12s %-20s\n",
                    $item->{first},
                    "--->",
                    $item->{first_utf8};
        }
        print $line2;
    }
    # print valid lastnames
    if($Conf::log_level>=2){
        print "\nValid lastnames: ",
              "($ref_encoding_check_results->{$file}{'RESULT'} ---> utf8)\n";
        print $line1;
        foreach my $item ( @{ $ref_encoding_check_results->{$file}{'LASTNAMES'}{'data_hits'} } ){
            printf  "%-20s %-12s %-20s\n",
                    $item->{last},
                    "--->",
                    $item->{last_utf8};
        }
        print $line2;
    }

    # print unknown firstnames
    if ($#{ $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'data_unknown'} } > -1 or $Conf::log_level>=2){
        print "\n ";
        print "Unknown firstnames (Please report to info\@linuxmuster.net):\n";
        print $line3;
        foreach my $item ( @{ $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'data_unknown'} } ){
            printf  "| %-40s |\n", $item->{first},
        }
        print $line3;
    }

    #  print firstnames with errors
    if ($#{ $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'data_errors'} } > -1 or $Conf::log_level>=2){
        print "\nFirstnames that should be an error (Please report the the School Office):\n";
        print $line3;
        foreach my $item ( @{ $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'data_errors'} } ){
            printf  "| %-15s%-63s|\n",
                    $item->{first_utf8},
                    $item->{line};
            my $enc_result=$ref_encoding_check_results->{$file}{'RESULT'};
            printf  "|          ---> %-63s|\n",$ref_encoding_data->{'FIRSTNAME_ERRORS'}{$enc_result}{ $item->{'first'} };
            print $line3;
        }
    }

    # print unknown lastnames
    if ($#{ $ref_encoding_check_results->{$file}{'LASTNAMES'}{'data_unknown'} } > -1 or $Conf::log_level>=2){
        print "\n";
        print "Unknown lastnames (Please report to info\@linuxmuster.net):\n";
        print $line3;
        foreach my $item ( @{ $ref_encoding_check_results->{$file}{'LASTNAMES'}{'data_unknown'} } ){
            printf  "| %-40s |\n", $item->{last},
        }
        print $line3;
    }

    #  print lastnames with errors
    if ($#{ $ref_encoding_check_results->{$file}{'LASTNAMES'}{'data_errors'} } > -1 or $Conf::log_level>=2){
        print "\nLastnames that should be an error (Please report the the School Office):\n";
        print $line3;
        foreach my $item ( @{ $ref_encoding_check_results->{$file}{'LASTNAMES'}{'data_errors'} } ){
            printf  "| %-15s%-63s|\n",
                    $item->{last_utf8},
                    $item->{line};
            my $enc_result=$ref_encoding_check_results->{$file}{'RESULT'};
            printf  "|          ---> %-63s|\n",$ref_encoding_data->{'LASTNAME_ERRORS'}{$enc_result}{ $item->{'last'} };
            print $line3;
        }
    }

    # print debug dump
    if($Conf::log_level>=3){
        print "\n";
        print "Dump of \$ref_encoding_check_results:\n";
        print Dumper($ref_encoding_check_results);
    }

    # Print Result
    print "\n";
    print "                      +-----------------+-----------------+         \n";
    print "                      |    firstname    |     surname     |         \n";
    print "+---------------------+--------+--------+--------+--------+--------+\n";
    printf  "| %-20s|%7s |%7s |%7s |%7s |%7s |\n",
            "Tested Encodings:",
            "Hits",
            "Errors",
            "Hits",
            "Errors",
            "Sum";
    print "+---------------------+--------+--------+--------+--------+--------+\n";
#    foreach my $enc (@encodings_to_check){
    foreach my $enc ( @{ $ref_encoding_data->{'TO_CHECK'} }){
        printf  "| %-20s|%7s |%7s |%7s |%7s |%7s |\n",
                $enc,
                $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{$enc},
                $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_errors'}{$enc},
                $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{$enc},
                $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_errors'}{$enc},
   	        $ref_encoding_check_results->{$file}{'TOTAL_POINTS'}{$enc};# ?????????
    }
    print "+---------------------+--------+--------+--------+--------+--------+\n";
    printf  "| %-20s|%7s |%7s |%7s |%7s |%7s |\n",
            "none of the above",
            $ref_encoding_check_results->{$file}{'FIRSTNAMES'}{'count_hits'}{'none'},
            "-",
            $ref_encoding_check_results->{$file}{'LASTNAMES'}{'count_hits'}{'none'},
            "-",
            "-";
    print "+---------------------+--------+--------+--------+--------+--------+\n";
    print "$file:\n",
          "    File-Encoding is $ref_encoding_check_results->{$file}{'RESULT'}".
          " (Sureness: $ref_encoding_check_results->{$file}{'SURE'})\n"; 
    print "\n";
    close(DATAFILE);
}



# encoding, recoding stuff
######################################################################
sub recode_utf8_to_ascii {
    my ($string) = @_;
    # ascii (immer filtern)
    # '
    $string=~s/\x27//g;
    $string=~s/\x60//g;
    # -
    $string=~s/\x2D/-/g;
    $string=~s/\x5F/-/g;

    # utf8
    # -
    $string=~s/\xC2\xAF/-/g;
    # '
    $string=~s/\xC2\xB4//g;

    # iso 8859-1 stuff
    # A
    $string=~s/\xC3\x80/A/g;
    $string=~s/\xC3\x81/A/g;
    $string=~s/\xC3\x82/A/g;
    $string=~s/\xC3\x83/A/g;
    $string=~s/\xC3\x85/A/g;
    # Ae
    $string=~s/\xC3\x84/Ae/g;
    $string=~s/\xC3\x86/Ae/g;
    # C
    $string=~s/\xC3\x87/C/g;
    # E
    $string=~s/\xC3\x88/E/g;
    $string=~s/\xC3\x89/E/g;
    $string=~s/\xC3\x8A/E/g;
    $string=~s/\xC3\x8B/E/g;
    # I
    $string=~s/\xC3\x8C/I/g;
    $string=~s/\xC3\x8D/I/g;
    $string=~s/\xC3\x8E/I/g;
    $string=~s/\xC3\x8F/I/g;
    # D
    $string=~s/\xC3\x90/D/g;
    # I
    $string=~s/\xC3\x91/N/g;
    # O
    $string=~s/\xC3\x92/O/g;
    $string=~s/\xC3\x93/O/g;
    $string=~s/\xC3\x94/O/g;
    $string=~s/\xC3\x95/O/g;
    $string=~s/\xC3\x98/O/g;
    # Oe
    $string=~s/\xC3\x96/Oe/g;
    # X
    $string=~s/\xC3\x97/x/g;
    # U
    $string=~s/\xC3\x99/U/g;
    $string=~s/\xC3\x9A/U/g;
    $string=~s/\xC3\x9B/U/g;
    # Ue
    $string=~s/\xC3\x9C/Ue/g;
    # Y
    $string=~s/\xC3\x9D/Y/g;
    # Th
    $string=~s/\xC3\x9E/Th/g;
    # ss
    $string=~s/\xC3\x9F/ss/g;
    # a
    $string=~s/\xC3\xA0/a/g;
    $string=~s/\xC3\xA1/a/g;
    $string=~s/\xC3\xA2/a/g;
    $string=~s/\xC3\xA3/a/g;
    $string=~s/\xC3\xA5/a/g;
    # ae
    $string=~s/\xC3\xA4/ae/g;
    $string=~s/\xC3\xA6/ae/g;
    # c
    $string=~s/\xC3\xA7/c/g;
    # e
    $string=~s/\xC3\xA8/e/g;
    $string=~s/\xC3\xA9/e/g;
    $string=~s/\xC3\xAA/e/g;
    $string=~s/\xC3\xAB/e/g;
    # i
    $string=~s/\xC3\xAC/i/g;
    $string=~s/\xC3\xAD/i/g;
    $string=~s/\xC3\xAE/i/g;
    $string=~s/\xC3\xAF/i/g;
    # d
    $string=~s/\xC3\xB0/d/g;
    # n
    $string=~s/\xC3\xB1/n/g;
    # o
    $string=~s/\xC3\xB2/o/g;
    $string=~s/\xC3\xB3/o/g;
    $string=~s/\xC3\xB4/o/g;
    $string=~s/\xC3\xB5/o/g;
    # \xC3\xB7 is DIVISION SIGN
    # o
    $string=~s/\xC3\xB8/o/g;
    # oe
    $string=~s/\xC3\xB6/oe/g;
    # u
    $string=~s/\xC3\xB9/u/g;
    $string=~s/\xC3\xBA/u/g;
    $string=~s/\xC3\xBB/u/g;
    # ue
    $string=~s/\xC3\xBC/ue/g;
    # y
    $string=~s/\xC3\xBD/y/g;
    $string=~s/\xC3\xBF/y/g;
    # FE thorn
    $string=~s/\xC3\xBE/th/g;
    # iso 8859-1 stuff end
   
    # \xc4 stuff (U+0100)
    $string=~s/\xC4\x80/A/g;
    $string=~s/\xC4\x81/a/g;
    $string=~s/\xC4\x82/A/g;
    $string=~s/\xC4\x83/a/g;
    $string=~s/\xC4\x84/A/g;
    $string=~s/\xC4\x85/a/g;
    $string=~s/\xC4\x86/C/g;
    $string=~s/\xC4\x87/c/g;
    $string=~s/\xC4\x88/C/g;
    $string=~s/\xC4\x89/c/g;
    $string=~s/\xC4\x8A/C/g;
    $string=~s/\xC4\x8B/c/g;
    $string=~s/\xC4\x8C/C/g;
    $string=~s/\xC4\x8D/c/g;
    $string=~s/\xC4\x8E/D/g;
    $string=~s/\xC4\x8F/d/g;
    $string=~s/\xC4\x90/D/g;
    $string=~s/\xC4\x91/d/g;
    $string=~s/\xC4\x92/E/g;
    $string=~s/\xC4\x93/e/g;
    $string=~s/\xC4\x94/E/g;
    $string=~s/\xC4\x95/e/g;
    $string=~s/\xC4\x96/E/g;
    $string=~s/\xC4\x97/e/g;
    $string=~s/\xC4\x98/E/g;
    $string=~s/\xC4\x99/e/g;
    $string=~s/\xC4\x9A/E/g;
    $string=~s/\xC4\x9B/e/g;
    $string=~s/\xC4\x9C/G/g;
    $string=~s/\xC4\x9D/g/g;
    $string=~s/\xC4\x9E/G/g;
    $string=~s/\xC4\x9F/g/g;
    $string=~s/\xC4\xA0/G/g;
    $string=~s/\xC4\xA1/g/g;
    $string=~s/\xC4\xA2/G/g;
    $string=~s/\xC4\xA3/g/g;
    $string=~s/\xC4\xA4/H/g;
    $string=~s/\xC4\xA5/h/g;
    $string=~s/\xC4\xA6/H/g;
    $string=~s/\xC4\xA7/h/g;
    $string=~s/\xC4\xA8/I/g;
    $string=~s/\xC4\xA9/i/g;
    $string=~s/\xC4\xAA/I/g;
    $string=~s/\xC4\xAB/i/g;
    $string=~s/\xC4\xAC/I/g;
    $string=~s/\xC4\xAD/i/g;
    $string=~s/\xC4\xAE/I/g;
    $string=~s/\xC4\xAF/i/g;
    $string=~s/\xC4\xB0/I/g;
    $string=~s/\xC4\xB1/i/g;
    $string=~s/\xC4\xB2/Ij/g;
    $string=~s/\xC4\xB3/ij/g;
    $string=~s/\xC4\xB4/J/g;
    $string=~s/\xC4\xB5/j/g;
    $string=~s/\xC4\xB6/K/g;
    $string=~s/\xC4\xB7/k/g;
    $string=~s/\xC4\xB8/k/g;
    $string=~s/\xC4\xB9/L/g;
    $string=~s/\xC4\xBA/l/g;
    $string=~s/\xC4\xBB/L/g;
    $string=~s/\xC4\xBC/l/g;
    $string=~s/\xC4\xBD/L/g;
    $string=~s/\xC4\xBE/l/g;
    $string=~s/\xC4\xBF/L/g;

    # \xc5 stuff (U+0140)
    $string=~s/\xC5\x80/l/g;
    $string=~s/\xC5\x81/L/g;
    $string=~s/\xC5\x82/l/g;
    $string=~s/\xC5\x83/N/g;
    $string=~s/\xC5\x84/n/g;
    $string=~s/\xC5\x85/N/g;
    $string=~s/\xC5\x86/n/g;
    $string=~s/\xC5\x87/N/g;
    $string=~s/\xC5\x88/n/g;
    $string=~s/\xC5\x89/n/g;
    $string=~s/\xC5\x8A/N/g;
    $string=~s/\xC5\x8B/n/g;
    $string=~s/\xC5\x8C/O/g;
    $string=~s/\xC5\x8D/o/g;
    $string=~s/\xC5\x8E/O/g;
    $string=~s/\xC5\x8F/o/g;
    $string=~s/\xC5\x90/O/g;
    $string=~s/\xC5\x91/o/g;
    $string=~s/\xC5\x92/Oe/g;
    $string=~s/\xC5\x93/oe/g;
    $string=~s/\xC5\x94/R/g;
    $string=~s/\xC5\x95/r/g;
    $string=~s/\xC5\x96/R/g;
    $string=~s/\xC5\x97/r/g;
    $string=~s/\xC5\x98/R/g;
    $string=~s/\xC5\x99/r/g;
    $string=~s/\xC5\x9A/S/g;
    $string=~s/\xC5\x9B/s/g;
    $string=~s/\xC5\x9C/S/g;
    $string=~s/\xC5\x9D/s/g;
    $string=~s/\xC5\x9E/S/g;
    $string=~s/\xC5\x9F/s/g;
    $string=~s/\xC5\xA0/S/g;
    $string=~s/\xC5\xA1/s/g;
    $string=~s/\xC5\xA2/T/g;
    $string=~s/\xC5\xA3/t/g;
    $string=~s/\xC5\xA4/T/g;
    $string=~s/\xC5\xA5/t/g;
    $string=~s/\xC5\xA6/T/g;
    $string=~s/\xC5\xA7/t/g;
    $string=~s/\xC5\xA8/U/g;
    $string=~s/\xC5\xA9/u/g;
    $string=~s/\xC5\xAA/U/g;
    $string=~s/\xC5\xAB/u/g;
    $string=~s/\xC5\xAC/U/g;
    $string=~s/\xC5\xAD/u/g;
    $string=~s/\xC5\xAE/U/g;
    $string=~s/\xC5\xAF/u/g;
    $string=~s/\xC5\xB0/U/g;
    $string=~s/\xC5\xB1/ue/g;
    $string=~s/\xC5\xB2/U/g;
    $string=~s/\xC5\xB3/u/g;
    $string=~s/\xC5\xB4/W/g;
    $string=~s/\xC5\xB5/w/g;
    $string=~s/\xC5\xB6/Y/g;
    $string=~s/\xC5\xB7/y/g;
    $string=~s/\xC5\xB8/Y/g;
    $string=~s/\xC5\xB9/Z/g;
    $string=~s/\xC5\xBA/z/g;
    $string=~s/\xC5\xBB/Z/g;
    $string=~s/\xC5\xBC/z/g;
    $string=~s/\xC5\xBD/Z/g;
    $string=~s/\xC5\xBE/z/g;
    $string=~s/\xC5\xBF/s/g;
    $string=~s/\xC6\x80/b/g;
    $string=~s/\xC6\x81/B/g;
    $string=~s/\xC6\x82/B/g;
    $string=~s/\xC6\x83/b/g;
    # not a letter
    $string=~s/\xC6\x84/6/g;
    # not a letter
    $string=~s/\xC6\x85/6/g;
    $string=~s/\xC6\x86/O/g;
    $string=~s/\xC6\x87/C/g;
    $string=~s/\xC6\x88/c/g;
    $string=~s/\xC6\x89/D/g;
    $string=~s/\xC6\x8A/D/g;
    $string=~s/\xC6\x8B/D/g;
    $string=~s/\xC6\x8C/d/g;
    $string=~s/\xC6\x8D/d/g;
    $string=~s/\xC6\x8E/E/g;
    # grosses Schwa
    $string=~s/\xC6\x8F/E/g;
    # ?????? continue here
    return $string;
}


######################################################################
# END OF FILE
# Return true=1
1;
