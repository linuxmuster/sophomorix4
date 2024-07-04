#!/usr/bin/perl -w
# This perl module SophomorixSambaAD is maintained by Rüdiger Beck
# It is Free Software (License GPLv3)
# If you find errors, contact the author
# jeffbeck@web.de  or  jeffbeck@linuxmuster.net

package Sophomorix::SophomorixSambaAD;
require Exporter;
#use File::Basename;
use Unicode::Map8;
use Unicode::String qw(utf16);
use Net::LDAP;
use Net::LDAP::Control::Sort;
use Net::LDAP::SID;
use List::MoreUtils qw(uniq);
use File::Basename;
use Math::Round;
use Data::Dumper;
use MIME::Base64;
use Socket;

# for smb://
use POSIX;
use Filesys::SmbClient;

$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1; 

@ISA = qw(Exporter);

@EXPORT_OK = qw( );
@EXPORT = qw(
            AD_get_passwd
            AD_get_unicodepwd
            AD_set_unicodepwd
            AD_bind_admin
            AD_unbind_admin
            AD_get_sessions
            AD_session_manage
            AD_user_set_exam_mode
            AD_user_unset_exam_mode
            AD_user_create
            AD_user_update
            AD_user_getquota_usage
            AD_user_setquota
            AD_get_user
            AD_get_user_return_hash
            AD_get_group
            AD_computer_create
            AD_computer_kill
            AD_computer_update
            AD_user_move
            AD_user_kill
            AD_remove_sam_from_sophomorix_attributes
            AD_group_create
            AD_group_kill
            AD_group_addmember
            AD_group_addmember_management
            AD_group_removemember
            AD_rolegroup_update
            AD_group_update
            AD_group_list
            AD_get_schoolname
            AD_get_name_tokened
            AD_ou_create
            AD_school_create
            AD_object_search
            AD_get_AD_for_repair
            AD_get_AD_for_check
            AD_get_AD_for_device
            AD_check_ui
            AD_create_new_mail
            AD_create_new_webui_string
            AD_get_quota
            AD_smbcquotas_queryuser
            AD_get_examusers
            AD_get_users_v
            AD_get_groups_v
            AD_get_shares_v
            AD_get_full_userdata
            AD_get_full_devicedata
            AD_get_full_groupdata
            AD_get_printdata
            AD_get_schema
            AD_class_fetch
            AD_project_fetch
            AD_sophomorix_group_fetch
            AD_dn_fetch_multivalue
            AD_project_sync_members
            AD_object_move
            AD_debug_logdump
            AD_login_test
            AD_dns_get
            AD_dns_nodecreate_update
            AD_dns_zonecreate
            AD_dns_kill
            AD_dns_zonekill
            AD_gpo_listall
            AD_gpo_create
            AD_gpo_kill
            AD_gpo_dump
            AD_repdir_using_file
            AD_examuser_create
            AD_examuser_kill
            AD_smbclient_testfile
            AD_sophomorix_schema_update
            samba_stop
            samba_start
            samba_status
            );


sub AD_get_unicodepwd {
    my ($sam,$ref_sophomorix_config) = @_;
    my $command="ldbsearch --url $ref_sophomorix_config->{'INI'}{'PATHS'}{'SAM_LDB'} ".
                "\"sAMAccountName=$sam\" unicodePwd supplementalCredentials";
    my $string=`$command`;
    my @lines=split("\n",$string);

    my $unicodepwd;
    foreach my $line (@lines){
        if ($line=~m/unicodePwd/){
            my ($attr,$pass)=split("::",$line);
            $unicodepwd=&Sophomorix::SophomorixBase::remove_whitespace($pass);
            last; # dont look further
        }
    }

    my $supplemental_credentials="";
    foreach my $line (@lines){
        if ($line=~m/supplementalCredentials/ or $line=~m/^ /){
            my ($attr,$supp)=split("::",$line);
	    $supplemental_credentials=$supplemental_credentials.$line."\n";
            if ($line eq ""){
                last; # dont look further
            }
        }
    }
    return ($unicodepwd,$supplemental_credentials);
}



sub AD_set_unicodepwd {
    my ($user,$unicodepwd,$supplemental_credentials,$ref_sophomorix_config) = @_;

    # ???
    my ($ldap,$root_dse) = &AD_bind_admin(\@arguments,\%sophomorix_result,$json);

    my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$user);
    system("mkdir -p $ref_sophomorix_config->{'INI'}{'PATHS'}{'TMP_PWDUPDATE'}");
    my $ldif=$ref_sophomorix_config->{'INI'}{'PATHS'}{'TMP_PWDUPDATE'}."/".$user.".ldif";
    open(LDIF,">$ldif")|| die "ERROR: $!";
    print LDIF "dn: $dn\n";
    print LDIF "changetype: modify\n";
    print LDIF "replace: unicodePwd\n";
    print LDIF "unicodePwd:: $unicodepwd\n";
    print LDIF "$supplemental_credentials\n";
    close(LDIF);
    # load ldif file
    my $com="ldbmodify -H /var/lib/samba/private/sam.ldb --controls=local_oid:1.3.6.1.4.1.7165.4.3.12:0 $ldif";
    my $res=system($com);
    if (not $res==0){
        print "ERROR: password update failed, $res returned\n";
    }
    system("rm $ldif");
    # ???
    &AD_unbind_admin($ldap);
}



sub AD_get_passwd {
    my ($user,$pwd_file)=@_;
    my $password="";
    if (-e $pwd_file) {
        open (SECRET, $pwd_file);
        while(<SECRET>){
            $password=$_;
            chomp($password);
        }
        close(SECRET);
    } else {
        print "Password of samba user $user must ",
               "be in $pwd_file\n";
        exit;
    }
    return($password);
}



sub AD_bind_admin {
    my ($ref_arguments,$ref_result,$json) = @_;
    if (not -e $DevelConf::secret_file_sophomorix_AD_admin){
        print "\nERROR: Connection to AD failed: No password found!\n\n";
        print "sophomorix connects to AD with the user $DevelConf::sophomorix_AD_admin:\n";
        print "  A) Make sure $DevelConf::sophomorix_AD_admin exists:\n";
        print "     samba-tool user create $DevelConf::sophomorix_AD_admin %<password>% \n";
        print "     (Replace <password> according to: samba-tool domain passwordsettings show)\n";
        print "  B) Store the Password of $DevelConf::sophomorix_AD_admin (without newline character) in:\n";
        print "     $DevelConf::secret_file_sophomorix_AD_admin\n";
        print "\n";
        exit;
    }

    my ($smb_admin_pass)=&AD_get_passwd($DevelConf::sophomorix_AD_admin,$DevelConf::secret_file_sophomorix_AD_admin);
    my $host="ldaps://localhost";
    # check connection to Samba4 AD
    if($Conf::log_level>=3){
        print "   Checking Samba4 AD connection ...\n";
    }

    #my $ldap = Net::LDAP->new('ldaps://localhost')  or  die "$@";
    my $ldap = Net::LDAP->new($host) or &Sophomorix::SophomorixBase::log_script_exit(
         "No connection to Samba4 AD!",1,1,0,$ref_arguments,$ref_result,$json);

    if($Conf::log_level>=2){
        print "Retrieving RootDSE...\n";
    }
    my $dse = $ldap->root_dse();
    # get naming Contexts
    my @contexts = $dse->get_value('namingContexts');

    ## get supported LDAP versions as an array reference
    #my $versions = $dse->get_value('supportedLDAPVersion', asref => 1);
    my $root_dse=$contexts[0];
    if($Conf::log_level>=3){
        foreach my $context (@contexts){
            print "      * NamingContext: <$context>\n";
        }
    }

    if($Conf::log_level>=2){
        print "   * RootDSE: $root_dse\n";
    }

    # admin bind
    my $sophomorix_AD_admin_dn="CN=".$DevelConf::sophomorix_AD_admin.",CN=Users,".$root_dse;
    if($Conf::log_level>=2){
        print "Binding with $sophomorix_AD_admin_dn\n";
    }
    my $mesg = $ldap->bind($sophomorix_AD_admin_dn, password => $smb_admin_pass);
    # show errors from bind
    my $return=&AD_debug_logdump($mesg,2,(caller(0))[3]);
    if ($return==0){
        print "Please verify the password file for $sophomorix_AD_admin_dn\n\n";
        exit;
    }

    # Testing if sophomorix schema is present
    # ldbsearch -H ldap://localhost -UAdministrator%<password> -b cn=Schema,cn=Configuration,DC=linuxmuster,DC=local cn=Sophomorix-User
    if($Conf::log_level>=2){
        print "Testing if the Sophomorix Schema exists (Sophomorix-User)...\n";
    }

    my $base="CN=Sophomorix-Schema-Version,CN=Schema,CN=Configuration,".$root_dse;
    my $filter="(cn=sophomorix-Schema-Version)";
    my $mesg2 = $ldap->search(
                       base   => $base,
                       scope => 'base',
                       filter => $filter,
                       attrs => ['rangeUpper']
                            );
    my $res = $mesg2->count; 
    if ($res!=1){
            print "   * ERROR: Sophomorix-Schema-Version nonexisting\n";
        exit;
    } elsif ($res==1){
        my $entry = $mesg2->entry(0);
        my $version=$entry->get_value('rangeUpper');
        if($Conf::log_level>=2){
            print "   * Sophomorix-Schema exists  (SophomorixSchemaVersion=$version)\n";
        }
        if (not $version==$DevelConf::sophomorix_schema_version){
            print "\n   * ERROR: Sophomorix-Schema-Version $version (in AD) is not the required verson: ",
                  "$DevelConf::sophomorix_schema_version\n\n";
            exit;
        } else {
            print "OK: SophomorixSchemaVersion $version matches required Version $DevelConf::sophomorix_schema_version\n";
        }
    }

    return ($ldap,$root_dse);
}



sub AD_unbind_admin {
    my ($ldap) = @_;
    my $mesg = $ldap->unbind();
    #  show errors from unbind
    $mesg->code && die $mesg->error;
}



sub AD_dns_get {
    # get dns domain from RootDSE
    my ($root_dse) = @_;
    my @dns_part_stripped=(); # without 'DC='
    my @dns_part=split(/,/,$root_dse);
    foreach my $part (@dns_part){
        $part=~s/DC=//g;
        push @dns_part_stripped, $part;
    }
    my $dns_name = join(".",@dns_part_stripped);
    if($Conf::log_level>=3){
        my $caller=(caller(0))[3];
        print "$caller RootDSE: $root_dse -> DNS: $dns_name\n";
    }
    return $dns_name;
}



sub AD_dns_nodecreate_update {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $dns_server = $arg_ref->{dns_server};
    my $dns_node = $arg_ref->{dns_node};
    my $dns_ipv4 = $arg_ref->{dns_ipv4};
    my $dns_type = $arg_ref->{dns_type};
    my $dns_cn = $arg_ref->{dns_cn};
    my $filename = $arg_ref->{filename};
    my $school = $arg_ref->{school};
    my $role = $arg_ref->{role};
    my $comment = $arg_ref->{comment};
    my $create = $arg_ref->{create};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    # calc dnsNode, reverse lookup
    my @octets=split(/\./,$dns_ipv4);
    my $dns_zone=$octets[2].".".$octets[1].".".$octets[0].".in-addr.arpa";
    my $dns_last_octet=$octets[3];

    print "\n";
    if ($create eq "CREATE"){
        &Sophomorix::SophomorixBase::print_title("Creating dnsNode: $dns_node (start)");
    } else {
        &Sophomorix::SophomorixBase::print_title("Updating dnsNode: $dns_node (start)");
    }

    # set defaults if not defined
    if (not defined $filename){
        $filename="---";
    }
    if (not defined $comment or $comment eq ""){
        $comment="---";
    }
    if (not defined $dns_cn){
        $dns_cn=$dns_node;
    }
    if (not defined $dns_server){
        $dns_server="localhost";
    }
    if (not defined $dns_type){
        $dns_type="A";
    }
    
    ############################################################
    # adding dnsNode with samba-tool
    if ($create eq "TRUE"){
        my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
            " dns add $dns_server $root_dns $dns_node $dns_type $dns_ipv4".
            " --password='******' -U $DevelConf::sophomorix_AD_admin";
        &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);
    }

    ############################################################
    # add/update comments to recognize the dnsNode as created by sophomorix
    my ($count,$dn_exist_dnshost,$cn_exist_dnshost)=&AD_object_search($ldap,$root_dse,"dnsNode",$dns_node);
    print "   * Adding Comments to dnsNode $dns_node\n";
    if ($count > 0){
             print "   * dnsNode $dns_node exists ($count results)\n";
             my $mesg = $ldap->modify( $dn_exist_dnshost, replace => {
                                       cn => $dns_cn,
                                       sophomorixRole => $role,
                                       sophomorixAdminFile => $filename,
                                       sophomorixSchoolname => $school,
                                       sophomorixComputerIP => $dns_ipv4,
                                       sophomorixDnsNodename => $dns_node,
                                       sophomorixDnsNodetype => $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_TYPE_LOOKUP'},
                                       sophomorixComment => $comment,
                                      });
             &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    ############################################################
    if ($create eq "TRUE"){
        my $dns_type="PTR";
        # adding reverse lookup with samba-tool
        my $command_reverse=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
            " dns add $dns_server $dns_zone $dns_last_octet $dns_type $dns_node.$root_dns ".
            " --password='******' -U $DevelConf::sophomorix_AD_admin";
        &Sophomorix::SophomorixBase::smb_command($command_reverse,$smb_admin_pass);
    }
    ############################################################
    # add/update comments to recognize the dnsNode reverse lookup as created by sophomorix
    my $dns_node_reverse="DC=".$dns_last_octet.",DC=".$dns_zone.",CN=MicrosoftDNS,DC=DomainDnsZones,".$root_dse;
    print "   * Adding Comments to reverse lookup $dns_node_reverse\n";
    my $mesg = $ldap->modify( $dns_node_reverse, replace => {
                              cn => $dns_cn,
                              sophomorixRole => $role,
                              sophomorixAdminFile => $filename,
                              sophomorixSchoolname => $school,
                              sophomorixComputerIP => $dns_ipv4,
                              sophomorixDnsNodename => $dns_node,
                              sophomorixDnsNodetype => $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_TYPE_REVERSE'},
                              sophomorixComment => $comment,
                    });
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    if ($create eq "CREATE"){
        &Sophomorix::SophomorixBase::print_title("Creating dnsNode: $dns_node (end)");
    } else {
        &Sophomorix::SophomorixBase::print_title("Updating dnsNode: $dns_node (end)");
    }

    return;
}



sub AD_dns_zonecreate {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $dns_server = $arg_ref->{dns_server};
    my $dns_zone = $arg_ref->{dns_zone};
    my $dns_cn = $arg_ref->{dns_cn};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title(
              "Creating dnsZone: $dns_zone");
    } 

    # set defaults if not defined

    if (not defined $dns_cn){
        $dns_cn=$dns_zone;
    }
    if (not defined $dns_server){
        $dns_server="localhost";
    }

    ############################################################
    # adding dnsNode with samba-tool
    my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
        " dns zonecreate $dns_server $dns_zone --password='******' -U $DevelConf::sophomorix_AD_admin";
    &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);

    ############################################################
    # adding comments to recognize the dnsZone as created by sophomorix
    my ($count,$dn_exist_dnszone,$cn_exist_dnszone)=&AD_object_search($ldap,$root_dse,"dnsZone",$dns_zone);
    print "   * Adding Comments to dnsZone $dns_zone\n";

    if ($count > 0){
             print "   * dnsZone $dns_zone exists ($count results)\n";
             my $mesg = $ldap->modify($dn_exist_dnszone, replace => {
                                      cn => $dns_cn,
                                      sophomorixRole => $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSZONE_ROLE'},
                                     });
             &AD_debug_logdump($mesg,2,(caller(0))[3]);
             return;
         }
}



sub AD_dns_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $dns_server = $arg_ref->{dns_server};
    my $dns_zone = $arg_ref->{dns_zone};
    my $dns_node = $arg_ref->{dns_node};
    my $dns_ipv4 = $arg_ref->{dns_ipv4};
    my $dns_type = $arg_ref->{dns_type};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    if (not defined $dns_server){
        $dns_server="localhost";
    }
    if (not defined $dns_type){
        $dns_type="A";
    }

    if ($dns_ipv4 ne "NXDOMAIN" and $dns_ipv4 ne "NOERROR"){
        # delete dnsNode
        my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
            " dns delete $dns_server ".
            "$dns_zone $dns_node.$dns_zone $dns_type $dns_ipv4 ".
            "--password='******' -U $DevelConf::sophomorix_AD_admin";
        &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);

        # delete reverse lookup
        my @octets=split(/\./,$dns_ipv4);
        my $dns_zone_reverse=$octets[2].".".$octets[1].".".$octets[0].".in-addr.arpa";
        my $dns_last_octet=$octets[3];
        my $dns_type="PTR";
        my $command_reverse=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
            " dns delete $dns_server $dns_zone_reverse $dns_last_octet $dns_type $dns_node.$dns_zone ".
            " --password='******' -U $DevelConf::sophomorix_AD_admin";
        &Sophomorix::SophomorixBase::smb_command($command_reverse,$smb_admin_pass);
    }
}



sub AD_dns_zonekill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $dns_server = $arg_ref->{dns_server};
    my $dns_zone = $arg_ref->{dns_zone};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    if (not defined $dns_server){
        $dns_server="localhost";
    }

    # deleting zone with samba-tool
    my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
        " dns zonedelete $dns_server $dns_zone --password='******' -U $DevelConf::sophomorix_AD_admin";
    &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);
}



sub AD_gpo_listall {
    my ($arg_ref) = @_;
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_result = $arg_ref->{sophomorix_result};
    my %gpo=();
    my $gpo_listall_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}." gpo listall";
    print "$gpo_listall_command (and: gpo listcontainers)\n";
    $gpo_listall_out=`$gpo_listall_command`;
    my $gpo_listall_return=${^CHILD_ERROR_NATIVE}; # return of value of last command
  
    $gpo_out="";

    my @lines=split(/\n/,$gpo_listall_out);
    push @lines, ""; # add empty line to allow to finalize last gpo
    my $gpo_current="";
    foreach my $line (@lines){
        if ($line eq ""){
            my $gpo_listcontainers_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                " gpo listcontainers $gpo_current";
            $gpo_listcontainers_out=`$gpo_listcontainers_command`;
	    #print $gpo_listcontainers_command."\n";
	    #print $gpo_listcontainers_out."\n";

            $gpo_out=$gpo_out."  ".$gpo_listcontainers_out."\n";
            # ???? analyze $listcontainers_out for json

            next;
        }

        my ($key,$value)=split(/:/,$line,2);
        $key=&Sophomorix::SophomorixBase::remove_embracing_whitespace($key);
        $value=&Sophomorix::SophomorixBase::remove_embracing_whitespace($value);
        if ($key eq "GPO"){
	    $gpo_out=$gpo_out."\n".$line."\n";
            # update current gpo name 
            $gpo_current=$value;
            $gpo{'GPO'}{$value}{'EXISTING'}="TRUE";
	} else{
            $gpo_out=$gpo_out.$line."\n";
            # store key value
            $gpo{'GPO'}{$gpo_current}{$key}=$value;
            if ($key eq "display name"){
                $gpo{'LOOKUP'}{"by_display_name"}{$value}=$gpo_current;
            }
        }
    }

    return \%gpo;
    # deprecated:
    # print $gpo_out;
}



sub AD_gpo_get_uuid {
    my ($gpo,$gpo_type,$ref_sophomorix_config,$ref_result)=@_;
    my $ref_gpo=&AD_gpo_listall({sophomorix_config=>$ref_sophomorix_config,
                                 sophomorix_result=>$ref_result,
                               });
    my $gpo_real="sophomorix".":".$gpo_type.":".$gpo;
    my $uuid="";
    my $gpo_dn="";
    if (exists $ref_gpo->{'LOOKUP'}{"by_display_name"}{$gpo_real}){
        $uuid=$ref_gpo->{'LOOKUP'}{"by_display_name"}{$gpo_real};
        $gpo_dn=$ref_gpo->{'GPO'}{$uuid}{'dn'};
    } else {
        print "\nERROR: gpo \"$gpo_real\" not found!\n\n";
        exit;
    }
    return ($uuid,$gpo_dn);
}



sub AD_gpo_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $gpo = $arg_ref->{gpo};
    my $gpo_type = $arg_ref->{gpo_type};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_result = $arg_ref->{sophomorix_result};

    my $gpo_real="sophomorix".":".$gpo_type.":".$gpo;

    &Sophomorix::SophomorixBase::print_title("Creating gpo $gpo_real (start)");
    my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                " gpo create \"".$gpo_real."\" ".
                "-U administrator%`cat /etc/linuxmuster/.secret/administrator`";
                
    print "$command\n";
    system($command);

    my ($uuid,$gpo_dn) = &AD_gpo_get_uuid($gpo,"school",$ref_sophomorix_config,$ref_result);
    print "Using gpo uuid $uuid\n";

    # create/update some dirs in sysvol
    &AD_repdir_using_file({root_dns=>$root_dns,
                           repdir_file=>"repdir.school_gpo",
                           smb_admin_pass=>$smb_admin_pass,
                           gpo_uuid=>$uuid,
                           sophomorix_config=>$ref_sophomorix_config,
                           sophomorix_result=>$ref_sophomorix_result,
                         });

    # copy some files without modification
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/GPT.INI",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "",
        "COPY",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/Machine/comment.cmtx",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "Machine",
        "COPY",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/Machine/Registry.pol",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "Machine",
        "COPY",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "Machine/Microsoft/Windows NT/SecEdit",
        "COPY",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/Machine/Scripts/scripts.ini",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "Machine/Scripts",
        "COPY",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/Machine/Scripts/Startup/http_proxy_signing_ca.p12",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "Machine/Scripts/Startup",
        "COPY",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/User/Scripts/scripts.ini",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "User/Scripts",
        "COPY",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);

    # copy some files line by line with modification
    # Drives.xml
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/User/Preferences/Drives/Drives.xml",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "User/Preferences/Drives",
        "REWRITE",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);
    # Printers.xml
    &Sophomorix::SophomorixBase::smb_file_rewrite(
        "/usr/share/sophomorix/devel/gpo/school/User/Preferences/Printers/Printers.xml",
        "sysvol",
        $root_dns."/Policies",
        $uuid,
        "User/Preferences/Printers",
        "REWRITE",
        $root_dns,
        $gpo,
        $smb_admin_pass,
        $ref_sophomorix_config);

    &Sophomorix::SophomorixBase::print_title("Creating gpo $gpo_real (end)");

    &Sophomorix::SophomorixBase::print_title("Creating link to $gpo_real (start)");
    # set gpo link to school
    my $command_link=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
	        " gpo setlink ".
	        $ref_sophomorix_config->{'SCHOOLS'}{$gpo}{'OU_TOP'}.
                " \"".$uuid."\" ".
                "-U administrator%`cat /etc/linuxmuster/.secret/administrator`";
                
    print "$command_link\n";
    system($command_link);
    &Sophomorix::SophomorixBase::print_title("Creating link to $gpo_real (end)");

    my $command_inherit=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
	        " gpo setinheritance ".
	        $ref_sophomorix_config->{'SCHOOLS'}{$gpo}{'OU_TOP'}.
                " inherit".
                " -U administrator%`cat /etc/linuxmuster/.secret/administrator`";
                
    print "MAYBE DO: $command_inherit\n";
    #system($command_inherit);

    # update the gpo
    if ($gpo_type eq "school"){
        # prepare *.ldif from *.ldif.template
        my $path_ldif="/usr/share/sophomorix/devel/gpo/".
                      $gpo_type.".ldif";
        my $path_ldif_template="/usr/share/sophomorix/devel/gpo/".
	    $gpo_type.".ldif.template";
	my $sed_command="sed ".
                        "-e 's/\@\@ROOTDSE\@\@/".$root_dse."/g' ".
                        "-e 's/\@\@GPO\@\@/".$uuid."/g' ".
	                $path_ldif_template." > ".$path_ldif;
	print "$sed_command\n";
        system($sed_command);

        # update AD from modified *.ldif.template file
	my $ldbmodify_command="ldbmodify -H /var/lib/samba/private/sam.ldb ".$path_ldif;
        print "$ldbmodify_command\n";
        system($ldbmodify_command);
    }

    # sysvoreset (updates acls for files)
    my $sysvolreset_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
        " ntacl sysvolreset";
    print "$sysvolreset_command\n";
    system ($sysvolreset_command);
}



sub AD_gpo_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $gpo = $arg_ref->{gpo};
    my $gpo_type = $arg_ref->{gpo_type};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_result = $arg_ref->{sophomorix_result};

    my $gpo_real="sophomorix".":".$gpo_type.":".$gpo;

    &Sophomorix::SophomorixBase::print_title("Killing gpo $gpo_real (start)");
    # find out the iD of the named gpo
    my $ref_gpo=&AD_gpo_listall({sophomorix_config=>$ref_sophomorix_config,
                                 sophomorix_result=>$ref_result,
                               });
    my $uuid="";
    if (exists $ref_gpo->{'LOOKUP'}{"by_display_name"}{$gpo_real}){
        $uuid=$ref_gpo->{'LOOKUP'}{"by_display_name"}{$gpo_real};
    } else {
        print "\nERROR: gpo \"$gpo_real\" not found!\n\n";
        exit;
    }

    my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                " gpo del \"".$uuid."\" ".
                "-U administrator%`cat /etc/linuxmuster/.secret/administrator`";
                
    print "$command\n";
    system($command);
    &Sophomorix::SophomorixBase::print_title("Killing gpo $gpo_real (end)");
    # activate
    my $sysvolreset_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
        " ntacl sysvolreset";
    print "$sysvolreset_command\n";
    system ($sysvolreset_command);
}



sub AD_gpo_dump {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $gpo_dump = $arg_ref->{gpo_dump};
    my $gpo_dump_type = $arg_ref->{gpo_dump_type};
    my $gpo_dump_path = $arg_ref->{gpo_dump_path};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_result = $arg_ref->{sophomorix_result};

    &Sophomorix::SophomorixBase::print_title("Dumping gpo $gpo_dump (start)");
    system("mkdir -p $gpo_dump_path");
    # assemble ldif path
    my $path_ldif=$gpo_dump_path."/".$gpo_dump_type.".ldif";
    my $path_ldif_template=$gpo_dump_path."/".$gpo_dump_type.".ldif.template";
    # assemble ldbsearch command
    my $ldbsearch_command="ldbsearch -b CN=Policies,CN=System,".$root_dse.
                          " -H /var/lib/samba/private/sam.ldb".
                          " '(name=".$gpo_dump.")'".
                          " gPCMachineExtensionNames".
                          " gPCUserExtensionNames".
                          " versionNumber".
                          " > $path_ldif";
    print "$ldbsearch_command\n";
    system($ldbsearch_command);

    # create a template
    my $sed_command="sed ".
                    " -e 's/#.*\$//g' ". # remove commented lines, $ must be escaped here
                    " -e '/^\$/d' ". # remove empty lines
                    " -e 's/".$gpo_dump."/\@\@GPO\@\@/g' ".
                    " -e 's/".$root_dse."/\@\@ROOTDSE\@\@/g' ".
                    " -e 's/gPCMachineExtensionNames/replace: gPCMachineExtensionNames\\ngPCMachineExtensionNames/g' ".
                    " -e 's/gPCUserExtensionNames/replace: gPCUserExtensionNames\\ngPCUserExtensionNames/g' ".
                    " -e 's/versionNumber/replace: versionNumber\\nversionNumber/g' ".
                    $path_ldif." > ".$path_ldif_template;
    print "$sed_command\n";
    system($sed_command);

    # insert "changetype: modify"-line after dn: ... line (i.e. line 2)
    my $sed_command2="sed -i '2ichangetype: modify' $path_ldif_template";
    print "$sed_command2\n";
    system($sed_command2);
    
    &Sophomorix::SophomorixBase::print_title("Dumping gpo $gpo_dump (end)");
}



sub AD_repdir_using_file {
    my ($arg_ref) = @_;
    # mandatory options
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $repdir_file = $arg_ref->{repdir_file};
    my $ref_AD = $arg_ref->{AD};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    # optional options
    my $school = $arg_ref->{school};
    my $project = $arg_ref->{project};
    my $administrator_home = $arg_ref->{administrator_home};
    my $teacherclass = $arg_ref->{teacherclass};
    my $teacher_home = $arg_ref->{teacher_home};
    my $adminclass = $arg_ref->{adminclass};
    my $extraclass = $arg_ref->{extraclass};
    my $subdir = $arg_ref->{subdir};
    my $student_home = $arg_ref->{student_home};
    my $gpo_uuid = $arg_ref->{gpo_uuid};

    if (not defined $gpo_uuid){
        $gpo_uuid="";
    }

    # abs path
    my $repdir_file_abs=$ref_sophomorix_config->{'REPDIR_FILES'}{$repdir_file}{'PATH_ABS'};
    my $entry_num=0; # was $num
    my $line_num=0;
    &Sophomorix::SophomorixBase::print_title("Repairing from file: $repdir_file (start)");
    print "";
    # option school
    my @schools=("");
    if (defined $school){
        @schools=($school);
    } else {

    }

    # reading repdir file
    open(REPDIRFILE, "<$repdir_file_abs")|| die "ERROR: $repdir_file_abs $!";
    while (<REPDIRFILE>) {
        my $line=$_;
        $line_num++;
        my $group_type="";
        my $groupvar_seen=0; # a group variable was in this line
        chomp($line);   
        if ($line eq ""){next;} # next on empty line
        if(/^\#/){next;} # next on comments
        $entry_num++;

        if (/\@\@SCHOOL\@\@/ and not defined $school) {
            @schools = @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} };
        }

        if (/\@\@ADMINCLASS\@\@/) {
            $group_type="adminclass";
            $groupvar_seen++;
        }
        if (/\@\@EXTRACLASS\@\@/) {
            $group_type="extraclass";
            $groupvar_seen++;
        }
        if (/\@\@TEACHERCLASS\@\@/) {
            $group_type="teacherclass";
            $groupvar_seen++;
        }
        if (/\@\@PROJECT\@\@/) {
            $group_type="project";
            $groupvar_seen++;
        }
        if (/\@\@SUBDIR\@\@/) {
            #$group_type="project";
            #$groupvar_seen++;
            if (defined $subdir and $subdir eq ""){
                # replace SUBDIR and / with ""
                $line=~s/\/\@\@SUBDIR\@\@//;
            } else {
                # replace SUBDIR with $subdir
                $line=~s/\@\@SUBDIR\@\@/$subdir/;
            }
        }
        if (/\$directory_management/) {
            # when $directory_management is followed by @@USER@@ a group is needed:
            # repdir.globaladministrator_home --> global-admins
            # repdir.schooladministrator_home --> admins
            if ($repdir_file eq "repdir.schooladministrator_home"){
                $group_type="admins";
            } elsif ($repdir_file eq "repdir.globaladministrator_home"){
                $group_type="global-admins";
                @schools = ($ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'});
            } elsif ($repdir_file eq "repdir.school"){
                $group_type="admins";
            } elsif ($repdir_file eq "repdir.global"){
                $group_type="admins";
            } else {
                $group_type="admins";
                print "WARNING: This else was not expected: $repdir_file\n";
            }
        }

        my ($entry_type,$path_with_var, $owner, $groupowner, $permission,$ntacl,$ntaclonly) = split(/::/,$line);
        if (not defined $ntaclonly){
            $ntaclonly="";            
        }

        # replacing $vars in path
        my @old_dirs=split(/\//,$path_with_var);
        my @new_dirs=();
        foreach my $dir (@old_dirs){
            $dir=">".$dir."<"; # add the ><, so that no substrings will be replaced
            # /var
            $dir=~s/>\$path_log</${DevelConf::path_log}/;
            $dir=~s/>\$path_log_user</${DevelConf::path_log_user}/;
            # /var/lib/samba/sysvol
            $dir=~s/>\$sysvol<//;
            $dir=~s/>\$root_dns</$root_dns/;
            $dir=~s/>\$gpo_uuid</$gpo_uuid/;
            # /srv/samba
            $dir=~s/>\$homedir_all_schools</${DevelConf::homedir_all_schools}/;
            $dir=~s/>\$homedir_global</${DevelConf::homedir_global}/;
            # other
            $dir=~s/>\$directory_students</${DevelConf::directory_students}/;
            $dir=~s/>\$directory_teachers</${DevelConf::directory_teachers}/;
            $dir=~s/>\$directory_projects</${DevelConf::directory_projects}/;
            $dir=~s/>\$directory_management</${DevelConf::directory_management}/;
            $dir=~s/>\$directory_examusers</${DevelConf::directory_examusers}/;
            $dir=~s/>\$directory_share</${DevelConf::directory_share}/;
            $dir=~s/>\$directory_program</${DevelConf::directory_program}/;
            $dir=~s/>\$directory_iso</${DevelConf::directory_iso}/;
            # remove <,>
            $dir=~s/^>//g;
            $dir=~s/<$//g;
	    push @new_dirs,$dir;
        }
        $path_with_var=join("/",@new_dirs);

        print "------------------------------------------------------------\n";
        print "$entry_num) Line $line_num:  $line:\n";
        if($Conf::log_level>=3){
            print "   Type:       $entry_type\n";
            print "   Path:       $path_with_var\n";
            print "   Owner:      $owner\n";
            print "   Group:      $groupowner\n";
            print "   Group-Type: $group_type\n";
            print "   Perm:       $permission\n";
            print "   NTACL:     $ntacl\n";
            print "   Schools:    @schools\n";
        }

        ########################################
        # school loop start             
        foreach my $school (@schools){
            my $path=$path_with_var;
            my $path_smb=$path_with_var;
            if ($school eq $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}){
                if ($path_smb eq $DevelConf::homedir_global){
                    $path_smb="/";
                } else {
                    $path_smb=~s/$DevelConf::homedir_global//; # for school
                    $path_smb=~s/\@\@SCHOOL\@\@\///; # for homdirs
                }
            } else {
                $path=~s/\@\@SCHOOL\@\@/$school/;
                if ($path_smb eq "\@\@SCHOOL\@\@"){
                    $path_smb="/";
                } else {
                    $path_smb=~s/\@\@SCHOOL\@\@\///;
                }
            }
            if($Conf::log_level>=3){
                print "   Determining path for school $school:\n";
                print "      * Path after school: $path (smb: $path_smb)\n";
            }
            # determining groups to walk through
            my @groups;
            if (defined $project){
                @groups=($project);
            } elsif (defined $teacherclass){
                @groups=($teacherclass);
            } elsif (defined $adminclass){
                @groups=($adminclass);
            } elsif (defined $extraclass){
                @groups=($extraclass);
            } elsif(defined $ref_AD->{'LISTS'}{'BY_SCHOOL'}{$school}{'groups_BY_sophomorixType'}{$group_type}){
                # there is a group list -> use it
                @groups=@{ $ref_AD->{'LISTS'}{'BY_SCHOOL'}{$school}{'groups_BY_sophomorixType'}{$group_type} };
            } elsif ($group_type eq "global-admins"){
                @groups=("global-admins");
            } else {
                @groups=("");
            }
            ########################################
            # group loop start
            foreach my $group (@groups){
                if ($group eq "" and $groupvar_seen>0){
                    # skip, if a groupvar should be replaced, but there is only an empty string a group
                    print "Skipping $line:\n";
                    print "  -> group would be replaced by empty string\n";
                    next;
                }

                my $group_basename=$group;
                $group_basename=&Sophomorix::SophomorixBase::get_group_basename($group,$school);
                my $path_after_group=$path;
                $path_after_group=~s/\@\@ADMINCLASS\@\@/$group_basename/;
                $path_after_group=~s/\@\@EXTRACLASS\@\@/$group_basename/;
                $path_after_group=~s/\@\@TEACHERCLASS\@\@/$group_basename/;
                $path_after_group=~s/\@\@PROJECT\@\@/$group_basename/;
                my $path_after_group_smb=$path_smb;
                $path_after_group_smb=~s/\@\@ADMINCLASS\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@EXTRACLASS\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@TEACHERCLASS\@\@/$group_basename/;
                $path_after_group_smb=~s/\@\@PROJECT\@\@/$group_basename/;
                if($Conf::log_level>=3){      
                    print "      * Path after group:  $path_after_group (smb: $path_after_group_smb)\n";
                }

                ########################################
                # user loop start
                my @users=("");
                if ($path_after_group=~/\@\@USER\@\@/) {
                    # determining list of users
                    if (defined $administrator_home){
                        @users=($administrator_home);
                    } elsif (defined $teacher_home){
                        @users=($teacher_home);
                    } elsif (defined $student_home){
                        @users=($student_home);
                    } elsif (defined $ref_AD->{'LISTS'}{'BY_SCHOOL'}{$school}{'users_BY_group'}{$group}){
                        @users = @{ $ref_AD->{'LISTS'}{'BY_SCHOOL'}{$school}{'users_BY_group'}{$group} };
                    } else {
                        print "\n";
                        print "##### No users in $group (school $school) #####\n";
                        # empty list means do nothing in next loop
                        @users=();
                    }
                }
                foreach my $user (@users){
                    my $path_after_user=$path_after_group;
                    $path_after_user=~s/\@\@USER\@\@/$user/;
                    my $path_after_user_smb=$path_after_group_smb;
                    $path_after_user_smb=~s/\@\@USER\@\@/$user/;

                    $path_after_user_smb=~s/\@\@COLLECT_DIR_HOME\@\@/$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{'COLLECT_DIR_HOME_'.$ref_sophomorix_config->{'GLOBAL'}{'LANG'}}/;
                    $path_after_user_smb=~s/\@\@SHARE_DIR_HOME\@\@/$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{'SHARE_DIR_HOME_'.$ref_sophomorix_config->{'GLOBAL'}{'LANG'}}/;
                    $path_after_user_smb=~s/\@\@TRANSFER_DIR_HOME\@\@/$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{'TRANSFER_DIR_HOME_'.$ref_sophomorix_config->{'GLOBAL'}{'LANG'}}/;
                    if($Conf::log_level>=3){      
                        print "      * Path after user:   $path_after_user (smb: $path_after_user_smb)\n";
	            }
                    if ($entry_type eq "SMB"){
                        # smbclient
                        my $share;
                        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
                            $share=$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
                        } else {
                            if ($gpo_uuid ne ""){
                                $share="sysvol";
                            } else {
                                $share=$school;
                            }
                         }
                        my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                            " -U ".$DevelConf::sophomorix_file_admin."%'******'".
                            " //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/".$share." -c 'mkdir \"$path_after_user_smb\"'";
                        my $user_typeout;
                        if ($user eq ""){
                            $user_typeout="<none>";
                        } else {
                            $user_typeout=$user;
                        }
                        if ($group eq ""){
                            $group_typeout="<none>";
                        } else {
                            $group_typeout=$group;
                        }
                        #print "\nUser: $user_typeout in group $group_typeout in school $school (SHARE: $share)\n";
                        #print "---------------------------------------------------------------\n";
                        if ($ntaclonly ne "ntaclonly"){
                            &Sophomorix::SophomorixBase::smb_command($smbclient_command,$smb_admin_pass);
		        } else {
                            print "* NOT executed (ntaclonly): smbclient command\n";
                        }

                        # use smbcacls
                        &Sophomorix::SophomorixBase::NTACL_set_file({root_dns=>$root_dns,
                                                                     user=>$user,
                                                                     group=>$group,
                                                                     school=>$share,
                                                                     ntacl=>$ntacl,
                                                                     smbpath=>$path_after_user_smb,
                                                                     smb_admin_pass=>$smb_admin_pass,
                                                                     sophomorix_config=>$ref_sophomorix_config,
                                                                     sophomorix_result=>$ref_sophomorix_result,
                                                                   });
                   } elsif ($entry_type eq "LINUX"){
                        mkdir $path_after_user;
                        my $chown_command="chown ".$owner.".".$groupowner." ".$path_after_user;
                        print "          $chown_command\n";
                        system($chown_command);
                        chmod oct($permission), $path_after_user;
                    } else {
                        print "\nERROR: $entry_type unknown\n\n";
                        exit;
                    }
                } # user loop end 
            } # group loop end 
        } # school loop end
        print "DONE with $entry_num) Line $line_num:  $line ---\n";
    }
    close(REPDIRFILE);
    &Sophomorix::SophomorixBase::print_title("Repairing from file: $repdir_file (end)");
}



sub AD_user_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{login};
    my $identifier = $arg_ref->{identifier};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$user);
    if ($count > 0){
        my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
            $home_directory_AD,$user_account_control_AD,$toleration_date_AD,$deactivation_date_AD,
            $school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
            &AD_get_user({ldap=>$ldap,
                          root_dse=>$root_dse,
                          root_dns=>$root_dns,
                          user=>$user,
                        });
        $home_directory_AD=~s/\\/\//g;
        my $smb_home="smb:".$home_directory_AD;

        &Sophomorix::SophomorixBase::print_title("Killing user $user ($user_count):");
        &AD_remove_sam_from_sophomorix_attributes($ldap,$root_dse,"user",$user);

        if ($json>=1){
            # prepare json object
            my %json_progress=();
            $json_progress{'JSONINFO'}="PROGRESS";
            $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLUSER_PREFIX_EN'}.
                                         " $user".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLUSER_POSTFIX_EN'};
            $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLUSER_PREFIX_DE'}.
                                         " $user".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLUSER_POSTFIX_DE'};
            $json_progress{'STEP'}=$user_count;
            $json_progress{'FINAL_STEP'}=$max_user_count;
            # print JSON Object
            &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                              json=>$json,
                                                              sophomorix_config=>$ref_sophomorix_config,
                                                            });
        }

        # deleting user
	my $kill_return=-1;
        my $home_delete_string="";

        my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
            " user delete ". $user;
        ($kill_return)=&Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);

        # deleting home
        if ($role_AD eq "student" or 
            $role_AD eq "teacher" or 
            $role_AD eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'} or
            $role_AD eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}
           ){
              # smbclient deltree
              my $adminclass_basename=&Sophomorix::SophomorixBase::get_group_basename($adminclass_AD,$school_AD);
              my ($homedirectory,$unix_home,$unc,$smb_rel_path)=
                  &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                                 $school_AD,
                                                                 $adminclass_basename,
                                                                 $user,
                                                                 $role_AD,
                                                                 $ref_sophomorix_config);

              my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                        " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'******' ".
                        $unc." -c 'deltree \"$smb_rel_path\";'";
              my $smbclient_return=&Sophomorix::SophomorixBase::smb_command($smbclient_command,$smb_admin_pass);
              if($smbclient_return==0){
                  $home_delete_string="TRUE";
                  print "OK: Deleted with succes $smb_home\n";
              } else {
                  $home_delete_string="FALSE";
                  print "ERROR: rmdir_recurse $smb_home $!\n";
              }
        }

        if ($kill_return==0){
            # log the killing of a user
            &Sophomorix::SophomorixBase::log_user_kill({sAMAccountName=>$user,
                                                        sophomorixRole=>$role_AD, 
                                                        home_delete_string=>$home_delete_string,
                                                        sophomorixSchoolname=>$school_AD,
                                                        firstname=>$firstname_utf8_AD,    
                                                        lastname=>$lastname_utf8_AD,
                                                        adminclass=>$adminclass_AD,
                                                        unid=>$unid_AD,
                                                        sophomorix_config=>$ref_sophomorix_config,
                                                        sophomorix_result=>$ref_sophomorix_result,
                                                      });
	}
        return;
    } else {
        print "   * User $user nonexisting ($count results)\n";
        return;
    }
}



sub AD_remove_sam_from_sophomorix_attributes {
    my ($ldap,$root_dse,$objectclass,$object)=@_;
    # removes a username/groupname from the listed sophomorix attributes
    # $objectclass: user,group (objectClass of the object that will be removed)
    # $object: sAMAccountName of the object that will be removed 
    &Sophomorix::SophomorixBase::print_title("Removing object $object from sophomorix attributes");
    my @attr_list=();
    if ($objectclass eq "user"){
        @attr_list=("sophomorixMembers","sophomorixAdmins");
    } elsif ($objectclass eq "group"){
        @attr_list=("sophomorixMemberGroups","sophomorixAdminGroups");
    } else {
        print "\nWARNING: Could not determine attribute list ( AD_remove_sam_from_sophomorix_attributes)\n\n";
        return;
    }
    foreach my $attr (@attr_list){
        my $filter="(&(objectClass=group)(".$attr."=".$object."))";
        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['sAMAccountName']
                                );
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        my $max_attr = $mesg->count; 
        for( my $index = 0 ; $index < $max_attr ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            print "   * user $object is in $attr of $sam -> removing ...\n";
            #print "     $dn\n";
            my $mesg2 = $ldap->modify( $dn,
     	    	              delete => {
                              $attr => $object,
                              });
            &AD_debug_logdump($mesg2,2,(caller(0))[3]);
        }
    }
}



sub AD_computer_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $computer = $arg_ref->{computer};
    my $computer_count = $arg_ref->{computer_count};
    my $max_computer_count = $arg_ref->{max_computer_count};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    &Sophomorix::SophomorixBase::print_title("Killing computer $computer ($computer_count):");
    my $dn="";
    my $filter="(&(objectClass=computer)(sAMAccountName=".$computer."))";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   attrs => ['sAMAccountName']
                         );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $count_result = $mesg->count;
    if ($count_result==1){
        if ($json>=1){
            # prepare json object
            my %json_progress=();
            $json_progress{'JSONINFO'}="PROGRESS";
            $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLCOMPUTER_PREFIX_EN'}.
                                         " $computer".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLCOMPUTER_POSTFIX_EN'};
            $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLCOMPUTER_PREFIX_DE'}.
                                         " $computer".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLCOMPUTER_POSTFIX_DE'};
            $json_progress{'STEP'}=$computer_count;
            $json_progress{'FINAL_STEP'}=$max_computer_count;
            # print JSON Object
            &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                              json=>$json,
                                                              sophomorix_config=>$ref_sophomorix_config,
                                                            });
        }
        my ($entry,@entries) = $mesg->entries;
        $dn = $entry->dn();
        print "   * DN: $dn\n";
        my $mesg = $ldap->delete( $dn );
    } else {
        print "   * WARNING: $computer not found/to many items ($count_result results)\n";     
    }
}



sub AD_computer_update {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $computer = $arg_ref->{computer};
    my $computer_count = $arg_ref->{computer_count};
    my $attrs_count = $arg_ref->{attrs_count};
    my $ref_replace = $arg_ref->{replace};
    my $sophomorix_first_password = $arg_ref->{sophomorix_first_password}; # unicodePwd
    my $hide_pwd = $arg_ref->{hide_pwd};
    my $max_computer_count = $arg_ref->{max_computer_count};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    # add password to $ref_replace
    if (defined $sophomorix_first_password){
        my $uni_password=&_unipwd_from_plainpwd($sophomorix_first_password);
        $ref_replace->{$computer}{'REPLACE'}{'unicodePwd'}=$uni_password;
    }

    print "\n";
    &Sophomorix::SophomorixBase::print_title(
          "Updating computer ${computer_count}/$max_computer_count: $computer ($attrs_count attributes) (start)");
    # get dn
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => "sAMAccountName=$computer",
                         );
    my $max = $mesg->count; 
    if ($max==1){
        my $entry = $mesg->entry(0);
        my $dn = $entry->dn();
        print "   DN: $dn\n";
        foreach my $attr (keys  %{ $ref_replace->{$computer}{'REPLACE'} }){
            if ($attr eq "unicodePwd"){
                if ($hide_pwd==1){
	            print "     Update $attr to \"******\" (omitted by --hide)\n";
	        } else {
	            print "     Update $attr to  $sophomorix_first_password\n";
	        }
            } else {
                print "     Update $attr to \"$ref_replace->{$computer}{'REPLACE'}{$attr}\"\n";
            }
        }
        # modify
        my $mesg = $ldap->modify( $dn,
                          replace => { %{ $ref_replace->{$computer}{'REPLACE'} } } 
                         );
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    } else {
        print "\nNot updating, $max results found for computer $computer\n\n";
        exit 88;
    }
    &Sophomorix::SophomorixBase::print_title(
          "Updating computer ${computer_count}/$max_computer_count: $computer (end)");
}



sub AD_group_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school_opt = $arg_ref->{school};
    my $group = $arg_ref->{group};
    my $type_opt = $arg_ref->{type};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $group_count = $arg_ref->{group_count};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my ($existing,
        $type,
        $school,
        $status,
        $description,
        $dn_unused)=
        &AD_get_group({ldap=>$ldap,
                      root_dse=>$root_dse,
                      root_dns=>$root_dns,
                      group=>$group,
                    });

    if (defined $school_opt){
        $school=$school_opt; # override school
    }
    if (defined $type_opt){
        $type=$type_opt; # override type
    }
    if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
        $school_smbshare=$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'};
    } elsif ($school eq "---"){
        $school=$DevelConf::name_default_school;
    }

    my ($smb_share,$unix_dir,$unc,$smb_rel_path_share,$smb_rel_path_homes)=
        &Sophomorix::SophomorixBase::get_sharedirectory($root_dns,$school,$group,$type,$ref_sophomorix_config);

    &Sophomorix::SophomorixBase::print_title("Killing group $group ($type, $school) (start):");
    &AD_remove_sam_from_sophomorix_attributes($ldap,$root_dse,"group",$group);

    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"group",$group);
    if ($count > 0){
        if ($type eq "adminclass" or $type eq "extraclass"){
            ### adminclass #####################################
            if ($smb_share ne  "unknown"){
                my $smbclient_command_rmdir_homes=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                    " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'******' "
                    .$unc." -c 'rmdir \"$smb_rel_path_homes\";'";
                my $smbclient_return_rmdir_homes=&Sophomorix::SophomorixBase::smb_command($smbclient_command_rmdir_homes,
                                                                                           $smb_admin_pass);
                my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                    " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'******' ".
                    $unc." -c 'deltree \"$smb_rel_path_share\";'";
                my $smbclient_return=&Sophomorix::SophomorixBase::smb_command($smbclient_command,$smb_admin_pass);
                my $smbclient_command_ls=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                    " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'******' ".
                    $unc." -c 'ls \"$smb_rel_path_share\";'";
                my $return2=&Sophomorix::SophomorixBase::smb_command($smbclient_command_ls,$smb_admin_pass);
                if($return2==1 or $return2==256){
                    print "OK: Deleted with succes $smb_share\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
                    # deleting the AD account
                    my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                        " group delete ". $group;
                    &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);
                } else {
                    print "ERROR: deltree $unc $smb_rel_path_share $!\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
                }
            }
	} elsif ($type eq "project"){
            # delete the share, when succesful the group
            if ($smb_share ne  "unknown"){

                # rewrite smb_dir with msdfs root
                $smb_share=&Sophomorix::SophomorixBase::rewrite_smb_path($smb_share,$ref_sophomorix_config);

                my $smb = new Filesys::SmbClient(username  => $DevelConf::sophomorix_file_admin,
                                                 password  => $smb_admin_pass,
                                                 debug     => 0);

                my $return1=$smb->rmdir_recurse($smb_share);
                if($return1==1){
                    print "OK: Deleted with succes $smb_share\n"; # smb://linuxmuster.local/<school>/subdir1/subdir2
                    # deleting the AD account
                    my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                        " group delete ". $group;
                    &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);
                } else {
                    print "ERROR: rmdir_recurse $smb_share $!\n";
                }
            }
	} elsif ($type eq "room"){
            ### rooms from sophomorix-device #####################################
            # there is no share, just delete the group
            my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                " group delete ". $group;
            &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);
	} elsif ($type eq "sophomorix-group"){
            ### sophomorix-group #####################################
            # there is no share, just delete the group
            my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                " group delete ". $group;
            &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);
	} elsif ($type eq $ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}){
            ### devicegroup #####################################
            # just delete the group
            my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                " group delete ". $group;
            &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);
	} elsif (exists $ref_sophomorix_config->{'LOOKUP'}{'HOST_GROUP_TYPE'}{$type}){
            # just delete the host group
            my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
                " group delete ". $group;
            &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);
        } else {
            print "ERROR: Not killing Group of unknown type $type\n";
        }
        # log the killing of a group
        &Sophomorix::SophomorixBase::log_group_kill({sAMAccountName=>$group,
                                                     sophomorixType=>$type,
                                                     sophomorixSchoolname=>$school,
                                                     sophomorix_config=>$ref_sophomorix_config,
                                                     sophomorix_result=>$ref_sophomorix_result,
                                                   });
        &Sophomorix::SophomorixBase::print_title("Killing group $group ($type, $school) (end)");
        return;
    } else {
       print "   * Group $group nonexisting ($count results)\n";
       &Sophomorix::SophomorixBase::print_title("Killing group $group ($type, $school) (end)");
       return;
    }
}



sub AD_computer_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $name = $arg_ref->{name};
    my $room = $arg_ref->{room};
    my $room_basename = $arg_ref->{room_basename};
    my $role = $arg_ref->{role};
    my $sophomorix_comment = $arg_ref->{sophomorix_comment};
    my $computer_count = $arg_ref->{computer_count};
    my $max_computer_count = $arg_ref->{max_computer_count};
    my $school = $arg_ref->{school};
    my $filename = $arg_ref->{filename};
    my $mac = $arg_ref->{mac};
    my $dgr_from_file = $arg_ref->{dgr_from_file};
    my $ipv4 = $arg_ref->{ipv4};
    my $creationdate = $arg_ref->{creationdate};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    # calculation
    my $display_name=$name;
    my $smb_name=$name."\$";

    my $creationdate_ok;
    if (defined $creationdate){
        $creationdate_ok=$creationdate;
    } else {
        $creationdate_ok=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'};
    }

    # avoid error for empty attribute
    if (not defined $sophomorix_comment or $sophomorix_comment eq ""){
        $sophomorix_comment="---";
    }

    # sophomorixDnsNodename
    my $s_dns_nodename=$name;
    $s_dns_nodename=~tr/A-Z/a-z/; # in Kleinbuchstaben umwandeln

    # dns
    my $root_dns=&AD_dns_get($root_dse);

    $dns_name=$name.".".$root_dns;
    my @service_principal_name=("HOST/".$name,
                                "HOST/".$dns_name,
                                "RestrictedKrbHost/".$name,
                                "RestrictedKrbHost/".$dns_name,
                               );
    my $room_ou=$ref_sophomorix_config->{'FILES'}{'DEVICE_FILE'}{$filename}{'GROUP_OU'};
    $room_ou=~s/\@\@FIELD_1\@\@/$room_basename/g; 
    my $dn_room = $room_ou.",OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    my $dn="CN=".$name.",".$dn_room;
    my $prefix=$school;
    if ($school eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix="---";
    }

    if($Conf::log_level>=1){
        &Sophomorix::SophomorixBase::print_title(
              "Creating workstation $computer_count: $name");
        print "   DN:                    $dn\n";
        print "   DN(Parent):            $dn_room\n";
        print "   Name:                  $name\n";
        print "   Room:                  $room\n";
        print "   School:                $school\n";
        print "   File:                  $filename\n";
        print "   Prefix:                $prefix\n";
        print "   sAMAccountName:        $smb_name\n";
        print "   dNSHostName:           $dns_name\n";
        print "   sophomorixDnsNodename: $s_dns_nodename\n";
        foreach my $entry (@service_principal_name){
            print "   servicePrincipalName:  $entry\n";
        }
        print "\n";
    }

    if ($json>=1){
        # prepare json object
        my %json_progress=();
        $json_progress{'JSONINFO'}="PROGRESS";
        $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDCOMPUTER_PREFIX_EN'}.
                                     " $name".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDCOMPUTER_POSTFIX_EN'};
        $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDCOMPUTER_PREFIX_DE'}.
                                     " $name ".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDCOMPUTER_POSTFIX_DE'};
        $json_progress{'STEP'}=$computer_count;
        $json_progress{'FINAL_STEP'}=$max_computer_count;
        # print JSON Object
        &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                          json=>$json,
                                                          sophomorix_config=>$ref_sophomorix_config,
                                                        });
    }

    $ldap->add($dn_room,attr => ['objectClass' => ['top', 'organizationalUnit']]);
    my $result = $ldap->add( $dn,
                   attr => [
                   sAMAccountName => $smb_name,
                   displayName => "Computer ".$display_name,
                   dNSHostName => $dns_name,
#                   givenName   =s> "Computer",
#                   sn   => "Account",
#                   cn   => $name_token,
                   cn   => $name,
                   accountExpires => '0', # means never
                   servicePrincipalName => \@service_principal_name,
#                   unicodePwd => $uni_password,
#                   sophomorixExitAdminClass => "unknown", 
                   sophomorixComputerIP => $ipv4,
                   sophomorixComputerMAC => $mac,
                   sophomorixIntrinsic1 => $dgr_from_file,
                   sophomorixComputerRoom => $room,
                   sophomorixStatus => "P",
                   sophomorixAdminClass => $room,    
#                   sophomorixFirstPassword => $sophomorix_first_password, 
#                   sophomorixFirstnameASCII => $firstname_ascii,
#                   sophomorixSurnameASCII  => $surname_ascii,
                   sophomorixRole => $role,
                   sophomorixComment => $sophomorix_comment,
                   sophomorixSchoolPrefix => $prefix,
                   sophomorixSchoolname => $school,
                   sophomorixAdminFile => $filename,
                   sophomorixCreationDate => $creationdate_ok, 
                   sophomorixDnsNodename => $s_dns_nodename, 
                   userAccountControl => '4096',
                   instanceType => '4',
                   objectclass => ['top', 'person',
                                   'organizationalPerson',
                                   'user','computer' ],
#                   'objectClass' => \@objectclass,
                           ]
                           );
    &AD_debug_logdump($result,2,(caller(0))[3]);
}



sub AD_session_manage {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
#    my $creationdate = $arg_ref->{creationdate};
    my $supervisor = $arg_ref->{supervisor};
    my $create = $arg_ref->{create};
    my $kill = $arg_ref->{kill};
    my $session = $arg_ref->{session};
    my $new_comment = $arg_ref->{comment};
    my $developer_session = $arg_ref->{developer_session};
    my $new_participants = $arg_ref->{participants};
    my $ref_sessions = $arg_ref->{sessions_ref};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    # the updated session string
    my $session_string_new="";
    my $session_new="";        

    if (defined $new_comment){
        # remove ; from comment
        $new_comment=~s/;//g;
    }

    # creating the session string
    $session_string="---";
    $session_string_old="---";
    if ($create eq "TRUE"){
        if (not defined $new_participants){
            $new_participants="";
        }
        if ($developer_session ne ""){
            # creating sessions with arbitrary names for testing
            $session_new=$developer_session;
            $session_string_new=$developer_session.";".$new_comment.";".$new_participants.";";
        } else {
            # new session
            # this is the default
            $session_new=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_FILE'};
            $session_string_new=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_FILE'}.
                                ";".$new_comment.";".$new_participants.";";
        }
    } elsif (defined $session and (defined $new_participants or defined $new_comment or $kill eq "TRUE")){
        # modifying the session
        if (defined $ref_sessions->{'ID'}{$session}{'SUPERVISOR'}{'sAMAccountName'}){
            # get data from session hash
            $session_new=$session;
            $supervisor=$ref_sessions->{'ID'}{$session}{'SUPERVISOR'}{'sAMAccountName'};
            $session_string_old=$ref_sessions->{'ID'}{$session}{'sophomorixSessions'};
            my ($unused,$old_comment,$old_participants)=split(/;/,$session_string_old);
            if (not defined $new_participants){
                $new_participants=$old_participants;
            }
            if (not defined $new_comment){
                $new_comment=$old_comment;
            }
	    if (not defined $new_comment){
                $new_comment=$old_comment;
	    }
            $session_string_new=$session.";".$new_comment.";".$new_participants.";";
        } else {
            print "\n Session $session not found\n\n";
            return;
        }
    } else {
        print "\nI do not know what you want me to do\n\n";
        return;
    }

    # locating the supervisors DN
    my ($count,$dn,$rdn)=&AD_object_search($ldap,$root_dse,"user",$supervisor);

    ############################################################
    if ($count==1){
        my %new_sessions=();
        my @new_sessions=();
        my @old_sessions = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"sophomorixSessions");

        # push old sessions into hash (drop doubles)
        foreach my $old_session (@old_sessions){
            my ($id,$old_comment,$old_participants) = split(/;/,$old_session);
            $new_sessions{$id}=$old_comment.";".$old_participants.";";
        }

        if ($kill eq "TRUE"){
	    print "Killing session $session_new\n";
            $session_string_new="---";
            delete $new_sessions{$session_new};
        } else {
            # overwrite the changing session
            $new_sessions{$session_new}=$new_comment.";".$new_participants.";";
        }

        # write the hash into a list
        foreach my $session ( keys %new_sessions ) {
            my $string=$session.";".$new_sessions{$session};
            push @new_sessions, $string;
	    #print "String: $string\n";
        }

        if($Conf::log_level>=1){
            print "   Supervisor:  $supervisor\n";
            print "   DN:          $dn\n";
            print "   Session:     $session_new\n";
            print "      Old:      $session_string_old\n";
            print "      New:      $session_string_new\n";
        }

        # updating session with the hash
        my $mesg = $ldap->modify($dn,
                          replace => {'sophomorixSessions' => \@new_sessions }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    } else {
        print "\nWARNING: User $supervisor not found in ldap, skipping session creation\n\n";
        return;
    }
}



sub AD_user_set_exam_mode {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $supervisor = $arg_ref->{supervisor};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    print "   * Setting exam mode for session participant $participant (Supervisor: $supervisor)\n";
    my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$participant);
    if (not $count==1){
        print "ERROR: Could not set exam mode for nonexisting user $participant\n";
        return 1;
    }
    &AD_user_update({ldap=>$ldap,
                     root_dse=>$root_dse,
                     dn=>$dn,
                     user=>$participant,
                     user_count=>$user_count,
                     max_user_count=>$max_user_count,
                     exammode=>$supervisor,
                     uac_force=>"disable",
                     json=>$json,
                     sophomorix_config=>$ref_sophomorix_config,
                     sophomorix_result=>$ref_sophomorix_result,
                   });
    return 0;
}



sub AD_user_unset_exam_mode {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    print "   * Unsetting exam mode for session participant $participant\n";
    my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$participant);
    if (not $count==1){
        print "ERROR: Could not unset exam mode for nonexisting user $participant\n";
        return 1;
    }
    &AD_user_update({ldap=>$ldap,
                     root_dse=>$root_dse,
                     dn=>$dn,
                     user=>$participant,
                     user_count=>$user_count,
                     max_user_count=>$max_user_count,
                     exammode=>"---",
                     uac_force=>"enable",
                     json=>$json,
                     sophomorix_config=>$ref_sophomorix_config,
                     sophomorix_result=>$ref_sophomorix_result,
                   });
    return 0;
}


sub AD_user_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $identifier = $arg_ref->{identifier};
    my $login = $arg_ref->{login};
    my $group = $arg_ref->{group};
    my $group_basename = $arg_ref->{group_basename};
    my $firstname_ascii = $arg_ref->{firstname_ascii};
    my $surname_ascii = $arg_ref->{surname_ascii};
    my $firstname_utf8 = $arg_ref->{firstname_utf8};
    my $surname_utf8 = $arg_ref->{surname_utf8};
    my $birthdate = $arg_ref->{birthdate};
    my $sophomorix_first_password = $arg_ref->{sophomorix_first_password};
    my $unid = $arg_ref->{unid};
    my $uidnumber_migrate = $arg_ref->{uidnumber_migrate};
    my $school = $arg_ref->{school};
    my $role = $arg_ref->{role};
    my $type = $arg_ref->{type};
    my $creationdate = $arg_ref->{creationdate};
    my $tolerationdate = $arg_ref->{tolerationdate};
    my $deactivationdate = $arg_ref->{deactivationdate};
    my $status = $arg_ref->{status};
    my $file = $arg_ref->{file};
    my $mail = $arg_ref->{mail};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $json = $arg_ref->{json};
    my $ref_webui_permissions_calculated = $arg_ref->{webui_permissions_calculated};
    my $comment = $arg_ref->{comment};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    my $creationdate_ok;
    if (defined $creationdate){
        $creationdate_ok=$creationdate;
    } else {
        $creationdate_ok=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'};
    }

    print "\n";
    &Sophomorix::SophomorixBase::print_title(
          "Creating user $user_count/$max_user_count : $login (start)");

    # set defaults if not defined
    if (not defined $identifier){
        $identifier="---";
    }
    if (not defined $uidnumber_migrate){
        $uidnumber_migrate="---";
    }

    if ($tolerationdate eq "---"){
        $tolerationdate=$DevelConf::default_date;
    }
    if ($deactivationdate eq "---"){
        $deactivationdate=$DevelConf::default_date;
    }
    $school=&AD_get_schoolname($school);

    $group=&Sophomorix::SophomorixBase::replace_vars($group,$ref_sophomorix_config,$school);
    $group_basename=&Sophomorix::SophomorixBase::replace_vars($group_basename,$ref_sophomorix_config,$school);

    # calculate
    my $shell="/bin/false";
    my $display_name = $firstname_utf8." ".$surname_utf8;
    my $user_principal_name = $login."\@".$root_dns;
    
    # calculate mail attribute, if not given as sub parameter
    if (not defined $mail){
        $mail = $login."\@".$root_dns;
        if ( exists $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAILDOMAIN'}){
            if ($ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAILDOMAIN'} ne ""){
                $mail=$login."\@".$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAILDOMAIN'};
            }
	}
    }

    my ($homedirectory,$unix_home,$unc,$smb_rel_path)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school,
                                                       $group_basename,
                                                       $login,
                                                       $role,
                                                       $ref_sophomorix_config);
    # ou
    my $class_ou;
    my $dn_class;
    my $dn;
    if ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        $class_ou=$ref_sophomorix_config->{'INI'}{'administrator.global'}{'SUB_OU'};
        $dn_class=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{ADMINS}{OU};
        $dn="cn=".$login.",".$dn_class;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        $class_ou=$ref_sophomorix_config->{'INI'}{'administrator.school'}{'SUB_OU'};
        $dn_class=$ref_sophomorix_config->{'SCHOOLS'}{$school}{ADMINS}{OU};
	$dn="cn=".$login.",".$dn_class;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        $class_ou=$ref_sophomorix_config->{'INI'}{'binduser.global'}{'SUB_OU'};
        $dn_class=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{ADMINS}{OU};
        $dn="cn=".$login.",".$dn_class;
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        $class_ou=$ref_sophomorix_config->{'INI'}{'binduser.school'}{'SUB_OU'};
        $dn_class=$ref_sophomorix_config->{'SCHOOLS'}{$school}{ADMINS}{OU};
	$dn="cn=".$login.",".$dn_class;
    } else {
        # from file
        $class_ou=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'GROUP_OU'};
        $class_ou=~s/\@\@FIELD_1\@\@/$group_basename/g; 
        $dn_class = $class_ou.",OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
        $dn="CN=".$login.",".$dn_class;
    }

    # password generation
    my $uni_password=&_unipwd_from_plainpwd($sophomorix_first_password);

    ## build the conversion map from your local character set to Unicode    
    #my $charmap = Unicode::Map8->new('latin1')  or  die;
    ## surround the PW with double quotes and convert it to UTF-16
    #my $uni_password = $charmap->tou('"'.$sophomorix_first_password.'"')->byteswap()->utf16();

    my $prefix=$school;
    if ($school eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix="---";
    }

    if (not defined $comment or $comment eq "---"){
        $comment="created by sophomorix";
    }
    
    # settingthe dates according to status
    if (defined $status and $status eq "T"){
        $deactivationdate=$DevelConf::default_date;
    } elsif ($status eq "deaktivate" and $deactivationdate ne "---"){
        # extraclass users
        $status="T";
    } elsif (defined $status and 
       ($status eq "U" or 
        $status eq "A" or 
        $status eq "E" or 
        $status eq "S" or 
        $status eq "P" )){
        $deactivationdate=$DevelConf::default_date;
        $tolerationdate=$DevelConf::default_date;
    }

    if ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        $sophomorix_first_password="---";
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        $sophomorix_first_password="---";
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        $sophomorix_first_password="---";
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        $sophomorix_first_password="---";
    } else {
        # user from a file
        # keep $sophomorix_first_password
    }

    my $firstname_initial_utf8=&Sophomorix::SophomorixBase::extract_initial($firstname_utf8);
    my $surname_initial_utf8=&Sophomorix::SophomorixBase::extract_initial($surname_utf8);

    if($Conf::log_level>=1){
        print "   DN:                 $dn\n";
        print "   DN(Parent):         $dn_class\n";
        print "   Surname(ASCII):     $surname_ascii\n";
        print "   Surname(UTF8):      $surname_utf8\n";
        print "   Firstname(ASCII):   $firstname_ascii\n";
        print "   Firstname(UTF8):    $firstname_utf8\n";
        print "   Initials(UTF8):     $firstname_initial_utf8 $surname_initial_utf8\n";
        print "   Birthday:           $birthdate\n";
        print "   Identifier:         $identifier\n";
        print "   School:             $school\n"; # Organisatinal Unit
        print "   Role(User):         $role\n";
        print "   Status:             $status\n";
        print "   Type(Group):        $type\n";
        print "   Group:              $group ($group_basename)\n"; # lehrer oder klasse
        #print "   GECOS:              $gecos\n";
        #print "   Login (to check):   $login_name_to_check\n";
        print "   Login (check OK):   $login\n";
        print "   Password:           $sophomorix_first_password\n";
        # sophomorix stuff
        print "   Creationdate:       $creationdate_ok\n";
        print "   Tolerationdate:     $tolerationdate\n";
        print "   Deactivationdate:   $deactivationdate\n";
        print "   Unid:               $unid\n";
        print "   Unix-uidNumber:     $uidnumber_migrate\n";
        print "   File:               $file\n";
        print "   Mail:               $mail\n";
        print "   homeDirectory:      $homedirectory\n";
        print "   unixHomeDirectory:  $unix_home\n";
        if (defined $ref_webui_permissions_calculated){
            foreach my $item ( @{ $ref_webui_permissions_calculated } ){
                print "   WebuiPermCalc:      $item\n";
            }
        }
    }

    if ($json>=1){
        # prepare json object
        my %json_progress=();
        $json_progress{'JSONINFO'}="PROGRESS";
        $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDUSER_PREFIX_EN'}.
                                     " $login ($firstname_utf8 $surname_utf8)".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDUSER_POSTFIX_EN'};
        $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDUSER_PREFIX_DE'}.
                                     " $login ($firstname_utf8 $surname_utf8) ".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDUSER_POSTFIX_DE'};
        $json_progress{'STEP'}=$user_count;
        $json_progress{'FINAL_STEP'}=$max_user_count;
        # print JSON Object
        &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                          json=>$json,
                                                          sophomorix_config=>$ref_sophomorix_config,
                                                        });
    }

    # make sure $dn_class exists
    $ldap->add($dn_class,attr => ['objectClass' => ['top', 'organizationalUnit']]);

    my $user_account_control;
    if (defined $status and $status ne "---"){
        if ($status eq "L" or
            $status eq "D" or
            $status eq "F" or
            $status eq "R" or
            $status eq "K"
            ){
	    $user_account_control=$DevelConf::default_user_account_control_disabled;
	} else {
	    $user_account_control=$DevelConf::default_user_account_control;
        }
    }

    # create quotalist
    my @quotalist;
    if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
        # school <global>: only one quota entry
        @quotalist=("$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NEWUSER'}:---:"); 
   } else {
       # other schools: global + school quota entry
       @quotalist=("$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NEWUSER'}:---:",
                   "$school:---:---:$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NEWUSER'}:---:");
    }

    # add the user
    my $add_array = [
        objectClass => ['top','person','organizationalPerson','user'],
        sAMAccountName => $login,
        givenName => $firstname_utf8,
        sn => $surname_utf8,
        displayName => [$display_name],
        userPrincipalName => $user_principal_name,
        mail => $mail,
        unicodePwd => $uni_password,
        homeDrive => "H:",
        homeDirectory => $homedirectory,
        sophomorixIntrinsic2 => $smb_rel_path,
        unixHomeDirectory => $unix_home,
        sophomorixExitAdminClass => "unknown", 
        sophomorixUnid => $unid,
        sophomorixStatus => $status,
        sophomorixAdminClass => $group,    
        sophomorixAdminFile => $file,    
        sophomorixFirstPassword => $sophomorix_first_password, 
        sophomorixFirstnameASCII => $firstname_ascii,
        sophomorixSurnameASCII  => $surname_ascii,
        sophomorixBirthdate  => $birthdate,
        sophomorixRole => $role,
        sophomorixUserToken => "---",
        sophomorixFirstnameInitial => $firstname_initial_utf8,
        sophomorixSurnameInitial => $surname_initial_utf8,
        sophomorixQuota=> [@quotalist],
        sophomorixMailQuota=>"---:---:",
        sophomorixMailQuotaCalculated=>$ref_sophomorix_config->{'INI'}{'MAILQUOTA'}{'CALCULATED_DEFAULT'},
        sophomorixCloudQuotaCalculated=>"---",
        sophomorixSchoolPrefix => $prefix,
        sophomorixSchoolname => $school,
        sophomorixCreationDate => $creationdate_ok, 
        sophomorixTolerationDate => $tolerationdate, 
        sophomorixDeactivationDate => $deactivationdate, 
        sophomorixComment => $comment, 
        sophomorixWebuiDashboard => "---",
        sophomorixExamMode => "---", 
        userAccountControl => $user_account_control,
        accountExpires => 0,
                    ];
    if (defined $uidnumber_migrate and $uidnumber_migrate ne "---"){
        my $intrinsic_string="MIGRATION uidNumber: ".$uidnumber_migrate;
        push @{ $add_array }, "sophomorixIntrinsic1", $intrinsic_string;
    }


    # add sophomorixWebuiPermissionsCalculated only if defined
    if (defined $ref_webui_permissions_calculated){
        if ($#{ $ref_webui_permissions_calculated  } > -1){
            # array not empty, use it
            push @{ $add_array },"sophomorixWebuiPermissionsCalculated",$ref_webui_permissions_calculated;
        } else {
            # empty array cannot be uploaded in AD, do not use it
        }
    }

    # do it
    my $result = $ldap->add( $dn, attr => [@{ $add_array }]);

    my $add_result=&AD_debug_logdump($result,2,(caller(0))[3]);
    if ($add_result!=0){ # add was succesful
        # log the addition of a user
        &Sophomorix::SophomorixBase::log_user_add({sAMAccountName=>$login,
                                                   sophomorixRole=>$role, 
                                                   #home_delete_string=>$home_delete_string,
                                                   sophomorixSchoolname=>$school,
                                                   firstname=>$firstname_utf8,    
                                                   lastname=>$surname_utf8,
                                                   adminclass=>$group,
                                                   unid=>$unid,
                                                   sophomorix_config=>$ref_sophomorix_config,
                                                   sophomorix_result=>$ref_sophomorix_result,
                                                 });
    }

    ######################################################################
    # memberships of created user
    ######################################################################
    # add user to rolegroup
    my $rolegroup="role-".$role;
    &AD_group_addmember({ldap => $ldap,
                         root_dse => $root_dse,
                         group => $rolegroup,
                         addmember => $login,
                       });
    # other memberships
    if ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        #######################################################
        # global binduser
        #######################################################
        my @manmember=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'binduser.global'}{'MANMEMBEROF'});
        foreach my $mangroup (@manmember){
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
        my @member=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'binduser.global'}{'MEMBEROF'});
        foreach my $group (@member){
            &AD_group_addmember({ldap => $ldap,
                                  root_dse => $root_dse, 
                                  group => $group,
                                  addmember => $login,
                                });
        }
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        #######################################################
        # school binduser
        #######################################################
        my @manmember=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'binduser.school'}{'MANMEMBEROF'});
        foreach my $mangroup (@manmember){
            $mangroup=&Sophomorix::SophomorixBase::replace_vars($mangroup,$ref_sophomorix_config,$school);
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
        my @member=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'binduser.school'}{'MEMBEROF'});
        foreach my $group (@member){
            $group=&Sophomorix::SophomorixBase::replace_vars($group,$ref_sophomorix_config,$school);
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $group,
                                 addmember => $login,
                               });
        }
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        #######################################################
        # global administrator
        #######################################################
        my @manmember=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.global'}{'MANMEMBEROF'});
        foreach my $mangroup (@manmember){
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
        my @member=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.global'}{'MEMBEROF'});
        foreach my $group (@member){
            &AD_group_addmember({ldap => $ldap,
                                  root_dse => $root_dse, 
                                  group => $group,
                                  addmember => $login,
                                });
        }
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        #######################################################
        # school administrator
        #######################################################
        my @manmember=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.school'}{'MANMEMBEROF'});
        foreach my $mangroup (@manmember){
            $mangroup=&Sophomorix::SophomorixBase::replace_vars($mangroup,$ref_sophomorix_config,$school);
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
        my @member=&Sophomorix::SophomorixBase::ini_list($ref_sophomorix_config->{'INI'}{'administrator.school'}{'MEMBEROF'});
        foreach my $group (@member){
            $group=&Sophomorix::SophomorixBase::replace_vars($group,$ref_sophomorix_config,$school);
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $group,
                                 addmember => $login,
                               });
        }
    } else {
        #######################################################
        # user from a file -> get groups from sophomorix_config 
        #######################################################
        # add user to groups
        # MEMBEROF
        foreach my $ref_group (@{ $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'MEMBEROF'} }){
            my $group=$ref_group; # make copy to not modify the hash 
            $group=~s/\@\@FIELD_1\@\@/$group_basename/g; 
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $group,
                                 addmember => $login,
                               }); 
	}

        # SOPHOMORIXMEMBEROF = MEMBEROF + sophomorixMember attribute
        foreach my $ref_s_group (@{ $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'SOPHOMORIXMEMBEROF'} }){
            my $s_group=$ref_s_group; # make copy to not modify the hash 
            $s_group=&Sophomorix::SophomorixBase::replace_vars($s_group,$ref_sophomorix_config,$school);
            $s_group=~s/\@\@FIELD_1\@\@/$group_basename/g; 
            # find dn of adminclass.group
            my ($count,$dn_class,$cn_exist,$infos)=&AD_object_search($ldap,$root_dse,"group",$s_group);
            # fetch old members from sophomorixmembers
            my @old_members = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn_class,"sophomorixMembers");
            # create a unique list of new members
            my @members = uniq(@old_members,$login); 
            my $members=join(",",@members);
            # update group
            &AD_group_update({ldap=>$ldap,
                              root_dse=>$root_dse,
                              dn=>$dn_class,
                              type=>"adminclass",
                              members=>$members,
                              sophomorix_config=>$ref_sophomorix_config,
                            });
	}

        # MANMEMBEROF
        # add user to management groups
        foreach my $ref_mangroup (@{ $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'MANMEMBEROF'} }){
            my $mangroup=$ref_mangroup; # make copy to not modify the hash 
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $mangroup,
                                            addmember => $login,
                                           }); 
        }
    }

    ############################################################
    # Create filesystem
    ############################################################
    if ($role eq $ref_sophomorix_config->{'INI'}{'administrator.school'}{'USER_ROLE'}){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.schooladministrator_home",
                               school=>$school,
                               administrator_home=>$login,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'administrator.global'}{'USER_ROLE'}){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.globaladministrator_home",
                               school=>$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},
                               administrator_home=>$login,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.school'}{'USER_ROLE'}){
        # no home
        &Sophomorix::SophomorixBase::print_title("NOT creating HOME: $login (sophomorixRole $role)");
    } elsif ($role eq $ref_sophomorix_config->{'INI'}{'binduser.global'}{'USER_ROLE'}){
        # no home
        &Sophomorix::SophomorixBase::print_title("NOT creating HOME: $login (sophomorixRole $role)");
    } elsif ($role eq "teacher"){
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.teacher_home",
                                   school=>$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},
                                   teacherclass=>$group,
                                   teacher_home=>$login,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        } else {
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.teacher_home",
                                   school=>$school,
                                   teacherclass=>$group,
                                   teacher_home=>$login,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        }
    } elsif ($role eq "student"){
        if ($school eq $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SCHOOLNAME'}){
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.student_home",
                                   school=>$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},
                                   adminclass=>$group,
                                   student_home=>$login,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        } else {
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.student_home",
                                   school=>$school,
                                   adminclass=>$group,
                                   student_home=>$login,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        }
    }  

    &Sophomorix::SophomorixBase::print_title("Creating user $user_count: $login (end)");
    print "\n";
}



sub AD_user_update {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $dn = $arg_ref->{dn};
    my $firstname_ascii = $arg_ref->{firstname_ascii};
    my $surname_ascii = $arg_ref->{surname_ascii};
    my $firstname_utf8 = $arg_ref->{firstname_utf8};
    my $surname_initial_utf8 = $arg_ref->{surname_initial_utf8};
    my $firstname_initial_utf8 = $arg_ref->{firstname_initial_utf8};
    my $surname_utf8 = $arg_ref->{surname_utf8};
    my $filename = $arg_ref->{filename};
    my $birthdate = $arg_ref->{birthdate};
    my $unid = $arg_ref->{unid};
    my $quota = $arg_ref->{quota};
    my $quota_force = $arg_ref->{quota_force};
    my $quota_calc = $arg_ref->{quota_calc};
    my $quota_info = $arg_ref->{quota_info};
    my $mailquota = $arg_ref->{mailquota};
    my $mailquota_calc = $arg_ref->{mailquota_calc};
    my $cloudquota_calc = $arg_ref->{cloudquota_calc};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $hide_pwd = $arg_ref->{hide_pwd};
    my $user = $arg_ref->{user};
    my $firstpassword = $arg_ref->{firstpassword}; # sophomorixFirstpassword
    my $sophomorix_first_password = $arg_ref->{sophomorix_first_password}; # unicodePwd
    my $smbpasswd = $arg_ref->{smbpasswd};
    my $status = $arg_ref->{status};
    my $comment = $arg_ref->{comment};
    my $homedirectory = $arg_ref->{homedirectory};
    my $homedirectory_rel = $arg_ref->{homedirectory_rel};
    # change proxyAddresses (multi-value)
    my $proxy_addresses_set = $arg_ref->{proxy_addresses_set};
    my $proxy_addresses_add = $arg_ref->{proxy_addresses_add};
    my $proxy_addresses_remove = $arg_ref->{proxy_addresses_remove};
    my $proxy_addresses_entry = $arg_ref->{proxy_addresses_entry};
    # changing OTHER single-value attributes
    my $single_value_set = $arg_ref->{single_value_set};
    my $single_value_entry = $arg_ref->{single_value_entry};
    # changing OTHER multi-value attributes
    my $multi_value_set = $arg_ref->{multi_value_set};
    my $multi_value_add = $arg_ref->{multi_value_add};
    my $multi_value_remove = $arg_ref->{multi_value_remove};
    my $multi_value_entry = $arg_ref->{multi_value_entry};
    # custom attributes
    my $custom_1 = $arg_ref->{custom_1};
    my $custom_2 = $arg_ref->{custom_2};
    my $custom_3 = $arg_ref->{custom_3};
    my $custom_4 = $arg_ref->{custom_4};
    my $custom_5 = $arg_ref->{custom_5};
    my $custom_multi_1 = $arg_ref->{custom_multi_1};
    my $custom_multi_2 = $arg_ref->{custom_multi_2};
    my $custom_multi_3 = $arg_ref->{custom_multi_3};
    my $custom_multi_4 = $arg_ref->{custom_multi_4};
    my $custom_multi_5 = $arg_ref->{custom_multi_5};
    # intrinsic attributes
    my $intrinsic_1 = $arg_ref->{intrinsic_1};
    my $intrinsic_2 = $arg_ref->{intrinsic_2};
    my $intrinsic_3 = $arg_ref->{intrinsic_3};
    my $intrinsic_4 = $arg_ref->{intrinsic_4};
    my $intrinsic_5 = $arg_ref->{intrinsic_5};
    my $intrinsic_multi_1 = $arg_ref->{intrinsic_multi_1};
    my $intrinsic_multi_2 = $arg_ref->{intrinsic_multi_2};
    my $intrinsic_multi_3 = $arg_ref->{intrinsic_multi_3};
    my $intrinsic_multi_4 = $arg_ref->{intrinsic_multi_4};
    my $intrinsic_multi_5 = $arg_ref->{intrinsic_multi_5};
    #
    my $mail = $arg_ref->{mail};
    my $webui_dashboard = $arg_ref->{webui_dashboard};
    my $webui_permissions = $arg_ref->{webui_permissions};
    my $ref_webui_permissions_calculated = $arg_ref->{webui_permissions_calculated};
    my $school = $arg_ref->{school};
    my $role = $arg_ref->{role};
    my $examteacher = $arg_ref->{exammode};
    my $uac_force = $arg_ref->{uac_force};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};
    # start with empty sharelist
    my @sharelist=();
    
    my $update_log_string="";

    if (not defined $max_user_count){
	$max_user_count="-";
    }

    if (not defined $smbpasswd){
        $smbpasswd="FALSE";
    }
    
    
    my ($firstname_utf8_AD,
        $lastname_utf8_AD,
        $adminclass_AD,
        $existing_AD,
        $exammode_AD,
        $role_AD,
        $home_directory_AD,
        $user_account_control_AD,
        $toleration_date_AD,
        $deactivation_date_AD,
        $school_AD,
        $status_AD,
        $firstpassword_AD,
        $unid_AD
       )=&AD_get_user({ldap=>$ldap,
                       root_dse=>$root_dse,
                       root_dns=>$root_dns,
                       user=>$user,
                     });

    # hash of what to replace
    my %replace=();
    # list of what to delete
    my @delete=();

    print "\n";
    &Sophomorix::SophomorixBase::print_title(
          "Updating User ${user_count}/$max_user_count: $user (start)");
    print "   DN: $dn\n";

    if (defined $firstname_utf8 and $firstname_utf8 ne "---"){
        $replace{'givenName'}=$firstname_utf8;
        print "   givenName:                  $firstname_utf8\n";
    }
    if (defined $surname_utf8 and $surname_utf8 ne "---"){
        $replace{'sn'}=$surname_utf8;
        print "   sn:                         $surname_utf8\n";
    }

   # IF first AND last are defined AND one of them is NOT "---" -> update displayname
   if ( (defined $firstname_utf8 and defined $surname_utf8) and 
        ($firstname_utf8 ne "---" or $surname_utf8 ne "---") ){
        # update displayname
        if ($firstname_utf8 ne "---" and $surname_utf8 ne "---"  ){
           $display_name = $firstname_utf8." ".$surname_utf8;
        } elsif ($firstname_utf8 eq "---"){
           $display_name = $firstname_utf8_AD." ".$surname_utf8;
        } elsif ($surname_utf8 eq "---"){
           $display_name = $firstname_utf8." ".$lastname_utf8_AD;
        }
        $replace{'displayName'}=$display_name;
        print "   displayName:                $display_name\n";
    }
    if (defined $firstname_initial_utf8 and $firstname_initial_utf8 ne "---" ){
        $replace{'sophomorixFirstnameInitial'}=$firstname_initial_utf8;
        print "   sophomorixFirstnameInitial: $firstname_initial_utf8\n";
    }
    if (defined $surname_initial_utf8 and $surname_initial_utf8 ne "---" ){
        $replace{'sophomorixSurnameInitial'}=$surname_initial_utf8;
        print "   sophomorixSurnameInitial:   $surname_initial_utf8\n";
    }
    if (defined $firstname_ascii and $firstname_ascii ne "---" ){
        $replace{'sophomorixFirstnameASCII'}=$firstname_ascii;
        print "   sophomorixFirstnameASCII:   $firstname_ascii\n";
    }
    if (defined $surname_ascii and $surname_ascii ne "---"){
        $replace{'sophomorixSurnameASCII'}=$surname_ascii;
        print "   sophomorixSurnameASCII:     $surname_ascii\n";
    }
    if (defined $birthdate and $birthdate ne "---"){
        $replace{'sophomorixBirthdate'}=$birthdate;
        print "   sophomorixBirthdate:        $birthdate\n";
    }
    if (defined $filename and $filename ne "---"){
        $replace{'sophomorixAdminFile'}=$filename;
        print "   sophomorixAdminFile:        $filename\n";
    }
    if (defined $mail and $mail ne "---"){
        $replace{'mail'}=$mail;
        print "   mail:                       $mail\n";
    }
    if (defined $unid and $unid ne "---"){
        if ($unid eq ""){
            $unid="---"; # upload --- for empty unid
        }
        $replace{'sophomorixUnid'}=$unid;
        print "   sophomorixUnid:             $unid\n";
    }
    # firstpassword for sophomorixFirstpassword
    if (defined $firstpassword){
        $replace{'sophomorixFirstPassword'}=$firstpassword;
	if ($hide_pwd==1){
	    print "   sophomorixFirstPassword: ****** (omitted by --hide)\n";
	} else {
	    print "   sophomorixFirstPassword: $firstpassword\n";
	}
    }

    # firstpassword (to create hashed password)
    if (defined $sophomorix_first_password){
        my $uni_password=&_unipwd_from_plainpwd($sophomorix_first_password);
        if ($smbpasswd eq "TRUE"){
            # update password later with smbpasswd
	} else {
	    $replace{'unicodePwd'}=$uni_password;
  	    if ($hide_pwd==1){
	        print "   unicodePwd:                 ****** (omitted by --hide)\n";
	    } else {
	        print "   unicodePwd:                 $sophomorix_first_password\n";
	    }
	}
    }

    # quota
    if (defined $quota){
        if (not defined $quota_force){
            $quota_force="FALSE";
        }
        my %quota_new=();
        my @quota_new=();
        my @quota_old = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,"sophomorixQuota");
        foreach my $quota_old (@quota_old){
            my ($share,$value,$calc,$info,$comment)=split(/:/,$quota_old);
            if (not defined $calc){$calc="---";}
            if (not defined $calc){$info="---";}
	    # save old values in quota_new
            $quota_new{'QUOTA'}{$share}{'VALUE'}=$value;
            $quota_new{'QUOTA'}{$share}{'OLD_INDIVIDUAL_VALUE'}=$value;
            $quota_new{'QUOTA'}{$share}{'CALC'}=$calc;
            $quota_new{'QUOTA'}{$share}{'INFO'}=$info;
            $quota_new{'QUOTA'}{$share}{'COMMENT'}=$comment;
	    push @sharelist, $share;
        }
        # work on NEW Quota, given by option
	my @schoolquota=split(/,/,$quota);
	foreach my $schoolquota (@schoolquota){
	    my ($share,$value,$comment)=split(/:/,$schoolquota);
	    if (not exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}){
                print "\nERROR: SMB-share $share does not exist!\n\n";
		exit;
	    }
            if ($value=~/[^0-9]/ and $value ne "-1" and $value ne "---"){
                print "\nERROR: Quota value $value does not consist ",
                      "of numerals 0-9 or is -1 or is \"---\"\n\n";
		exit;
	    }
            # overriding quota_new:
            # -----------------------
            # A) user value (used by sophomorix-user)
	    if ($quota_force eq "TRUE"){
                # use new forced value
                $quota_new{'QUOTA'}{$share}{'VALUE_FORCE'}="TRUE";
                $quota_new{'QUOTA'}{$share}{'VALUE'}=$value;
            } else {
                # use old individual value
                $quota_new{'QUOTA'}{$share}{'VALUE_FORCE'}="FALSE";
                $quota_new{'QUOTA'}{$share}{'VALUE'}=$quota_new{'QUOTA'}{$share}{'OLD_INDIVIDUAL_VALUE'};
            }

            # B) calc value (used by sophomorix-quota)
            if (defined $quota_calc){
                $quota_new{'QUOTA'}{$share}{'CALC'}=$quota_calc;
            } else {
                 $quota_new{'QUOTA'}{$share}{'CALC'}="---";
            }
            # C) info value (used by sophomorix-quota AFTER quota is set successfully)
            if (defined $quota_info){
                $quota_new{'QUOTA'}{$share}{'INFO'}=$quota_info;
            } else {
                $quota_new{'QUOTA'}{$share}{'INFO'}=
                    $ref_sophomorix_config->{'INI'}{'QUOTA'}{'UPDATEUSER'};
	    }
            # D) comment
            if (defined $comment){
                $quota_new{'QUOTA'}{$share}{'COMMENT'}=$comment;
            }
   	    push @sharelist, $share;
	}
        # debug
        #print "OLD: @quota_old\n";
	#print Dumper(%quota_new);
	#print "Sharelist: @sharelist\n";
        # prepare ldap modify list
	@sharelist = uniq(@sharelist);
	@sharelist = sort(@sharelist);
	foreach my $share (@sharelist){
            if ($quota_new{'QUOTA'}{$share}{'VALUE'} eq "---" and 
                $share ne $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'} and
                $share ne $school_AD){
                # push NOT in @quota_new -> attribute will be removed
	    } else {
		# push -> keep attribute
		if (not exists $quota_new{'QUOTA'}{$share}{'CALC'}){
                    # new share
                    $quota_new{'QUOTA'}{$share}{'CALC'}="---";
                }
		if (not defined $quota_new{'QUOTA'}{$share}{'COMMENT'}){
                    $quota_new{'QUOTA'}{$share}{'COMMENT'}="---";
		}
		push @quota_new, $share.":".
                                 $quota_new{'QUOTA'}{$share}{'VALUE'}.":".
                                 $quota_new{'QUOTA'}{$share}{'CALC'}.":".
                                 $quota_new{'QUOTA'}{$share}{'INFO'}.":".
                                 $quota_new{'QUOTA'}{$share}{'COMMENT'}.":";
	    }
	}
	print "   * Setting sophomorixQuota to: @quota_new\n";
        my $quota_new_string=join("|",@quota_new);
        $update_log_string=$update_log_string."\"sophomorixQuota=".$quota_new_string."\",";
        my $mesg = $ldap->modify($dn,replace => { sophomorixQuota => \@quota_new }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # mailquota
    if (defined $mailquota){
        my ($value,$comment)=split(/:/,$mailquota);
        if (not defined $comment){
            $comment="---";
        }
        my $mailquota_new=$value.":".$comment.":";
        $replace{'sophomorixMailQuota'}=$mailquota_new;
        print "   sophomorixMailQuota:        $mailquota_new\n";
    }
    
    # mailquota_calc
    if (defined $mailquota_calc){
        $replace{'sophomorixMailQuotaCalculated'}=$mailquota_calc;
        print "   sophomorixMailQuotaCalculated:        $mailquota_calc\n";
    }
    
    # cloudquota_calc
    if (defined $cloudquota_calc){
        $replace{'sophomorixCloudQuotaCalculated'}=$cloudquota_calc;
        print "   sophomorixCloudQuotaCalculated:       $cloudquota_calc\n";
    }

    # status
    if (defined $status and $status ne "---"){
        $replace{'sophomorixStatus'}=$status;
        print "   sophomorixStatus:           $status\n";
        # setting userAccountControl and Dates
        my $user_account_control;
        my $toleration_date;
        my $deactivation_date;
        if ($status eq "U" or
            $status eq "E" or
            $status eq "A" or
            $status eq "S" or
            $status eq "P" 
            ){
            # Status U,E,A,S,P
            $user_account_control=&_uac_enable_user($user_account_control_AD);
            $toleration_date=$DevelConf::default_date;
            $deactivation_date=$DevelConf::default_date;
        } elsif  ($status eq "T"){
            # Status T
            $user_account_control=&_uac_enable_user($user_account_control_AD);
            $toleration_date=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'};
            $deactivation_date=$DevelConf::default_date;
        } elsif  ($status eq "D" or
                  $status eq "F" or
                  $status eq "L"){
            # Status D,F,L
            $user_account_control=&_uac_disable_user($user_account_control_AD);
            $toleration_date=$toleration_date_AD;
            $deactivation_date=$ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'};
        } elsif  ($status eq "K" or
                  $status eq "R"){
            # Status K,R
            $user_account_control=&_uac_disable_user($user_account_control_AD);
            $toleration_date=$toleration_date_AD;
            $deactivation_date=$deactivation_date_AD;
        } else {
            # unknown status
            print "\nERROR: status $status not definned\n\n";
            return;
        }

        # setting the hash
        $replace{'userAccountControl'}=$user_account_control;
        $replace{'sophomorixTolerationDate'}=$toleration_date;
        $replace{'sophomorixDeactivationDate'}=$deactivation_date;
        # print what is set
        print "   sophomorixTolerationDate:   $toleration_date\n";
        print "   sophomorixDeactivationDate: $deactivation_date\n";
        print "   userAccountControl:         $user_account_control",
              " (was: $user_account_control_AD)\n";
    }
    # update userAccountControl for exam users
    if (defined $uac_force and not defined $status){
        my $user_account_control;
        if ($uac_force eq "enable"){
            $user_account_control=&_uac_enable_user($user_account_control_AD);
            $replace{'userAccountControl'}=$user_account_control;
            print "   userAccountControl:         $user_account_control",
                  " (was: $user_account_control_AD)\n";
        } elsif ($uac_force eq "disable"){
            $user_account_control=&_uac_disable_user($user_account_control_AD);
            $replace{'userAccountControl'}=$user_account_control;
            print "   userAccountControl:         $user_account_control",
                  " (was: $user_account_control_AD)\n";
	}
    }
    if (defined $school and $school ne "---"){
        # update sophomorixSchoolname AND sophomorixSchoolPrefix
        $replace{'sophomorixSchoolname'}=$school;
        print "   sophomorixSchoolname:       $school\n";
        my $prefix;
        if ($school eq $DevelConf::name_default_school){
            $prefix="---";
        } else {
            $prefix=$school;
        }
        $replace{'sophomorixSchoolPrefix'}=$prefix;
        print "   sophomorixSchoolPrefix:     $prefix\n";
    } else {
        $school="---";
    }
    if (defined $role and $role ne "---"){
        $replace{'sophomorixRole'}=$role;
        print "   sophomorixRole:             $role\n";
    }
    if (defined $examteacher and $examteacher ne ""){
        $replace{'sophomorixExamMode'}=$examteacher;
        print "   sophomorixExamMode:         $examteacher\n";
    }
    if (defined $comment){
        if ($comment eq ""){
            # delete attr if empty
            push @delete, "sophomorixComment";
        } else {
            $replace{'sophomorixComment'}=$comment;
        }
        print "   sophomorixComment:          $comment\n";
    }

    # homedirectory
    if (defined $homedirectory and $homedirectory ne "---"){
        $replace{'homeDirectory'}=$homedirectory;
        print "   homeDirectory:       $homedirectory\n";
    }

    # homedirectory_rel
    if (defined $homedirectory_rel and $homedirectory_rel ne "---"){
        $replace{'sophomorixIntrinsic2'}=$homedirectory_rel;
        print "   sophomorixIntrinsic2:       $homedirectory_rel\n";
    }

    # custom attributes
    if (defined $custom_1){
        if ($custom_1 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom1";
        } else {
            $replace{'sophomorixCustom1'}=$custom_1;
        }
        print "   sophomorixCustom1:          $custom_1\n";
    }
    if (defined $custom_2){
        if ($custom_2 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom2";
        } else {
            $replace{'sophomorixCustom2'}=$custom_2;
        }
        print "   sophomorixCustom2:          $custom_2\n";
    }
    if (defined $custom_3){
        if ($custom_3 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom3";
        } else {
            $replace{'sophomorixCustom3'}=$custom_3;
        }
        print "   sophomorixCustom3:          $custom_3\n";
    }
    if (defined $custom_4){
        if ($custom_4 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom4";
        } else {
            $replace{'sophomorixCustom4'}=$custom_4;
        }
        print "   sophomorixCustom4:          $custom_4\n";
    }
    if (defined $custom_5){
        if ($custom_5 eq ""){
            # delete attr if empty
            push @delete, "sophomorixCustom5";
        } else {
            $replace{'sophomorixCustom5'}=$custom_5;
        }
        print "   sophomorixCustom5:          $custom_5\n";
    }

    # OTHER single-value attributes
    if (defined $single_value_set and defined $single_value_entry){
        if ($single_value_entry eq ""){
            # delete attr if empty
            push @delete, $single_value_set;
            print "   $single_value_set:      DELETE\n";
        } else {
            $replace{$single_value_set}=$single_value_entry;
            print "   $single_value_set:      $single_value_entry\n";
        }
    }

    # OTHER multi-value attributes
    if (defined $multi_value_set and defined $multi_value_entry){
        my @multi_value_entry=split(/,/,$multi_value_entry);
        @multi_value_entry = reverse @multi_value_entry;
        print "   * Setting $multi_value_set to: @multi_value_entry\n";
        my $multi_value_entry_string=join("|",@multi_value_entry);
        $update_log_string=$update_log_string."\"".$multi_value_set."=".$multi_value_entry_string."\",";
        my $mesg = $ldap->modify($dn,replace => {$multi_value_set => \@multi_value_entry }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $multi_value_add and defined $multi_value_entry){
        my @multi_value_entry=split(/,/,$multi_value_entry);
        @multi_value_entry = reverse @multi_value_entry;
        print "   * Setting $multi_value_add to: @multi_value_entry\n";
        my $multi_value_entry_string=join("|",@multi_value_entry);
        $update_log_string=$update_log_string."\"".$multi_value_add."=".$multi_value_entry_string."\",";
        my $mesg = $ldap->modify($dn,replace => {$multi_value_add => \@multi_value_entry }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $multi_value_remove and defined $multi_value_entry){
        my @multi_value_entry=split(/,/,$multi_value_entry);
        @multi_value_entry = reverse @multi_value_entry;
        print "   * Setting $multi_value_remove to: @multi_value_entry\n";
        my $multi_value_entry_string=join("|",@multi_value_entry);
        $update_log_string=$update_log_string."\"".$multi_value_remove."=".$multi_value_entry_string."\",";
        my $mesg = $ldap->modify($dn,replace => {$multi_value_remove => \@multi_value_entry }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # proxyAddresses
    if (defined $proxy_addresses_set){
        my @proxy_addresses=split(/,/,$proxy_addresses_set);
        @proxy_addresses = reverse @proxy_addresses;
        print "   * Setting proxyAddresses to: @proxy_addresses\n";
        my $proxy_addresses_string=join("|",@proxy_addresses);
        $update_log_string=$update_log_string."\"proxyAddresses=".$proxy_addresses_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'proxyAddresses' => \@proxy_addresses }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $proxy_addresses_add and defined $proxy_addresses_entry){
        my @proxy_addresses_entry=split(/,/,$proxy_addresses_entry);
        @proxy_addresses_entry = reverse @proxy_addresses_entry;
        print "   * Setting proxyAddresses to: @proxy_addresses_entry\n";
        my $proxy_addresses_entry_string=join("|",@proxy_addresses_entry);
        $update_log_string=$update_log_string."\"proxyAddresses=".$proxy_addresses_entry_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'proxyAddresses' => \@proxy_addresses_entry }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $proxy_addresses_remove and defined $proxy_addresses_entry){
        my @proxy_addresses_entry=split(/,/,$proxy_addresses_entry);
        @proxy_addresses_entry = reverse @proxy_addresses_entry;
        print "   * Setting proxyAddresses to: @proxy_addresses_entry\n";
        my $proxy_addresses_entry_string=join("|",@proxy_addresses_entry);
        $update_log_string=$update_log_string."\"proxyAddresses=".$proxy_addresses_entry_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'proxyAddresses' => \@proxy_addresses_entry }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    
    # custom attributes (multiValue)
    if (defined $custom_multi_1){
        my @custom_multi_1=split(/,/,$custom_multi_1);
        @custom_multi_1 = reverse @custom_multi_1;
        print "   * Setting sophomorixCustomMulti1 to: @custom_multi_1\n";
        my $custom_multi_1_string=join("|",@custom_multi_1);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti1=".$custom_multi_1_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti1' => \@custom_multi_1 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $custom_multi_2){
        my @custom_multi_2=split(/,/,$custom_multi_2);
        @custom_multi_2 = reverse @custom_multi_2;
        print "   * Setting sophomorixCustomMulti2 to: @custom_multi_2\n";
        my $custom_multi_2_string=join("|",@custom_multi_2);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti2=".$custom_multi_2_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti2' => \@custom_multi_2 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $custom_multi_3){
        my @custom_multi_3=split(/,/,$custom_multi_3);
        @custom_multi_3 = reverse @custom_multi_3;
        print "   * Setting sophomorixCustomMulti3 to: @custom_multi_3\n";
        my $custom_multi_3_string=join("|",@custom_multi_3);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti3=".$custom_multi_3_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti3' => \@custom_multi_3 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $custom_multi_4){
        my @custom_multi_4=split(/,/,$custom_multi_4);
        @custom_multi_4 = reverse @custom_multi_4;
        print "   * Setting sophomorixCustomMulti4 to: @custom_multi_4\n";
        my $custom_multi_4_string=join("|",@custom_multi_4);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti4=".$custom_multi_4_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti4' => \@custom_multi_4 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $custom_multi_5){
        my @custom_multi_5=split(/,/,$custom_multi_5);
        @custom_multi_5 = reverse @custom_multi_5;
        print "   * Setting sophomorixCustomMulti5 to: @custom_multi_5\n";
        my $custom_multi_5_string=join("|",@custom_multi_5);
        $update_log_string=$update_log_string."\"sophomorixCustomMulti5=".$custom_multi_5_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixCustomMulti5' => \@custom_multi_5 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # intrinsic attributes (singleValue)
    if (defined $intrinsic_1){
        if ($intrinsic_1 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic1";
        } else {
            $replace{'sophomorixIntrinsic1'}=$intrinsic_1;
        }
        print "   sophomorixIntrinsic1:       $intrinsic_1\n";
    }
    if (defined $intrinsic_2){
        if ($intrinsic_2 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic2";
        } else {
            $replace{'sophomorixIntrinsic2'}=$intrinsic_2;
        }
        print "   sophomorixIntrinsic2:       $intrinsic_2\n";
    }
    if (defined $intrinsic_3){
        if ($intrinsic_3 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic3";
        } else {
            $replace{'sophomorixIntrinsic3'}=$intrinsic_3;
        }
        print "   sophomorixIntrinsic3:       $intrinsic_3\n";
    }
    if (defined $intrinsic_4){
        if ($intrinsic_4 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic4";
        } else {
            $replace{'sophomorixIntrinsic4'}=$intrinsic_4;
        }
        print "   sophomorixIntrinsic4:       $intrinsic_4\n";
    }
    if (defined $intrinsic_5){
        if ($intrinsic_5 eq ""){
            # delete attr if empty
            push @delete, "sophomorixIntrinsic5";
        } else {
            $replace{'sophomorixIntrinsic5'}=$intrinsic_5;
        }
        print "   sophomorixIntrinsic5:       $intrinsic_5\n";
    }

    # intrinsic attributes (multiValue)
    if (defined $intrinsic_multi_1){
        my @intrinsic_multi_1=split(/,/,$intrinsic_multi_1);
        @intrinsic_multi_1 = reverse @intrinsic_multi_1;
        print "   * Setting sophomorixIntrinsicMulti1 to: @intrinsic_multi_1\n";
        my $intrinsic_multi_1_string=join("|",@intrinsic_multi_1);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti1=".$intrinsic_multi_1_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti1' => \@intrinsic_multi_1 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $intrinsic_multi_2){
        my @intrinsic_multi_2=split(/,/,$intrinsic_multi_2);
        @intrinsic_multi_2 = reverse @intrinsic_multi_2;
        print "   * Setting sophomorixIntrinsicMulti2 to: @intrinsic_multi_2\n";
        my $intrinsic_multi_2_string=join("|",@intrinsic_multi_2);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti2=".$intrinsic_multi_2_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti2' => \@intrinsic_multi_2 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $intrinsic_multi_3){
        my @intrinsic_multi_3=split(/,/,$intrinsic_multi_3);
        @intrinsic_multi_3 = reverse @intrinsic_multi_3;
        print "   * Setting sophomorixIntrinsicMulti3 to: @intrinsic_multi_3\n";
        my $intrinsic_multi_3_string=join("|",@intrinsic_multi_3);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti3=".$intrinsic_multi_3_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti3' => \@intrinsic_multi_3 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $intrinsic_multi_4){
        my @intrinsic_multi_4=split(/,/,$intrinsic_multi_4);
        @intrinsic_multi_4 = reverse @intrinsic_multi_4;
        print "   * Setting sophomorixIntrinsicMulti4 to: @intrinsic_multi_4\n";
        my $intrinsic_multi_4_string=join("|",@intrinsic_multi_4);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti4=".$intrinsic_multi_4_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti4' => \@intrinsic_multi_4 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    if (defined $intrinsic_multi_5){
        my @intrinsic_multi_5=split(/,/,$intrinsic_multi_5);
        @intrinsic_multi_5 = reverse @intrinsic_multi_5;
        print "   * Setting sophomorixIntrinsicMulti5 to: @intrinsic_multi_5\n";
        my $intrinsic_multi_5_string=join("|",@intrinsic_multi_5);
        $update_log_string=$update_log_string."\"sophomorixIntrinsicMulti5=".$intrinsic_multi_5_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixIntrinsicMulti5' => \@intrinsic_multi_5 }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # webui
    if (defined $webui_dashboard){
        if ($webui_dashboard eq ""){
            # delete attr if empty
            push @delete, "sophomorixWebuiDashboard";
        } else {
            $replace{'sophomorixWebuiDashboard'}=$webui_dashboard;
        }
        print "   sophomorixWebuiDashboard:   $webui_dashboard\n";
    }

    if (defined $webui_permissions){
        my @webui_permissions=split(/,/,$webui_permissions);
        @webui_permissions = reverse @webui_permissions;
        print "   * Setting sophomorixWebuiPermissions to: @webui_permissions\n";
        my $webui_permissions_string=join("|",@webui_permissions);
        $update_log_string=$update_log_string."\"sophomorixWebuiPermissions=".$webui_permissions_string."\",";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixWebuiPermissions' => \@webui_permissions }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    if (defined $ref_webui_permissions_calculated){
        if ($#{ $ref_webui_permissions_calculated }==0 and ${ $ref_webui_permissions_calculated }[0] eq "---"){
            # --- as the single entry means: don not do anything to sophomorixWebuiPermissionsCalculated
        } else {
	    print "   * Setting sophomorixWebuiPermissionsCalculated to:\n";
            foreach my $entry (@{ $ref_webui_permissions_calculated }){
                print "      $entry\n";
            }
            my $ref_webui_permissions_calculated_string=join("|",@{ $ref_webui_permissions_calculated });
            $update_log_string=$update_log_string."\"sophomorixWebuiPermissionsCalculated=".
                $ref_webui_permissions_calculated_string."\",";
            my $mesg = $ldap->modify($dn,
                replace => { sophomorixWebuiPermissionsCalculated => $ref_webui_permissions_calculated }); 
            &AD_debug_logdump($mesg,2,(caller(0))[3]);
        }
    } 


    if ($json>=1){
        # prepare json object
        my %json_progress=();
        $json_progress{'JSONINFO'}="PROGRESS";
        $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'UPDATEUSER_PREFIX_EN'}.
                                     " $user".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'UPDATEUSER_POSTFIX_EN'};
        $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'UPDATEUSER_PREFIX_DE'}.
                                     " $user".
                                     $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'UPDATEUSER_POSTFIX_DE'};
        $json_progress{'STEP'}=$user_count;
        $json_progress{'FINAL_STEP'}=$max_user_count;
        # print JSON Object
        &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                          json=>$json,
                                                          sophomorix_config=>$ref_sophomorix_config,
                                                        });
    }

    #print Dumper(\$replace);
    if (%replace){
        foreach my $key (keys %replace) {
            if ($update_log_string=~m/\"$/){
                $update_log_string=$update_log_string.",";
            }
            $update_log_string=$update_log_string."\"".$key."=".$replace{$key}."\"";
        }
        # modify
        my $mesg = $ldap->modify( $dn,
	  	          replace => { %replace }
                         );
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    #print Dumper(\@delete);
    if ($#delete > -1){
        # delete
        my $mesg = $ldap->modify( $dn,
                          delete => ( @delete )
                         );
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }


    # set password with smbpasswd
    if ($smbpasswd eq "TRUE"){
	my $smbpasswd_command = "(echo '$sophomorix_first_password'; echo '$sophomorix_first_password')".
                                " | $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBPASSWD'} -U $user -s";
	my $smbpasswd_display = "(echo '******'; echo '******')".
                                " | $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBPASSWD'} -U $user -s";
	if ($hide_pwd==1){
	    print "Executing (password omitted by --hide):\n"; 
            print "  $smbpasswd_display\n";
	} else {
	    print "Executing:\n"; 
            print "  $smbpasswd_command\n";
	}
	my ($return_value,@out_lines)=&Sophomorix::SophomorixBase::smbpasswd_command($smbpasswd_command);
	if ($return_value==0){
	    # OK
	} else {
            my $error_string=join("|",@out_lines);
	    &Sophomorix::SophomorixBase::result_sophomorix_add($ref_sophomorix_result,"ERROR",-1,"",$error_string);
        }
    }
    
    print "Logging user update\n";
    &Sophomorix::SophomorixBase::log_user_update({sAMAccountName=>$user,
                                                  unid=>$unid_AD,
                                                  school_old=>$school_AD,
                                                  school_new=>$school,
                                                  update_log_string=>$update_log_string,
                                                  sophomorix_config=>$ref_sophomorix_config,
                                                  sophomorix_result=>$ref_sophomorix_result,
                                                });
    &Sophomorix::SophomorixBase::print_title(
          "Updating User ${user_count}/$max_user_count: $user (end)");
    print "\n";
}



sub AD_user_getquota_usage {
    my ($arg_ref) = @_; 
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};
    my $share = $arg_ref->{share};

    # what parameter? user
    # how to append to user data hash?
    # sophomorix-user --quota-usage

    # see sophomorix-query, option --quota-usage

}



sub AD_user_setquota {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $share_count = $arg_ref->{share_count};
    my $max_share_count = $arg_ref->{max_share_count};
    my $share = $arg_ref->{share};
    my $quota = $arg_ref->{quota};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $debug_level = $arg_ref->{debug_level};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    # calculate limits
    my $hard_bytes;
    my $soft_bytes;
    if ($quota==-1){
    $hard_bytes=-1;
    $soft_bytes=-1;
    } else {
        $hard_bytes=1024*1024*$quota; # bytes to MiB
        $soft_bytes=int(0.80*$hard_bytes/1024)*1024;
    }

    # check if msdfs is true, if so use the remote address for smbcquotas
    #my $msdfs = $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}{'msdfs root'} eq 'yes';
    if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}{'msdfs root'} and
	$ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}{'msdfs root'} eq 'yes'){
            # setting quota on a remote server ->  ubuntu 22.04 or later expected, no -mNT1 option available
            $smbcquotas_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
                                  " ".$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS_PROTOCOL_OPT'}.
                                  " --debuglevel=$debug_level -U ".$DevelConf::sophomorix_file_admin."%'".
                                  $smb_admin_pass."'".
		                  " -S UQLIM:".$user.":".$soft_bytes."/".$hard_bytes." ".$ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}{'msdfs proxy'};
    } else {
	if ($ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_RELEASE'} eq "18.04"){
            # switch back to old protocol
            $smbcquotas_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
                                 " -mNT1".
                                 " --debuglevel=$debug_level -U ".$DevelConf::sophomorix_file_admin."%'".
                                 $smb_admin_pass."'".
                                 " -S UQLIM:".$user.":".$soft_bytes."/".$hard_bytes." //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/$share";
        } else {
            # ubuntu 22.04 or later expected, no -mNT1 option available
            $smbcquotas_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
                                 " ".$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS_PROTOCOL_OPT'}.
                                 " --debuglevel=$debug_level -U ".$DevelConf::sophomorix_file_admin."%'".
                                 $smb_admin_pass."'".
                                 " -S UQLIM:".$user.":".$soft_bytes."/".$hard_bytes." //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/$share";
	}
    }


    ############################################################
    # run the command
    print "HERE: $smbcquotas_command\n";
    $smbcquotas_out=`$smbcquotas_command`;
    my $smbcquotas_return=${^CHILD_ERROR_NATIVE}; # return of value of last command

    ############################################################
    # display result
    my $display_command=$smbcquotas_command;
    # hide password
    $display_command=~s/$smb_admin_pass/***/;
    my $smbcquotas_out_ident=&Sophomorix::SophomorixBase::ident_output($smbcquotas_out,8);
    if($smbcquotas_return==0){
        print "OK: $display_command\n";
        if($Conf::log_level>1){
            print "     RETURN VALUE: $smbcquotas_return\n";
            print "     ERROR MESSAGE:\n";
            print $smbcquotas_out_ident;
        }
        #chomp($smbcquotas_return);
        my ($full_user,
            $quota_user,
            $colon,
            $used,
            $soft_limit,
            $hard_limit,
            $used_mib,
            $soft_limit_mib,
            $hard_limit_mib,
           )=&Sophomorix::SophomorixBase::analyze_smbcquotas_out($smbcquotas_out,$user);

        # update the sophomorixQuota entry at the user
        my $share_quota=$share.":".$quota;
        if($Conf::log_level>2){
            print "smbcquotas RETURNED: $quota_user has used $used of $hard_limit\n";
            print "Updating quota for user $user to $share_quota:\n";
        }

        my ($count,$dn,$cn)=&AD_object_search($ldap,$root_dse,"user",$user);
        &AD_user_update({ldap=>$ldap,
                         root_dse=>$root_dse,
                         dn=>$dn,
                         user=>$user,
                         quota=>$share_quota,     # <share>:<quota_on_share>
                         quota_calc=>$quota,      # what was calculated (same as quota_on_share)
                         quota_info=>$hard_limit, # what was set
                         user_count=>$user_count,
                         max_user_count=>$max_user_count,
                         json=>$json,
                         sophomorix_config=>$ref_sophomorix_config,
                         sophomorix_result=>$ref_sophomorix_result,
                       });
    } else {
        print "ERROR: $display_command \n";
        print "     RETURN VALUE: $smbcquotas_return\n";
        print "     ERROR MESSAGE:\n";
        print $smbcquotas_out_ident;
        &Sophomorix::SophomorixBase::result_sophomorix_add($ref_sophomorix_result,
                                                           "ERROR",-1,$ref_parameter,
                                                           "FAILED ($smbcquotas_return): $display_command");
    }
}



sub AD_get_user {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};

    my $filter="(&(objectClass=user) (sAMAccountName=".$user."))";
    #my $filter="(sAMAccountName=".$user.")";
     $mesg = $ldap->search( # perform a search
                    base   => $root_dse,
                    scope => 'sub',
                    filter => $filter,
                    attrs => ['sAMAccountName',
                              'sophomorixAdminClass',
                              'sophomorixExamMode',
                              'sophomorixRole',
                              'givenName',
                              'sn',
                              'homeDirectory',
                              'userAccountControl',
                              'sophomorixTolerationDate',
                              'sophomorixDeactivationDate',
                              'sophomorixSchoolname',
                              'sophomorixStatus',
                              'sophomorixFirstPassword',
                              'sophomorixUnid',
			      'sophomorixFirstnameASCII',
			      'sophomorixSurnameASCII',
                              'sophomorixFirstnameInitial', 
			      'sophomorixSurnameInitial',
			      'sophomorixUserToken',
			      'sophomorixAdminFile',
			      'sophomorixBirthdate',
                             ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);

    my $max_user = $mesg->count; 
    my $entry = $mesg->entry(0);
    if (not defined $entry){
        my $existing="FALSE";
        return ("","","",$existing);
    } else {
        my $firstname = $entry->get_value('givenName');
        my $lastname = $entry->get_value('sn');
        my $firstname_ASCII = $entry->get_value('sophomorixFirstnameASCII');
        my $lastname_ASCII = $entry->get_value('sophomorixSurnameASCII');
        my $firstname_initial = $entry->get_value('sophomorixFirstnameInitial');
        my $lastname_initial = $entry->get_value('sophomorixSurnameInitial');
        my $class = $entry->get_value('sophomorixAdminClass');
        my $role = $entry->get_value('sophomorixRole');
        my $exammode = $entry->get_value('sophomorixExamMode');
        my $home_directory = $entry->get_value('homeDirectory');
        my $user_account_control = $entry->get_value('userAccountControl');
        my $toleration_date = $entry->get_value('sophomorixTolerationDate');
        my $deactivation_date = $entry->get_value('sophomorixDeactivationDate');
        my $school = $entry->get_value('sophomorixSchoolname');
        my $status = $entry->get_value('sophomorixStatus');
        my $firstpassword = $entry->get_value('sophomorixFirstPassword');
        my $unid = $entry->get_value('sophomorixUnid');
        my $user_token = $entry->get_value('sophomorixUserToken');
        my $file = $entry->get_value('sophomorixAdminFile');
        my $birthdate = $entry->get_value('sophomorixBirthdate');
        my $existing="TRUE";
        return ($firstname,$lastname,$class,$existing,$exammode,$role,
                $home_directory,$user_account_control,$toleration_date,
                $deactivation_date,$school,$status,$firstpassword,$unid,
                $firstname_ASCII,$lastname_ASCII,
                $firstname_initial,$lastname_initial,$user_token,$file,$birthdate);
    }
}


sub AD_get_user_return_hash {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};
    my $ref_result=$arg_ref->{hash_ref};
    #my %result=();
    my $filter="(&(objectClass=user) (sAMAccountName=".$user."))";
    #my $filter="(sAMAccountName=".$user.")";
     $mesg = $ldap->search( # perform a search
                    base   => $root_dse,
                    scope => 'sub',
                    filter => $filter,
                    attrs => ['sAMAccountName',
                              'sophomorixAdminClass',
                              'sophomorixExamMode',
                              'sophomorixRole',
                              'givenName',
                              'sn',
                              'homeDirectory',
                              'userAccountControl',
                              'sophomorixTolerationDate',
                              'sophomorixDeactivationDate',
                              'sophomorixSchoolname',
                              'sophomorixStatus',
                              'sophomorixFirstPassword',
                              'sophomorixUnid',
			      'sophomorixFirstnameASCII',
			      'sophomorixSurnameASCII',
                              'sophomorixFirstnameInitial',
			      'sophomorixSurnameInitial',
			      'sophomorixUserToken',
			      'sophomorixAdminFile',
			      'sophomorixBirthdate',
                             ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);

    my $max_user = $mesg->count;
    my $entry = $mesg->entry(0);
    if (not defined $entry){
        $ref_result->{$user}{'EXISTING'}="FALSE";
    } else {
        $ref_result->{$user}{'EXISTING'}="TRUE";
	$ref_result->{$user}{'givenName'} = $entry->get_value('givenName');
	$ref_result->{$user}{'sn'} = $entry->get_value('sn');
	$ref_result->{$user}{'sophomorixFirstnameASCII'} = $entry->get_value('sophomorixFirstnameASCII');
	$ref_result->{$user}{'sophomorixSurnameASCII'} = $entry->get_value('sophomorixSurnameASCII');
	$ref_result->{$user}{'sophomorixFirstnameInitial'} = $entry->get_value('sophomorixFirstnameInitial');
	$ref_result->{$user}{'sophomorixSurnameInitial'} = $entry->get_value('sophomorixSurnameInitial');
	$ref_result->{$user}{'sophomorixAdminClass'} = $entry->get_value('sophomorixAdminClass');
	$ref_result->{$user}{'sophomorixRole'} = $entry->get_value('sophomorixRole');
	$ref_result->{$user}{'sophomorixExamMode'} = $entry->get_value('sophomorixExamMode');
	$ref_result->{$user}{'homeDirectory'} = $entry->get_value('homeDirectory');
	$ref_result->{$user}{'userAccountControl'} = $entry->get_value('userAccountControl');
	$ref_result->{$user}{'sophomorixTolerationDate'} = $entry->get_value('sophomorixTolerationDate');
	$ref_result->{$user}{'sophomorixDeactivationDate'} = $entry->get_value('sophomorixDeactivationDate');
	$ref_result->{$user}{'sophomorixSchoolname'} = $entry->get_value('sophomorixSchoolname');
	$ref_result->{$user}{'sophomorixStatus'} = $entry->get_value('sophomorixStatus');
	$ref_result->{$user}{'sophomorixFirstPassword'} = $entry->get_value('sophomorixFirstPassword');
	$ref_result->{$user}{'sophomorixUnid'} = $entry->get_value('sophomorixUnid');
	$ref_result->{$user}{'sophomorixUserToken'} = $entry->get_value('sophomorixUserToken');
	$ref_result->{$user}{'sophomorixAdminFile'} = $entry->get_value('sophomorixAdminFile');
	$ref_result->{$user}{'sophomorixBirthdate'} = $entry->get_value('sophomorixBirthdate');
    }
    return $ref_result;
}



sub AD_get_group {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $group = $arg_ref->{group};

    my $filter="(&(objectClass=group) (sAMAccountName=".$group."))";
     $mesg = $ldap->search( # perform a search
                    base   => $root_dse,
                    scope => 'sub',
                    filter => $filter,
                    attrs => ['sAMAccountName',
                              'sophomorixSchoolname',
                              'sophomorixType',
                              'sophomorixStatus',
                              'description',
                              'dn',
                             ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);

    my $max_group = $mesg->count; 
    my $entry = $mesg->entry(0);
    if (not defined $entry){
        my $existing="FALSE";
        return ($existing,"","","","");
    } else {
        my $existing="TRUE";
        my $type = $entry->get_value('sophomorixType');
        my $school = $entry->get_value('sophomorixSchoolname');
        if ($school eq "---"){
            $school=$DevelConf::name_default_school;
        }
        my $status = $entry->get_value('sophomorixStatus');
        my $description = $entry->get_value('description');
        my $dn = $entry->dn();
        return ($existing,$type,$school,$status,$description,$dn);
    }
}



sub AD_user_move {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $user = $arg_ref->{user};
    my $unid = $arg_ref->{unid};
    my $user_count = $arg_ref->{user_count};
    my $group_old = $arg_ref->{group_old};
    my $group_new = $arg_ref->{group_new};
    my $group_old_basename = $arg_ref->{group_old_basename};
    my $group_new_basename = $arg_ref->{group_new_basename};
    my $school_old = $arg_ref->{school_old};
    my $school_new = $arg_ref->{school_new};
    my $role_old = $arg_ref->{role_old};
    my $role_new = $arg_ref->{role_new};
    my $filename_old = $arg_ref->{filename_old};
    my $filename_new = $arg_ref->{filename_new};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    # read from config
    my $group_type_new;
    if (defined $ref_sophomorix_config->{'SCHOOLS'}{$school_new}{'GROUP_TYPE'}{$group_new}){
        $group_type_new=$ref_sophomorix_config->{'SCHOOLS'}{$school_new}{'GROUP_TYPE'}{$group_new};
    } else{
        $group_type_new="adminclass";
    }

    my $prefix_new=$school_new;
    if ($school_new eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix_new="---";
    }

    my $filename;
    if ($filename_new eq "---"){
        $filename=$filename_old;
    } else {
        $filename=$filename_new;
    }

    my $target_branch;
    $school_old=&AD_get_schoolname($school_old);
    $school_new=&AD_get_schoolname($school_new);

    if ($role_new eq "student"){
         $target_branch="OU=".$group_new_basename.",OU=Students,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
    } elsif ($role_new eq "teacher"){
#         $target_branch="OU=".$group_new_basename.",OU=Teachers,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
         $target_branch="OU=Teachers,OU=".$school_new.",".$DevelConf::AD_schools_ou.",".$root_dse;
    }

    my ($homedirectory_old,$unix_home_old,$unc_old,$smb_rel_path_old)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school_old,
                                                       $group_old_basename,
                                                       $user,
                                                       $role_old,
                                                       $ref_sophomorix_config);
    my ($homedirectory_new,$unix_home_new,$unc_new,$smb_rel_path_new)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school_new,
                                                       $group_new_basename,
                                                       $user,
                                                       $role_new,
                                                       $ref_sophomorix_config);

    # fetch the dn (where the object really is)
    my ($count,$dn,$rdn)=&AD_object_search($ldap,$root_dse,"user",$user);
    if ($count==0){
        print "\nWARNING: $user not found in ldap, skipping\n\n";
        next;
    }
    my ($count_group_old,
        $dn_group_old,
        $rdn_group_old)=&AD_object_search($ldap,$root_dse,"group",$group_old);
    if ($count_group_old==0){
        print "\nWARNING: Group $group_old not found in ldap, skipping\n\n";
        next;
    }
    if($Conf::log_level>=1){
        print "\n";
        &Sophomorix::SophomorixBase::print_title("Moving user $user ($user_count),(start):");
        print "   DN:             $dn\n";
        print "   Target DN:         $target_branch\n";
        print "   Group (Old):       $group_old ($group_old_basename)\n";
        print "   Group (New):       $group_new ($group_new_basename)\n";
        print "   Role (New):        $role_new\n";
        print "   Type (New):        $group_type_new\n";
        print "   School(Old):       $school_old\n";
        print "   School(New):       $school_new\n";
        print "   Prefix(New):       $prefix_new\n";
        print "   Rename:            $smb_rel_path_old -> $smb_rel_path_new\n";
        print "   filename:          $filename\n";
        print "   homeDirectory:     $homedirectory_new\n";
        print "   unixHomeDirectory: $unix_home_new\n";
    }

    # make sure OU and tree exists
    if (not exists $school_created{$school_new}){
         # create new ou
         &AD_school_create({ldap=>$ldap,
                            root_dse=>$root_dse,
                            root_dns=>$root_dns,
                            school=>$school_new,
                            smb_admin_pass=>$smb_admin_pass,
                            sophomorix_config=>$ref_sophomorix_config,
                            sophomorix_result=>$ref_sophomorix_result,
                          });
         # remember new ou to add it only once
         $school_created{$school_new}="already created";
    } else {
        print "   * OU $school_new already created\n";
    }

    # make sure new group exists
    &AD_group_create({ldap=>$ldap,
                      root_dse=>$root_dse,
                      root_dns=>$root_dns,
                      group=>$group_new,
                      group_basename=>$group_new_basename,
                      description=>$group_new,
                      school=>$school_new,
                      type=>$group_type_new,
                      joinable=>"TRUE",
                      status=>"P",
                      file=>$filename,
                      smb_admin_pass=>$smb_admin_pass,
                      sophomorix_config=>$ref_sophomorix_config,
                      sophomorix_result=>$ref_sophomorix_result,
                    });

    # update user entry
    my $mesg = $ldap->modify( $dn,
		      replace => {
                          sophomorixAdminClass => $group_new,
                          sophomorixExitAdminClass => $group_old,
                          sophomorixSchoolPrefix => $prefix_new,
                          sophomorixSchoolname => $school_new,
                          sophomorixRole => $role_new,
                          homeDirectory => $homedirectory_new,
                          unixHomeDirectory => $unix_home_new,
                      }
               );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    print "Logging user move\n";
    my $update_log_string="\"GROUP:".$group_old."->".$group_new.",ROLE:".$role_old."->".$role_new."\"";
    &Sophomorix::SophomorixBase::log_user_update({sAMAccountName=>$user,
                                                  unid=>$unid,
                                                  school_old=>$school_old,
                                                  school_new=>$school_new,
                                                  update_log_string=>$update_log_string,
                                                  sophomorix_config=>$ref_sophomorix_config,
                                                  sophomorix_result=>$ref_sophomorix_result,
                                                });



    # remove user from old group
    my ($count_oldclass,$dn_oldclass,$cn_oldclass,$info_oldclass)=&AD_object_search($ldap,$root_dse,"group",$group_old);
    my @old_members_oldgroup = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn_oldclass,"sophomorixMembers");
    my @members_oldgroup = &Sophomorix::SophomorixBase::remove_from_list($user,@old_members_oldgroup);
    my $members_oldgroup=join(",",@members_oldgroup);
    &AD_group_update({ldap=>$ldap,
                      root_dse=>$root_dse,
                      dn=>$dn_oldclass,
                      type=>"adminclass",
                      members=>$members_oldgroup,
                      sophomorix_config=>$ref_sophomorix_config,
                    });
    # add user to new group 
    my ($count_newclass,$dn_newclass,$cn_newclass,$info_newclass)=&AD_object_search($ldap,$root_dse,"group",$group_new);
    my @old_members_newgroup = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn_newclass,"sophomorixMembers");
    # create a unique list of new members
    my @members_newgroup = uniq(@old_members_newgroup,$user); 
    my $members_newgroup=join(",",@members_newgroup);
    # update project
    &AD_group_update({ldap=>$ldap,
                      root_dse=>$root_dse,
                      dn=>$dn_newclass,
                      type=>"adminclass",
                      members=>$members_newgroup,
                      sophomorix_config=>$ref_sophomorix_config,
                    });
    # move the object in ldap tree
    &AD_object_move({ldap=>$ldap,
                     dn=>$dn,
                     rdn=>$rdn,
                     target_branch=>$target_branch,
                    });

    # change management groups if school changes
    if ($school_old ne $school_new){
        &Sophomorix::SophomorixBase::print_title("School $school_old --> $school_new, managment groups change (start)");
        my @grouplist=("wifi","internet","webfilter","intranet","printing");
        # removing
        foreach my $group (@grouplist){
            my $management_group=&AD_get_name_tokened($group,$school_old,"management");
            &AD_group_removemember({ldap => $ldap,
                                    root_dse => $root_dse, 
                                    group => $management_group,
                                    removemember => $user,
                                    sophomorix_config=>$ref_sophomorix_config,
                                   });   
        }
        # adding
        foreach my $group (@grouplist){
            my $management_group=&AD_get_name_tokened($group,$school_new,"management");
            &AD_group_addmember_management({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $management_group,
                                            addmember => $user,
                                           }); 
        }
        &Sophomorix::SophomorixBase::print_title("School $school_old --> $school_new, managment groups change (start)");
    }


    # move the home directory of the user
    if ($school_old eq $school_new){
        # this is on the same share
        # smbclient ... rename (=move)
        my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
            " -U ".$DevelConf::sophomorix_file_admin."%'******'".
            " //$root_dns/$school_old -c 'rename \"$smb_rel_path_old\" \"$smb_rel_path_new\"'";
        &Sophomorix::SophomorixBase::smb_command($smbclient_command,$smb_admin_pass);
    } else {
        # this is dirty and works only if the shares are on the same server
        # ????????????????????????????

        my $mv="mv $unix_home_old $unix_home_new";
        print "Moving Home: $mv\n";
        system($mv);
    }

    # fixing the acls on the new home
    if ($role_new eq "student"){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.student_home",
                               school=>$school_new,
                               adminclass=>$group_new,
                               student_home=>$user,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($role_new eq "teacher"){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.teacher_home",
                               school=>$school_new,
                               teacherclass=>$group_new,
                               teacher_home=>$user,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    }
    &Sophomorix::SophomorixBase::print_title("Moving user $user ($user_count),(end)");
    print "\n";
}



sub AD_get_schoolname {
    my ($ou) = @_;
    if ($ou eq "---"){
        my $string=$DevelConf::name_default_school;
        $ou=$string;
    }
    return $ou;
}



sub AD_get_name_tokened {
    # $role is: group type / user role
    # prepend <token> or not, depending on the users role/groups type 
    my ($name,$school,$role) = @_;
    my $name_tokened="";
    if ($role eq "adminclass" or 
        $role eq "extraclass" or 
        $role eq "teacherclass" or
        $role eq "all" or
        $role eq "room" or 
        $role eq "devicegroup" or 
        $role eq "roomws" or
        $role eq "dnsnode" or
        $role eq "computer" or
        $role eq "project" or
        $role eq "management" or
        $role eq "administrator" or
        $role eq "ouexamusers" or
        $role eq "sophomorix-group" or
        $role eq "group"){
        if ($school eq "---" 
            or $school eq ""
            or $school eq "global"
            or $school eq $DevelConf::name_default_school
           ){
            # SCHOOL, no multischool
            $name_tokened=$name;
        } else {
            # multischool
            if ($DevelConf::token_postfix==0){
                # prefix
                $name_tokened=$school."-".$name;
            } elsif ($DevelConf::token_postfix==1){
                # postfix
                $name_tokened=$name."-".$school;
            }
        }
        if ($role eq "computer"){
            # make uppercase
            $name_tokened=~tr/a-z/A-Z/;
        }
        if ($role eq "project"){
            unless ($name_tokened =~ m/^p\_/) { 
                # add prefix to projects: p_ 
                $name_tokened="p_".$name_tokened;
            }
        }
        if ($role eq "devicegroup"){
            unless ($name_tokened =~ m/^d\_/) { 
                # add prefix to : d_devicegroup 
                $name_tokened="d_".$name_tokened;
            }
        }
        return $name_tokened;
    } elsif ($role eq "teacher" or
             $role eq "student"){
        return $name;
    } else {
        return $name;
    }
}



sub AD_school_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_result = $arg_ref->{sophomorix_result};

    # test with RUNTIME stuff in sophomorix_config
    # if school was already created in this script
    if (exists $ref_sophomorix_config->{'RUNTIME'}{'SCHOOLS_CREATED'}{$school}){
        print "   * $school already created RUNTIME\n";
        #print Dumper ($ref_sophomorix_config->{'RUNTIME'});
        return;
    } else {
        print "   * $school must be created RUNTIME\n";
        #print Dumper ($ref_sophomorix_config->{'RUNTIME'});
    }
    $school=&AD_get_schoolname($school);

    print "\n";
    &Sophomorix::SophomorixBase::print_title("Testing smb shares ...");
    ############################################################
    # providing smb shares
    ############################################################
    # global share
    if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}}){
        print "   * Nothing to do: Global share $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'} exists.\n";
    } else {
        &Sophomorix::SophomorixBase::print_title("Creating $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}");
        system("mkdir -p $DevelConf::homedir_global");
        my $command="net conf addshare ".
                    $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}." ".
                    $DevelConf::homedir_global.
                    " writeable=y guest_ok=N 'Share for school global'";
        print "   * $command\n";
        system($command);
        my $command_mod1="net conf setparm ".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}.
# ??????
#                         " 'msdfs root' 'yes'";
                         " 'msdfs root' 'no'";
        print "   * $command_mod1\n";
        system($command_mod1);
        my $command_mod2="net conf setparm ".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}.
                         " 'hide unreadable' 'yes'";
        print "   * $command_mod2\n";
        system($command_mod2);
	my $groupstring=$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}.
                        "\\".$DevelConf::sophomorix_file_admin.
                        ", \@".$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}."\\SCHOOLS";
        my $command_mod3="net conf setparm ".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}.
                         " 'valid users' '$groupstring'";
        print "   * $command_mod3\n";
        system($command_mod3);
        my $command_mod4="net conf setparm ".$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}.
                         " 'strict allocate' 'yes'";
        print "   * $command_mod4\n";
        system($command_mod4);

        &Sophomorix::SophomorixBase::read_smb_net_conf_list($ref_sophomorix_config);
    }

    # school share
    if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$school} or 
        $school eq "global"
       ){
        print "   * nothing to do: School share $school exists.\n";
    } else {
        &Sophomorix::SophomorixBase::print_title("Creating share for school $school");
        my $unix_path=$DevelConf::homedir_all_schools."/".$school;
        system("mkdir -p $unix_path");
        my $command="net conf addshare ".
                    $school." ".
                    $unix_path.
                    " writeable=y guest_ok=N 'Share for school $school'";
        print "   * $command\n";
        system($command);
        my $command_mod1="net conf setparm ".$school.
# ?????
#                         " 'msdfs root' 'yes'";
                         " 'msdfs root' 'no'";
        print "   * $command_mod1\n";
        system($command_mod1);

        my $command_mod2="net conf setparm ".$school.
                         " 'hide unreadable' 'yes'";
        print "   * $command_mod2\n";
        system($command_mod2);
        my $groupstring=$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}.
                        "\\".$DevelConf::sophomorix_file_admin.
                        ", \@".$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}."\\".$school.
                        ", \@".$ref_sophomorix_config->{'samba'}{'smb.conf'}{'global'}{'workgroup'}."\\global-admins";
        my $command_mod3="net conf setparm ".$school.
                         " 'valid users' '$groupstring'";
        print "   * $command_mod3\n";
        system($command_mod3);
        my $command_mod4="net conf setparm ".$school.
                         " 'strict allocate' 'yes'";
        print "   * $command_mod4\n";
        system($command_mod4);

        &Sophomorix::SophomorixBase::read_smb_net_conf_list($ref_sophomorix_config);
    }

    if ($school ne "global"){
        &Sophomorix::SophomorixBase::print_title("Adding school $school in AD (begin) ...");
        ############################################################
        # providing OU=SCHOOLS 
        ############################################################
        my $schools_ou=$DevelConf::AD_schools_ou.",".$root_dse;
        my $result1 = $ldap->add($schools_ou,
                             attr => ['objectClass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result1,2,(caller(0))[3]);
        ############################################################
        # providing group 'SCHOOLS'
        ############################################################
        my $dn_schools="CN=".$DevelConf::AD_schools_group.",".$DevelConf::AD_schools_ou.",".$root_dse;
        &AD_group_create({ldap=>$ldap,
                          root_dse=>$root_dse,
                          root_dns=>$root_dns,
                          dn_wish=>$dn_schools,
                          school=>$DevelConf::AD_schools_group,
                          group=>$DevelConf::AD_schools_group,
                          group_basename=>$DevelConf::AD_schools_group,
                          description=>"The group that includes all schools",
                          type=>$ref_sophomorix_config->{'INI'}{'SCHOOLS'}{'SCHOOL_GROUP_TYPE'},
                          status=>"P",
                          joinable=>"FALSE",
                          hidden=>"FALSE",
                          smb_admin_pass=>$smb_admin_pass,
                          sophomorix_config=>$ref_sophomorix_config,
                          sophomorix_result=>$ref_sophomorix_result,
                         });
        ############################################################
        # providing the OU=<school>,OU=SCHOOLS for schools
        ############################################################
        my $result2 = $ldap->add($ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP},
                             attr => ['objectClass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result1,2,(caller(0))[3]);
        ############################################################
        # providing group s_<schoolname>
        ############################################################
        my $dn_schoolname="CN=".$ref_sophomorix_config->{'INI'}{'VARS'}{'SCHOOLGROUP_PREFIX'}.$school.
                          ",OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
        &AD_group_create({ldap=>$ldap,
                          root_dse=>$root_dse,
                          root_dns=>$root_dns,
                          dn_wish=>$dn_schoolname,
                          school=>$school,
                          group=>$ref_sophomorix_config->{'INI'}{'VARS'}{'SCHOOLGROUP_PREFIX'}.$school,
                          group_basename=>$ref_sophomorix_config->{'INI'}{'VARS'}{'SCHOOLGROUP_PREFIX'}.$school,
                          description=>"The school group of school ".$school, # no s_ (This is the schoolname)
                          type=>"school",
                          status=>"P",
                          joinable=>"FALSE",
                          hidden=>"FALSE",
                          smb_admin_pass=>$smb_admin_pass,
                          sophomorix_config=>$ref_sophomorix_config,
                          sophomorix_result=>$ref_sophomorix_result,
                        });
        # make group s_<schoolname> member in SCHOOLS
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $DevelConf::AD_schools_group,
                             addgroup => $ref_sophomorix_config->{'INI'}{'VARS'}{'SCHOOLGROUP_PREFIX'}.$school, # s_ (This is the group name)
                           }); 
        ############################################################
        # sub ou's for OU=*    
        if($Conf::log_level>=2){
            print "   * Adding sub ou's for OU=$school ...\n";
        }
        foreach my $ref_sub_ou (@{ $ref_sophomorix_config->{'INI'}{'SCHOOLS'}{'SUB_OU'} } ){
            my $sub_ou=$ref_sub_ou; # make copy to not modify the hash 
            $dn=$sub_ou.",".$ref_sophomorix_config->{'SCHOOLS'}{$school}{OU_TOP};
            print "      * DN: $dn (RT_SCHOOL_OU) $school\n";
            my $result = $ldap->add($dn,attr => ['objectClass' => ['top', 'organizationalUnit']]);
            &AD_debug_logdump($result,2,(caller(0))[3]);
        }

        ############################################################
        # OU=*    
        if($Conf::log_level>=2){
            print "   * Adding OU's for default groups in OU=$school ...\n";
        }

        &AD_create_school_groups($ldap,$root_dse,$root_dns,$smb_admin_pass,
                                 $school,$ref_sophomorix_config);
        ############################################################
        # adding groups to <schoolname>-group
        foreach my $ref_membergroup (@{ $ref_sophomorix_config->{'SCHOOLS'}{$school}{'SCHOOLGROUP_MEMBERGROUPS'} } ){
        my $membergroup=$ref_membergroup; # make copy to not modify the hash
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'INI'}{'VARS'}{'SCHOOLGROUP_PREFIX'}.$school,
                             addgroup => $membergroup,
                           }); 
        }
    }
    ############################################################
    # providing OU=GLOBAL
    ############################################################
    my $result3 = $ldap->add($ref_sophomorix_config->{$DevelConf::AD_global_ou}{OU_TOP},
                        attr => ['objectClass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result3,2,(caller(0))[3]);
    ############################################################
    # sub ou's for OU=GLOBAL    
    if($Conf::log_level>=2){
        print "   * Adding sub ou's for OU=$DevelConf::AD_global_ou ...\n";
    }
    foreach my $sub_ou (@{ $ref_sophomorix_config->{'INI'}{'GLOBAL'}{'SUB_OU'} } ){
        $dn=$sub_ou.",".$ref_sophomorix_config->{$DevelConf::AD_global_ou}{OU_TOP};
        print "      * DN: $dn\n";
        my $result = $ldap->add($dn,attr => ['objectClass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($result,2,(caller(0))[3]);
    }

    ############################################################
    # OU=GLOBAL    
    if($Conf::log_level>=2){
        print "   * Adding OU's for default groups in OU=$school ...\n";
    }

    &AD_create_school_groups($ldap,$root_dse,$root_dns,$smb_admin_pass,
                             $DevelConf::AD_global_ou,$ref_sophomorix_config);

    # all groups created, add some memberships from GLOBAL
    foreach my $group (keys %{$ref_sophomorix_config->{'GLOBAL'}{'GROUP_MEMBEROF'}}) {
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'GLOBAL'}{'GROUP_MEMBEROF'}{$group},
                             addgroup => $group,
                            }); 
    }
    # all groups created, add some memberships from SCHOOLS
    foreach my $group (keys %{$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_MEMBEROF'}}) {
       &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_MEMBEROF'}{$group},
                             addgroup => $group,
                            }); 
    }

    # creating fileystem at last, because groups are needed beforehand for the ACL's 
    # creating filesystem for school
    if ($school ne "global"){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.school",
                               school=>$school,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                            });
    }
    # creating filesystem for global
    &AD_repdir_using_file({ldap=>$ldap,
                           root_dns=>$root_dns,
                           repdir_file=>"repdir.global",
                           school=>$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},
                           smb_admin_pass=>$smb_admin_pass,
                           sophomorix_config=>$ref_sophomorix_config,
                           sophomorix_result=>$ref_sophomorix_result,
                         });
    &Sophomorix::SophomorixBase::print_title("Adding school $school in AD (end) ...");
    print "\n";
    # remember the school in RUNTIME hash
    $ref_sophomorix_config->{'RUNTIME'}{'SCHOOLS_CREATED'}{$school}="created by AD_school_create RUNTIME";
}



sub AD_create_school_groups {
    my ($ldap,$root_dse,$root_dns,$smb_admin_pass,$school,$ref_sophomorix_config) = @_;
    if ($school eq $DevelConf::AD_global_ou){
        foreach my $dn (keys %{$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_CN'}}) {
            # create ou for group
            my $group=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_CN'}{$dn};
            my $description="LMN Group, change if you like";
            my $type=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'GROUP_TYPE'}{$group};
            my $school=$ref_sophomorix_config->{$DevelConf::AD_global_ou}{'SCHOOL'};
            # create
            &AD_group_create({ldap=>$ldap,
                              root_dse=>$root_dse,
                              root_dns=>$root_dns,
                              dn_wish=>$dn,
                              school=>$school,
                              group=>$group,
                              group_basename=>$group,
                              description=>$description,
                              type=>$type,
                              status=>"P",
                              joinable=>"TRUE",
                              hidden=>"FALSE",
                              smb_admin_pass=>$smb_admin_pass,
                              sophomorix_config=>$ref_sophomorix_config,
                              sophomorix_result=>$ref_sophomorix_result,
                            });
        }
    } else {
        # *-admin groups must be created FIRST (NTACLs of other groups contain *-admin)
        # this can be done as a hack by an ascibetic sort
        my @dn_list=();
        foreach my $dn (keys %{$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_CN'}}) {
            push @dn_list,$dn;
        }
        @dn_list = sort @dn_list;
        foreach my $dn (@dn_list) {
            # create ou for group
            my $group=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_CN'}{$dn};
            my $description="LMN Group, change if you like";
            my $type=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'GROUP_TYPE'}{$group};
            my $school=$ref_sophomorix_config->{'SCHOOLS'}{$school}{'SCHOOL'};
            # create
            &AD_group_create({ldap=>$ldap,
                              root_dse=>$root_dse,
                              root_dns=>$root_dns,
                              dn_wish=>$dn,
                              school=>$school,
                              group=>$group,
                              group_basename=>$group,
                              description=>$description,
                              type=>$type,
                              status=>"P",
                              joinable=>"TRUE",
                              hidden=>"FALSE",
                              smb_admin_pass=>$smb_admin_pass,
                              sophomorix_config=>$ref_sophomorix_config,
                              sophomorix_result=>$ref_sophomorix_result,
                            });
        }
    }
}


sub AD_object_search {
    my ($ldap,$root_dse,$objectclass,$name) = @_;
    # returns 0,"" or 1,"dn of object"
    # objectClass: group, user, ...
    # check if object exists
    # (&(objectClass=user)(cn=pete)
    # (&(objectClass=group)(cn=7a)
    my $filter;
    my $base;
    if ($objectclass eq "dnsNode" or $objectclass eq "dnsZone"){
        # searching dnsNode
        $base="DC=DomainDnsZones,".$root_dse;
        $filter="(&(objectClass=".$objectclass.") (name=".$name."))"; 
    } elsif  ($objectclass eq "all"){
        # find all 
        $base=$root_dse;
        $filter="(cn=".$name.")"; 
    } else {
        $base=$root_dse;
        $filter="(&(objectClass=".$objectclass.") (cn=".$name."))"; 
    }

    my $mesg = $ldap->search(
                      base   => $base,
                      scope => 'sub',
                      filter => $filter,
                      attr => ['cn']
                            );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $count = $mesg->count;
    if ($count > 0){
        # process first entry
        my ($entry,@entries) = $mesg->entries;
        my $dn = $entry->dn();
        my $cn;
        if (defined $entry->get_value ('cn')){
            $cn = $entry->get_value ('cn');
            $cn="CN=".$cn;
        } else {
            $cn="CN=---";
        } 
        my $info="no sophomorix info available (Role, Type)";
        if ($objectclass eq "group"){
            $info = $entry->get_value ('sophomorixType');
        } elsif ($objectclass eq "user"){
            $info = $entry->get_value ('sophomorixRole');
        } elsif ($objectclass eq "dnsZone"){
            $info = $entry->get_value ('sophomorixRole');
        } elsif ($objectclass eq "dnsNode"){
            $info = $entry->get_value ('sophomorixRole');
        }
        return ($count,$dn,$cn,$info);
    } else {
        return (0,"","");
    }
}



sub AD_get_sessions {
    my ($ldap,
	$root_dse,
	$root_dns,
	$json,
	$show_session,
	$show_supervisor,
	$smb_admin_pass,
	$list_transfer_dirs,
	$list_quota,
	$ref_sophomorix_config)=@_;
    my %sessions=();
    my %management=();
    my $session_count=0;
    { # begin block
	my $filter="(& (objectClass=group) (| ";
        foreach my $grouptype (@{ $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'} }){
            $filter=$filter."(sophomorixType=".$grouptype.")";
        }
        $filter=$filter." ) )";
        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['sAMAccountName',
                                    'sophomorixSchoolname',
                                    'sophomorixStatus',
                                    'sophomorixType',
                                    'member',
                                   ]);
        my $max_mangroups = $mesg->count;
        &Sophomorix::SophomorixBase::print_title("$max_mangroups managementgroups found in AD");
        for( my $index = 0 ; $index < $max_mangroups ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            #$management{'managementgroup'}{$type}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
            $management{'managementgroup'}{$type}{$sam}{'sophomorixSchoolname'}=$schoolname;
            # members
            # creating member lookup table
            my @man_members=$entry->get_value('member');
            foreach my $member (@man_members){
                my ($sam_user,@unused)=split(/,/,$member);
                $sam_user=~s/^CN=//g; # remove leading CN=
                $management{'managementgroup'}{$type}{$sam}{'members'}{$sam_user}=$member;
            }
        }
    } # end block

    # fetching the sessions
    my $filter;
    my $base;
    if ($show_supervisor eq "allsupervisors"){
	$base=$root_dse;
	$filter="(&(objectClass=user)(sophomorixSessions=*)(|(sophomorixRole=student)(sophomorixRole=teacher)))";
    } else {
	$base=$root_dse;	
	$filter="(&(objectClass=user)(sophomorixSessions=*)(sAMAccountName=$show_supervisor)(|(sophomorixRole=student)(sophomorixRole=teacher)))";
    }	
    my $mesg = $ldap->search( # perform a search
                   base   => $base,
                   scope => 'sub',
                   filter => $filter,
                   attrs => ['sAMAccountName',
                             'sophomorixSessions',
                             'sophomorixRole',
                             'givenName',
                             'sn',
                             'sophomorixSchoolname',
                             'sophomorixExamMode',
                             'sophomorixStatus',
                             'homeDirectory',
                            ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max_user = $mesg->count; 
    if($Conf::log_level>=2){
        &Sophomorix::SophomorixBase::print_title("$max_user sophomorix users have sessions");
    }

    $AD{'RESULT'}{'supervisor'}{'student'}{'COUNT'}=$max_user;

    # walk through all supervisors
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
        my $supervisor=$entry->get_value('sAMAccountName');
        my @session_list = sort $entry->get_value('sophomorixSessions');
        if($Conf::log_level>=2){
            my $user_session_count=$#session_list+1;
            print "   * User $supervisor has $user_session_count sessions\n";
	}
        # walk through all sessions of the user
        foreach my $session (@session_list){
            $session_count++;
            if($Conf::log_level>=2){
                &Sophomorix::SophomorixBase::print_title("$session_count: User $supervisor has session $session");
            }
            my ($id,$comment,$participants,$string)=split(/;/,$session);

	    # select auto generaded sessions
	    if ($comment=~m/-autoGenerated$/){
                $sessions{'AUTO_GENERATED_by_session'}{$id}=$comment;
	    }

            if ($show_session eq "all" or $id eq $show_session){
                # just go on
                if($Conf::log_level>=2){
                    print "   * Loading partial data of session $id.\n";
                }
            
                # calculate smb_dir
                my $smb_dir=$entry->get_value('homeDirectory');
                $smb_dir=~s/\\/\//g;
		my $key="TRANSFER_DIR_HOME_".$ref_sophomorix_config->{'GLOBAL'}{'LANG'};
                my $transfer=$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{$key};
                $smb_dir="smb:".$smb_dir."/".$transfer;
		#print "SMB: $smb_dir\n";

                # save supervisor information
                #--------------------------------------------------
                # save by user
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'sophomorixSessions'}=$session;
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'COMMENT'}=$comment;
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTSTRING'}=$participants;
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixRole'}=$entry->get_value('sophomorixRole');
                $sessions{'SUPERVISOR'}{$supervisor}{'givenName'}=$entry->get_value('givenName');
                $sessions{'SUPERVISOR'}{$supervisor}{'sn'}=$entry->get_value('sn');
                $sessions{'SUPERVISOR'}{$supervisor}{'homeDirectory'}=$entry->get_value('homeDirectory');
                $sessions{'SUPERVISOR'}{$supervisor}{'SMBhomeDirectory'}=$smb_dir;
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixExamMode'}=$entry->get_value('sophomorixExamMode');
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
                push @{ $sessions{'SUPERVISOR_LIST'} }, $supervisor; 
                # save by id
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sAMAccountName'}=$supervisor;
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sophomorixRole'}=$entry->get_value('sophomorixRole');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'givenName'}=$entry->get_value('givenName');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sn'}=$entry->get_value('sn');
                $sessions{'ID'}{$id}{'sophomorixSessions'}=$session;
                $sessions{'ID'}{$id}{'COMMENT'}=$comment;
                $sessions{'ID'}{$id}{'PARTICIPANTSTRING'}=$participants;
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'homeDirectory'}=$entry->get_value('homeDirectory');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'SMBhomeDirectory'}=$smb_dir;
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sophomorixExamMode'}=$entry->get_value('sophomorixExamMode');
                $sessions{'ID'}{$id}{'SUPERVISOR'}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
                push @{ $sessions{'ID_LIST'} }, $id; 

                # save participant information
                #--------------------------------------------------
                my @participants=split(/,/,$participants);
                if ($#participants==-1){
                    # skip user detection when participantlist is empty
                    next;
                }

                foreach $participant (@participants){
                    my $exammode_boolean;
                    # get userinfo
                    my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
                        $home_directory_AD,$user_account_control_AD,$toleration_date_AD,
                        $deactivation_date_AD,$school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
                        &AD_get_user({ldap=>$ldap,
                                      root_dse=>$root_dse,
                                      root_dns=>$root_dns,
                                      user=>$participant,
				     });
		    if ($existing_AD eq "FALSE"){
 		        print "WARNING: User $participant nonexisting but part of session $id\n";
			$sessions{'NONEXISTING_PARTICIPANTS_by_session'}{$id}{'PARTICIPANTS'}{$participant}="NONEXISTING";
			$sessions{'NONEXISTING_PARTICIPANTS_by_session'}{$id}{'SUPERVISOR'}=$supervisor;

                        $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'user_existing'}=$existing_AD;
                        $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'user_existing'}=$existing_AD;
                        next;
		    }
                    if ($exammode_AD ne "---"){
                        $exammode_boolean="TRUE";
                        # display exam-account
                        $participant=$participant.$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'};
                        
                        # get data again
                        ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
                        $home_directory_AD,$user_account_control_AD,$toleration_date_AD,
                        $deactivation_date_AD,$school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
                        &AD_get_user({ldap=>$ldap,
                                      root_dse=>$root_dse,
                                      root_dns=>$root_dns,
                                      user=>$participant,
                                    });
                    } else {
                        $exammode_boolean="FALSE";
                    }

                    # calculate smb_dir
                    my $smb_dir=$home_directory_AD;
                    $smb_dir=~s/\\/\//g;
		    my $key="TRANSFER_DIR_HOME_".$ref_sophomorix_config->{'GLOBAL'}{'LANG'};
                    my $transfer=$ref_sophomorix_config->{'INI'}{'LANG.FILESYSTEM'}{$key};
                    $smb_dir="smb:".$smb_dir."/".$transfer;
		    #print "SMB: $smb_dir\n";


                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'exammode_boolean'}=$exammode_boolean;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'givenName'}=$firstname_utf8_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sn'}=$lastname_utf8_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixAdminClass'}=$adminclass_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'user_existing'}=$existing_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixRole'}=$role_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixExamMode'}=$exammode_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixStatus'}=$status_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'homeDirectory'}=$home_directory_AD;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'SMBhomeDirectory'}=$smb_dir;
                    $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixSchoolname'}=$school_AD;
                    push @{ $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} }, $participant; 

                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'givenName'}=$firstname_utf8_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sn'}=$lastname_utf8_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sophomorixAdminClass'}=$adminclass_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'user_existing'}=$existing_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sophomorixExamMode'}=$exammode_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sophomorixStatus'}=$status_AD;
                    $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANTS'}
                             {$participant}{'sophomorixRole'}=$role_AD;
                    push @{ $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'} }, $participant; 

                    # test membership in managementgroups
                    foreach my $grouptype (@{ $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'MANAGEMENTGROUPLIST'} }){
                        # befor testing set FALSE as default
                        $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{"group_".$grouptype}="FALSE";
                        $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}
                                 {'PARTICIPANTS'}{$participant}{"group_".$grouptype}="FALSE";
                        foreach my $group (keys %{$management{'managementgroup'}{$grouptype}}) {
                           if (exists $management{'managementgroup'}{$grouptype}{$group}{'members'}{$participant}){
                                # if in the groups, set TRUE
                                $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{"group_".$grouptype}="TRUE";
                                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}
                                         {'PARTICIPANTS'}{$participant}{"group_".$grouptype}="TRUE";
                            }
                        }
                    }
                }

                # sort some lists and count
		if ( exists $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} ){
                    @{ $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} } = sort @{ $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} };
                }
                $sessions{'ID'}{$id}{'PARTICIPANT_COUNT'}=$#{ $sessions{'ID'}{$id}{'PARTICIPANT_LIST'} }+1;
                if (exists $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'}){
		    @{ $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'} } = 
                        sort @{ $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'} };
                }
                $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_COUNT'}=
                    $#{ $sessions{'SUPERVISOR'}{$supervisor}{'sophomorixSessions'}{$id}{'PARTICIPANT_LIST'} }+1;

                # save extended information
                #--------------------------------------------------
                if ($id eq $show_session){
                    if($Conf::log_level>=2){
                        print "   * Loading extended data of selected session $id.\n";
                    }
                    # transfer directory of supervisor
                    my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
                        $home_directory_AD,$user_account_control_AD,$toleration_date_AD,
                        $deactivation_date_AD,$school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
                    &AD_get_user({ldap=>$ldap,
                                  root_dse=>$root_dse,
                                  root_dns=>$root_dns,
                                  user=>$sessions{'ID'}{$show_session}{'SUPERVISOR'}{'sAMAccountName'},
                                });

                    if ($list_transfer_dirs==1){
                        &Sophomorix::SophomorixBase::dir_listing_user($root_dns,
                                                                      $sessions{'ID'}{$show_session}{'SUPERVISOR'}{'sAMAccountName'},
                                                                      $sessions{'ID'}{$show_session}{'SUPERVISOR'}{'SMBhomeDirectory'},
                                                                      $sessions{'ID'}{$show_session}{'SUPERVISOR'}{'sophomorixSchoolname'},
                                                                      $smb_admin_pass,
                                                                      \%sessions,
                                                                      $ref_sophomorix_config,
                                                                      $school_AD,
                                                                     );
		    }

                    # participants
                    foreach my $participant (keys %{$sessions{'ID'}{$id}{'PARTICIPANTS'}}) {
                        # managementgroups

                        if ($sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'user_existing'} eq "FALSE"){
 		            print "WARNING: $participant nonexisting (Skipping  dirlisting and quota)\n";
                            next;
			}

			if ($list_transfer_dirs==1){
                            # transfer directory of participants
                            &Sophomorix::SophomorixBase::dir_listing_user(
                                $root_dns,
                                $participant,
                                $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'SMBhomeDirectory'},
                                $sessions{'ID'}{$id}{'PARTICIPANTS'}{$participant}{'sophomorixSchoolname'},
                                $smb_admin_pass,
                                \%sessions,
                                $ref_sophomorix_config,
			    );
			}
			if ($list_quota==1){
                            # quota
                            &Sophomorix::SophomorixBase::quota_listing_session_participant($participant,
                                                                                           $show_session,
                                                                                           $supervisor,
                                                                                           \%sessions);
			}
                    }
                }         
            } else { #neither all nor the requested session
                # skip this session
                if($Conf::log_level>=2){
                    print "   * Session $id was not requested.\n";
                }            
                next;
            }
        }
    }
    $sessions{'SESSIONCOUNT'}=$session_count;
    @{ $sessions{'SUPERVISOR_LIST'} }=uniq(@{ $sessions{'SUPERVISOR_LIST'} });
    &Sophomorix::SophomorixBase::print_title("$session_count running sessions found");
    return %sessions; 
}



sub AD_get_AD_for_repair {
    my %AD=();
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
   
    ############################################################
    # groups with sophomorixType from ldap
    {
        my $filter="(& (objectClass=group) (| ".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'EXTRACLASS'}.")".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ADMINCLASS'}.")".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'TEACHERCLASS'}.")".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ADMINS'}.")".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ALLADMINS'}.")".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'POWERGROUP'}.")".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'PROJECT'}.")".
           "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ROOM'}.")".
           " ) )";
        
        #print "FILTER: $filter\n";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixSchoolname',
                                 'sophomorixType',
                                ]);
        my $max_adminclass = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title(
            "$max_adminclass sophomorix adminclasses found in AD");
        $AD{'RESULT'}{'group'}{'class'}{'COUNT'}=$max_adminclass;
        for( my $index = 0 ; $index < $max_adminclass ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            # lists
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{'global'}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'groups_BY_sophomorixType'}{$type} }, $sam; 
        }
    }

    ############################################################
    # users with sophomorixRole from ldap
    {
        my $filter="(&(objectClass=user)(|(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'STUDENT'}.")(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'TEACHER'}.")(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'GLOBALADMINISTRATOR'}.")(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'SCHOOLADMINISTRATOR'}.")))";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixAdminClass',
                                 'sophomorixSchoolname',
                                ]);
        my $max_user = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_user sophomorix students found in AD");
        $AD{'RESULT'}{'user'}{'student'}{'COUNT'}=$max_user;
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}
                       {'users_BY_group'}{$entry->get_value('sophomorixAdminClass')} }, $sam;  
        }
    }

    ############################################################
    # computers with sophomorixRole from ldap
    {
        my $filter="(& (objectClass=computer)(sophomorixRole=*) )";
        #print "Filter: $filter\n";
        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['sAMAccountName',
                                    'sophomorixSchoolname',
                                    'sophomorixAdminClass',
                                  ]);
        my $max_user = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_user Computers found in AD");
        $AD{'RESULT'}{'computer'}{'computer'}{'COUNT'}=$max_user;
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}
                       {'users_BY_group'}{$entry->get_value('sophomorixAdminClass')} }, $sam;  
        }
    }
    return(\%AD);
}



sub AD_get_AD_for_check_old {
    my %AD=();
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $admins = $arg_ref->{admins};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my $unid_warn_count=0;
    my $identifier_warn_count=0;

    # forbidden login names
    $AD{'FORBIDDEN'}{'root'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'linbo'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'opsi'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'container'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'mail'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'webui'}="forbidden by Hand";

    ############################################################
    # SEARCH FOR ALL
    &Sophomorix::SophomorixBase::print_title("Query AD (begin)");

    # get all objects (for forbidden logins)
    my $filter="(| (objectClass=user) (objectClass=group) (objectClass=computer) )";
    my $mesg = $ldap->search( # perform a search
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attrs => ['sAMAccountName',
                                'sophomorixSchoolname',
                                'sophomorixStatus',
                                'sophomorixUnid',
                                'sophomorixSurnameASCII',
                                'sophomorixFirstnameASCII',
                                'sophomorixBirthdate',
                                'sn',
                                'givenName',
                                'displayName',
                                'mail',
				'homeDirectory',
                                'sophomorixSurnameInitial',
                                'sophomorixFirstnameInitial',
                                'sophomorixAdminFile',
                                'sophomorixAdminClass',
                                'sophomorixRole',
                                'sophomorixType',
                                'sophomorixTolerationDate',
                                'sophomorixDeactivationDate',
                                'SophomorixWebuiPermissions',
                                'SophomorixWebuiPermissionsCalculated',
                                'objectClass',
                                'sophomorixIntrinsic1',
                                'sophomorixIntrinsic2',
                                'sophomorixIntrinsic3',
                                'sophomorixIntrinsic4',
                                'sophomorixIntrinsic5',
                               ]);
    my $max = $mesg->count;
    for( my $index = 0 ; $index < $max ; $index++) {
       my $entry = $mesg->entry($index);
       my $sam=$entry->get_value('sAMAccountName');
       #my $objectclass=$entry->get_value('objectClass');
       my $role;
       my $type;
       my $forbidden_warn; # what to save as warn message

       if (defined $entry->get_value('sophomorixRole')){
           ##### a sophomorix user #####
           $role=$entry->get_value('sophomorixRole');
           $forbidden_warn="$sam forbidden, $sam exists already as a sophomorix user";
           if ($role eq $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'STUDENT'} or
               $role eq $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'TEACHER'} or
               $role eq "schooladministrator" or 
               $role eq "globaladministrator"
              ){
               if ($admins eq "FALSE" and ($role eq "schooladministrator" or $role eq "globaladministrator") ){
                   # do nothing
               } else {
                   # save needed stuff
                   $AD{'sAMAccountName'}{$sam}{'sophomorixRole'}=$role;
                   $AD{'sAMAccountName'}{$sam}{'dn'}=$entry->dn();
                   $AD{'sAMAccountName'}{$sam}{'sophomorixUnid'}=$entry->get_value('sophomorixUnid');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixSurnameASCII'}=$entry->get_value('sophomorixSurnameASCII');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixFirstnameASCII'}=$entry->get_value('sophomorixFirstnameASCII');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixBirthdate'}=$entry->get_value('sophomorixBirthdate');
                   $AD{'sAMAccountName'}{$sam}{'sn'}=$entry->get_value('sn');
                   $AD{'sAMAccountName'}{$sam}{'givenName'}=$entry->get_value('givenName');
                   $AD{'sAMAccountName'}{$sam}{'displayName'}=$entry->get_value('displayName');
                   $AD{'sAMAccountName'}{$sam}{'mail'}=$entry->get_value('mail');
                   $AD{'sAMAccountName'}{$sam}{'homeDirectory'}=$entry->get_value('homeDirectory');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixSurnameInitial'}=$entry->get_value('sophomorixSurnameInitial');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixFirstnameInitial'}=$entry->get_value('sophomorixFirstnameInitial');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixAdminFile'}=$entry->get_value('sophomorixAdminFile');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixTolerationDate'}=$entry->get_value('sophomorixTolerationDate');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixDeactivationDate'}=$entry->get_value('sophomorixDeactivationDate');

                   my $identifier_ascii=
                       $entry->get_value('sophomorixSurnameASCII').
                       ";".
                       $entry->get_value('sophomorixFirstnameASCII').
                       ";".
                       $entry->get_value('sophomorixBirthdate');
                   $AD{'sAMAccountName'}{$sam}{'IDENTIFIER_ASCII'}=$identifier_ascii;

                   my $identifier_utf8=
                       $entry->get_value('sn').
                       ";".
                       $entry->get_value('givenName').
                       ";".
                       $entry->get_value('sophomorixBirthdate');
                   # wegelassen: IDENTIFIER_UTF8,userAccountControl,sophomorixPrefix
                   # $AD{'sAMAccountName'}{$sam}{'IDENTIFIER_UTF8'}=$identifier_utf8;


                   # check for double sophomorixUnid in AD
		   if($entry->get_value('sophomorixUnid') ne "---" and
                       exists $AD{'seen'}{'unid'}{$entry->get_value('sophomorixSchoolname')}{$entry->get_value('sophomorixUnid')}
		     ){
		       $unid_warn_count++;  
                       my $old_sam=$AD{'seen'}{'unid'}{$entry->get_value('sophomorixSchoolname')}{$entry->get_value('sophomorixUnid')};
                       my $old_identifier_ascii=$AD{'sAMAccountName'}{$old_sam}{'IDENTIFIER_ASCII'}; 
		       # save warning for later use
                       $AD{'WARNINGS'}{'sophomorixUnid'}{$entry->get_value('sophomorixUnid')}{'TYPE'}="sophomorixUnid multiple";
                       $AD{'WARNINGS'}{'sophomorixUnid'}{$entry->get_value('sophomorixUnid')}{'COUNT'}=$unid_warn_count;
		       # current user
                       $AD{'WARNINGS'}{'sophomorixUnid'}{$entry->get_value('sophomorixUnid')}{$sam}=$identifier_ascii;
		       # other user
                       $AD{'WARNINGS'}{'sophomorixUnid'}{$entry->get_value('sophomorixUnid')}{$old_sam}=$old_identifier_ascii;
		   } else {
                       $AD{'seen'}{'unid'}{$entry->get_value('sophomorixSchoolname')}{$entry->get_value('sophomorixUnid')}=$sam;
		   }


                   # check for double identifier in AD
		   if(exists $AD{'seen'}{'IDENTIFIER_ASCII'}{$entry->get_value('sophomorixSchoolname')}{$identifier_ascii}
		     ){
		       $identifier_warn_count++;
                       my $old_sam=$AD{'seen'}{'IDENTIFIER_ASCII'}{$entry->get_value('sophomorixSchoolname')}{$identifier_ascii};
                       my $old_unid=$AD{'sAMAccountName'}{$old_sam}{'sophomorixUnid'}; 
		       # save warning for later use
                       $AD{'WARNINGS'}{'IDENTIFIER_ASCII'}{$identifier_ascii}{'TYPE'}="IDENTIFIER_ASCII multiple";
                       $AD{'WARNINGS'}{'IDENTIFIER_ASCII'}{$identifier_ascii}{'COUNT'}=$identifier_warn_count;
		       # current user
                       $AD{'WARNINGS'}{'IDENTIFIER_ASCII'}{$identifier_ascii}{$sam}=$entry->get_value('sophomorixUnid');
		       # other user
                       $AD{'WARNINGS'}{'IDENTIFIER_ASCII'}{$identifier_ascii}{$old_sam}=$old_unid;
		   } else {
                       $AD{'seen'}{'IDENTIFIER_ASCII'}{$entry->get_value('sophomorixSchoolname')}{$identifier_ascii}=$sam;
		   }


                   # save ui stuff
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixWebuiPermissions'} } =
                       sort $entry->get_value('sophomorixWebuiPermissions');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixWebuiPermissionsCalculated'} } =
                       sort $entry->get_value('sophomorixWebuiPermissionsCalculated');

                   # save intrinsic stuff
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic1'}=$entry->get_value('sophomorixIntrinsic1');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic2'}=$entry->get_value('sophomorixIntrinsic2');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic3'}=$entry->get_value('sophomorixIntrinsic3');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic4'}=$entry->get_value('sophomorixIntrinsic4');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic5'}=$entry->get_value('sophomorixIntrinsic5');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti1'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti1');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti2'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti2');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti3'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti3');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti4'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti4');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti5'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti5');

                   # LOOKUP
                   $AD{'LOOKUP'}{'user_BY_identifier_utf8'}{$identifier_utf8}=$sam;
                   $AD{'LOOKUP'}{'user_BY_identifier_ascii'}{$identifier_ascii}=$sam;
                   $AD{'LOOKUP'}{'sophomorixStatus_BY_identifier_ascii'}{$identifier_ascii}=$entry->get_value('sophomorixStatus');
                   $AD{'LOOKUP'}{'sophomorixRole_BY_sAMAccountName'}{$sam}=$entry->get_value('sophomorixRole');
                   if ($entry->get_value('sophomorixUnid') ne "---"){
                       # no lookup for unid '---'
                       $AD{'LOOKUP'}{'user_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=$sam;
                       # $AD{'LOOKUP'}{'identifier_utf8_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                       #     $identifier_utf8;
                       $AD{'LOOKUP'}{'identifier_ascii_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                           $identifier_ascii;
                   }
               }
           }
       } elsif (defined $entry->get_value('sophomorixType')){
           ##### a sophomorix group #####
           $type=$entry->get_value('sophomorixType');
           $forbidden_warn="$sam forbidden, $sam exists already as a sophomorix group";
       } else {
           ##### a non sophomorix object #####
           $forbidden_warn="$sam forbidden, $sam exists already as a non-sophomorix object";
       }

       $AD{'FORBIDDEN'}{$sam}=$forbidden_warn;
       #print "$sam: $forbidden_warn\n";
    }

    &Sophomorix::SophomorixBase::print_title("Query AD (end)");
    return(\%AD);
}



sub AD_get_AD_for_check {
    my %AD=();
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $admins = $arg_ref->{admins};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my $unid_warn_count=0;
    my $identifier_warn_count=0;

    # forbidden login names
    $AD{'FORBIDDEN'}{'root'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'linbo'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'opsi'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'container'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'mail'}="forbidden by Hand";
    $AD{'FORBIDDEN'}{'webui'}="forbidden by Hand";

    ############################################################
    # SEARCH FOR ALL
    &Sophomorix::SophomorixBase::print_title("Query AD (begin)");

    # get all objects (for forbidden logins)
    my $filter="(| (objectClass=user) (objectClass=group) (objectClass=computer) )";
    my $mesg = $ldap->search( # perform a search
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attrs => ['sAMAccountName',
                                'sophomorixSchoolname',
                                'sophomorixStatus',
                                'sophomorixUnid',
                                'sophomorixSurnameASCII',
                                'sophomorixFirstnameASCII',
                                'sophomorixBirthdate',
                                'sn',
                                'givenName',
                                'displayName',
                                'mail',
				'homeDirectory',
                                'sophomorixSurnameInitial',
                                'sophomorixFirstnameInitial',
                                'sophomorixFirstPassword',
                                'sophomorixAdminFile',
                                'sophomorixAdminClass',
                                'sophomorixExitAdminClass',
                                'sophomorixRole',
                                'sophomorixType',
                                'sophomorixTolerationDate',
                                'sophomorixDeactivationDate',
                                'SophomorixWebuiPermissions',
                                'SophomorixWebuiPermissionsCalculated',
                                'objectClass',
                                'sophomorixIntrinsic1',
                                'sophomorixIntrinsic2',
                                'sophomorixIntrinsic3',
                                'sophomorixIntrinsic4',
                                'sophomorixIntrinsic5',
                               ]);
    my $max = $mesg->count;
    for( my $index = 0 ; $index < $max ; $index++) {
       my $entry = $mesg->entry($index);
       my $sam=$entry->get_value('sAMAccountName');
       #my $objectclass=$entry->get_value('objectClass');
       my $role;
       my $type;
       my $forbidden_warn; # what to save as warn message

       if (defined $entry->get_value('sophomorixRole')){
           ##### a sophomorix user #####
           $role=$entry->get_value('sophomorixRole');
           $forbidden_warn="$sam forbidden, $sam exists already as a sophomorix user";
           if ($role eq $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'STUDENT'} or
               $role eq $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'TEACHER'} or
               $role eq "schooladministrator" or 
               $role eq "globaladministrator"
              ){
               if ($admins eq "FALSE" and ($role eq "schooladministrator" or $role eq "globaladministrator") ){
                   # do nothing
               } else {
                   # save needed stuff
                   my $dn=$entry->dn();
                   my $file=$entry->get_value('sophomorixAdminFile');
                   my $school=$entry->get_value('sophomorixSchoolname');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixRole'}=$role;
                   $AD{'sAMAccountName'}{$sam}{'dn'}=$dn;
                   $AD{'sAMAccountName'}{$sam}{'sophomorixUnid'}=$entry->get_value('sophomorixUnid');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixSchoolname'}=$school;
                   $AD{'sAMAccountName'}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixSurnameASCII'}=$entry->get_value('sophomorixSurnameASCII');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixFirstnameASCII'}=$entry->get_value('sophomorixFirstnameASCII');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixBirthdate'}=$entry->get_value('sophomorixBirthdate');
                   $AD{'sAMAccountName'}{$sam}{'sn'}=$entry->get_value('sn');
                   $AD{'sAMAccountName'}{$sam}{'givenName'}=$entry->get_value('givenName');
                   $AD{'sAMAccountName'}{$sam}{'displayName'}=$entry->get_value('displayName');
                   $AD{'sAMAccountName'}{$sam}{'mail'}=$entry->get_value('mail');
                   $AD{'sAMAccountName'}{$sam}{'homeDirectory'}=$entry->get_value('homeDirectory');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixSurnameInitial'}=$entry->get_value('sophomorixSurnameInitial');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixFirstnameInitial'}=$entry->get_value('sophomorixFirstnameInitial');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixFirstPassword'}=$entry->get_value('sophomorixFirstPassword');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixAdminFile'}=$file;
                   $AD{'sAMAccountName'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixExitAdminClass'}=$entry->get_value('sophomorixExitAdminClass');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixTolerationDate'}=$entry->get_value('sophomorixTolerationDate');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixDeactivationDate'}=$entry->get_value('sophomorixDeactivationDate');

                   my $identifier_ascii=
                       $entry->get_value('sophomorixSurnameASCII').
                       ";".
                       $entry->get_value('sophomorixFirstnameASCII').
                       ";".
                       $entry->get_value('sophomorixBirthdate');
                   $AD{'sAMAccountName'}{$sam}{'IDENTIFIER_ASCII'}=$identifier_ascii;

                   my $identifier_utf8=
                       $entry->get_value('sn').
                       ";".
                       $entry->get_value('givenName').
                       ";".
                       $entry->get_value('sophomorixBirthdate');
                   # wegelassen: IDENTIFIER_UTF8,userAccountControl,sophomorixPrefix
                   # $AD{'sAMAccountName'}{$sam}{'IDENTIFIER_UTF8'}=$identifier_utf8;



                   # check for double sophomorixUnid in AD
		   if($entry->get_value('sophomorixUnid') ne "---" and
                       exists $AD{'seen'}{'unid'}{$entry->get_value('sophomorixSchoolname')}{$entry->get_value('sophomorixUnid')}
		     ){
		       $unid_warn_count++;
                       my $old_sam=$AD{'seen'}{'unid'}{$entry->get_value('sophomorixSchoolname')}{$entry->get_value('sophomorixUnid')};
                       my $old_identifier_ascii=$AD{'sAMAccountName'}{$old_sam}{'IDENTIFIER_ASCII'};
		       # save warning for later use
                       $AD{'WARNINGS'}{'sophomorixUnid'}{$entry->get_value('sophomorixUnid')}{'TYPE'}="sophomorixUnid multiple";
                       $AD{'WARNINGS'}{'sophomorixUnid'}{$entry->get_value('sophomorixUnid')}{'COUNT'}=$unid_warn_count;
		       # current user
                       $AD{'WARNINGS'}{'sophomorixUnid'}{$entry->get_value('sophomorixUnid')}{$sam}=$identifier_ascii;
		       # other user
                       $AD{'WARNINGS'}{'sophomorixUnid'}{$entry->get_value('sophomorixUnid')}{$old_sam}=$old_identifier_ascii;
		   } else {
                       $AD{'seen'}{'unid'}{$entry->get_value('sophomorixSchoolname')}{$entry->get_value('sophomorixUnid')}=$sam;
		   }


                   # check for double identifier in AD
		   if(exists $AD{'seen'}{'IDENTIFIER_ASCII'}{$entry->get_value('sophomorixSchoolname')}{$identifier_ascii}
		     ){
		       $identifier_warn_count++;
                       my $old_sam=$AD{'seen'}{'IDENTIFIER_ASCII'}{$entry->get_value('sophomorixSchoolname')}{$identifier_ascii};
                       my $old_unid=$AD{'sAMAccountName'}{$old_sam}{'sophomorixUnid'};
		       # save warning for later use
                       $AD{'WARNINGS'}{'IDENTIFIER_ASCII'}{$identifier_ascii}{'TYPE'}="IDENTIFIER_ASCII multiple";
                       $AD{'WARNINGS'}{'IDENTIFIER_ASCII'}{$identifier_ascii}{'COUNT'}=$identifier_warn_count;
		       # current user
                       $AD{'WARNINGS'}{'IDENTIFIER_ASCII'}{$identifier_ascii}{$sam}=$entry->get_value('sophomorixUnid');
		       # other user
                       $AD{'WARNINGS'}{'IDENTIFIER_ASCII'}{$identifier_ascii}{$old_sam}=$old_unid;
		   } else {
                       $AD{'seen'}{'IDENTIFIER_ASCII'}{$entry->get_value('sophomorixSchoolname')}{$identifier_ascii}=$sam;
		   }


                   # save ui stuff
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixWebuiPermissions'} } =
                       sort $entry->get_value('sophomorixWebuiPermissions');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixWebuiPermissionsCalculated'} } =
                       sort $entry->get_value('sophomorixWebuiPermissionsCalculated');

                   # save intrinsic stuff
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic1'}=$entry->get_value('sophomorixIntrinsic1');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic2'}=$entry->get_value('sophomorixIntrinsic2');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic3'}=$entry->get_value('sophomorixIntrinsic3');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic4'}=$entry->get_value('sophomorixIntrinsic4');
                   $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsic5'}=$entry->get_value('sophomorixIntrinsic5');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti1'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti1');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti2'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti2');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti3'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti3');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti4'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti4');
                   @{ $AD{'sAMAccountName'}{$sam}{'sophomorixIntrinsicMulti5'} } =
                       sort $entry->get_value('sophomorixIntrinsicMulti5');

                   # LIST for rolegroups
                   push @{ $AD{'LIST_user_by_sophomorixRole'}{$role}{'GLOBAL'} }, $sam;
                   push @{ $AD{'LIST_dn_by_sophomorixRole'}{$role}{'GLOBAL'} }, $dn;

                   # LOOKUP
                   $AD{'LOOKUP'}{'sophomorixRole_BY_sAMAccountName'}{$sam}=$entry->get_value('sophomorixRole');

                   # LOOKUP by filename
                   $AD{'LOOKUP_by_filename'}{$file}{'user_BY_sAMAccountName'}{$sam}="seen in AD";
                   $AD{'LOOKUP_by_filename'}{$file}{'user_BY_identifier_utf8'}{$identifier_utf8}=$sam;
                   $AD{'LOOKUP_by_filename'}{$file}{'user_BY_identifier_ascii'}{$identifier_ascii}=$sam;
                   $AD{'LOOKUP_by_filename'}{$file}{'sophomorixStatus_BY_identifier_ascii'}{$identifier_ascii}=$entry->get_value('sophomorixStatus');
                   if ($entry->get_value('sophomorixUnid') ne "---"){
                       # no lookup for unid '---'
                       $AD{'LOOKUP_by_filename'}{$file}{'user_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=$sam;
                       # $AD{'LOOKUP_by_filename'}{$file}{'identifier_utf8_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                       #     $identifier_utf8;
                       $AD{'LOOKUP_by_filename'}{$file}{'identifier_ascii_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                           $identifier_ascii;
                   }

                   # LOOKUP by school
                   $AD{'LOOKUP_by_school'}{$school}{'user_BY_sAMAccountName'}{$sam}="seen in AD";
                   $AD{'LOOKUP_by_school'}{$school}{'user_BY_identifier_utf8'}{$identifier_utf8}=$sam;
                   $AD{'LOOKUP_by_school'}{$school}{'user_BY_identifier_ascii'}{$identifier_ascii}=$sam;
                   $AD{'LOOKUP_by_school'}{$school}{'sophomorixStatus_BY_identifier_ascii'}{$identifier_ascii}=$entry->get_value('sophomorixStatus');
                   if ($entry->get_value('sophomorixUnid') ne "---"){
                       # no lookup for unid '---'
                       $AD{'LOOKUP_by_school'}{$school}{'user_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=$sam;
                       # $AD{'LOOKUP_by_school'}{$school}{'identifier_utf8_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                       #     $identifier_utf8;
                       $AD{'LOOKUP_by_school'}{$school}{'identifier_ascii_BY_sophomorixUnid'}{$entry->get_value('sophomorixUnid')}=
                           $identifier_ascii;
                   }


               }
           }
       } elsif (defined $entry->get_value('sophomorixType')){
           ##### a sophomorix group #####
           $type=$entry->get_value('sophomorixType');
           $school=$entry->get_value('sophomorixSchoolname');
           $forbidden_warn="$sam forbidden, $sam exists already as a sophomorix group";

           # LOOKUP by school
           $AD{'LOOKUP_by_school'}{$school}{'group_BY_sAMAccountName'}{$sam}{'sophomorixType'}=$type;
       } else {
           ##### a non sophomorix object #####
           $forbidden_warn="$sam forbidden, $sam exists already as a non-sophomorix object";
       }

       $AD{'FORBIDDEN'}{$sam}=$forbidden_warn;
       #print "$sam: $forbidden_warn\n";
    }

    &Sophomorix::SophomorixBase::print_title("Query AD (end)");
    return(\%AD);
}



sub AD_get_schema {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my %schema=();
    &Sophomorix::SophomorixBase::print_title("Query AD for schema (start)");
    my $filter="(LDAPDisplayName=*)";
    my $base="CN=Schema,CN=Configuration,".$root_dse;
    my $mesg = $ldap->search( # perform a search
                          base   => $base,
                          scope => 'sub',
                          filter => $filter,
                                   );
    my $max = $mesg->count;
    my $ref_mesg = $mesg->as_struct; # result in Datenstruktur darstellen
    print Dumper \%mesg;
    # set total counter
    $schema{'RESULT'}{'LDAPDisplayName'}{'TOTAL'}{'COUNT'}=$max;
    print "$max attributes found with LDAPDisplayName\n";
    for( my $index = 0 ; $index < $max ; $index++) {
        my $is_sophomorix=0; # from sophomorix schema or not
        my $entry = $mesg->entry($index); 
        my $dn=$entry->dn();
        my $name=$entry->get_value('LDAPDisplayName');
        my $cn=$entry->get_value('cn');
        $schema{'LDAPDisplayName'}{$name}{'DN'}=$dn;
        $schema{'LDAPDisplayName'}{$name}{'CN'}=$cn;
        $schema{'LOOKUP'}{'LDAPDisplayName_by_DN'}{$dn}=$name;

        # save Camelcase names 
        my $lowercase_name=$name;
        $lowercase_name=~tr/A-Z/a-z/; # make lowercase
        $schema{'LOOKUP'}{'CamelCase'}{$lowercase_name}=$name;

        # $type is classSchema or attributeSchema
        my $type="NONE";
        foreach my $objectclass (@{ $ref_mesg->{$dn}{'objectclass'} }) { # objectclass MUST be lowercase(NET::LDAP hash)
            if ($objectclass eq "classSchema" ){
                $type=$objectclass;
            } elsif ($objectclass eq "attributeSchema"){
                $type=$objectclass;
            }
        }

        foreach my $attr (keys %{ $ref_mesg->{$dn} }) {
            # save it in returned data structure
            $schema{'LDAPDisplayName'}{$name}{$attr}=$ref_mesg->{$dn}{$attr};
            # test if its a sophomorix attribute
            if ($attr eq "attributeid" or $attr eq "governsid"){
                my $attribute_id=$ref_mesg->{$dn}{$attr}[0];
                # 1.3.6.1.4.1.47512     is linuxmuster.net
                # 1.3.6.1.4.1.47512.1   is the sophomorix subspace
                if ( $attribute_id=~m/^1.3.6.1.4.1.47512.1/ ){
                    $is_sophomorix=1;
                } 
            }
        }

        # save attribute in LISTS
        push @{ $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type} }, $name;
        if ($is_sophomorix==1){
            push @{ $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type} }, $name;
        } else {
            push @{ $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type} }, $name;
        }
    }

    # sort and count some lists
    my @types=("classSchema","attributeSchema");
    foreach my $type (@types){
        if (exists $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type}){
            @{ $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type} } = 
                sort @{ $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type} };
            $schema{'RESULT'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type}{'COUNT'}=
                $#{ $schema{'LISTS'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type} }+1;
        } else {
            $schema{'RESULT'}{'LDAPDisplayName'}{'ALL_ATTRS'}{$type}{'COUNT'}=0;
        }

        if (exists $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type}){
            @{ $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type} } = 
                sort @{ $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type} };
            $schema{'RESULT'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type}{'COUNT'}=
            $#{ $schema{'LISTS'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type} }+1;
        } else {
            $schema{'RESULT'}{'LDAPDisplayName'}{'SOPHOMORIX_ATTRS'}{$type}{'COUNT'}=0;
        }

        if (exists $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type}){ 
            @{ $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type} } = 
                sort @{ $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type} };
            $schema{'RESULT'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type}{'COUNT'}=
                $#{ $schema{'LISTS'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type} }+1;
        } else {
	    $schema{'RESULT'}{'LDAPDisplayName'}{'NON_SOPHOMORIX_ATTRS'}{$type}{'COUNT'}=0;
        }
    }
    &Sophomorix::SophomorixBase::print_title("Query AD for schema (end)");
    return \%schema;
}



sub AD_get_AD_for_device {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my %AD=();
    &Sophomorix::SophomorixBase::print_title("Query AD for device (start)");
    ############################################################
    # sophomorix computers from ldap
    { # BLOCK computer start
        ### create filter
        # finds all computer with any string as sophomorixRole
        my $filter="(& (objectClass=computer) (sophomorixRole=*) )";
        # print "Filter:  $filter\n";

        my $mesg = $ldap->search( # perform a search
                          base   => $root_dse,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['sAMAccountName',
                                    'sophomorixSchoolPrefix',
                                    'sophomorixSchoolname',
                                    'sophomorixAdminFile',
                                    'sophomorixAdminClass',
                                    'sophomorixRole',
                                    'sophomorixDnsNodename',
                                    'comment',
                                    'sophomorixComment',
                                    'sophomorixComputerIP',
                                    'sophomorixComputerMAC',
                                    'sophomorixComputerRoom',
                                    'sophomorixComputerDefaults',
				    'sophomorixIntrinsic1',
                                   ]);
        my $max_computer = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_computer Computers found in AD");
        # set total counter
        $AD{'RESULT'}{'computer'}{'TOTAL'}{'COUNT'}=$max_computer;
        # set role counters to 0, will be upcounted later
        foreach my $keyname (keys %{$ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}}) {
            $AD{'RESULT'}{'computer'}{$keyname}{'COUNT'}=0;
        }
        for( my $index = 0 ; $index < $max_computer ; $index++) {
            my $entry = $mesg->entry($index);
            my $sam=$entry->get_value('sAMAccountName');
            my $prefix=$entry->get_value('sophomorixSchoolPrefix');
            my $role=$entry->get_value('sophomorixRole');
            my $school=$entry->get_value('sophomorixSchoolname');
            my $file=$entry->get_value('sophomorixAdminFile');
            $AD{'computer'}{$sam}{'sophomorixSchoolPrefix'}=$prefix;

            $AD{'computer'}{$sam}{'sophomorixRole'}=$role;
            # increase role counter 
            $AD{'RESULT'}{'computer'}{$role}{'COUNT'}++;

            $AD{'computer'}{$sam}{'sophomorixSchoolname'}=$school;
            $AD{'computer'}{$sam}{'sophomorixAdminFile'}=$file;
            $AD{'computer'}{$sam}{'sophomorixDnsNodename'}=$entry->get_value('sophomorixDnsNodename');
            $AD{'computer'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
            $AD{'computer'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
            $AD{'computer'}{$sam}{'comment'}=$entry->get_value('comment');
            $AD{'computer'}{$sam}{'sophomorixComputerIP'}=$entry->get_value('sophomorixComputerIP');
            $AD{'computer'}{$sam}{'sophomorixComputerMAC'}=$entry->get_value('sophomorixComputerMAC');
            $AD{'computer'}{$sam}{'sophomorixComputerRoom'}=$entry->get_value('sophomorixComputerRoom');
            $AD{'computer'}{$sam}{'sophomorixIntrinsic1'}=$entry->get_value('sophomorixIntrinsic1');
            @{ $AD{'computer'}{$sam}{'sophomorixComputerDefaults'} }=$entry->get_value('sophomorixComputerDefaults');

            # lists
            push @{ $AD{'LISTS'}{'COMPUTER_BY_sophomorixSchoolname'}{$school}{$role} }, $sam; 
            #push @{ $AD{'LISTS'}{'DEVICE_BY_sophomorixSchoolname'}{$school}{$role} }, $sam; 

            # lookup
            $AD{'LOOKUP'}{'sAMAccountName_BY_sophomorixDnsNodename'}{$entry->get_value('sophomorixDnsNodename')}=$sam;

            #my $type=$AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$entry->get_value('sophomorixAdminClass')};
            #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}
            #           {'users_BY_group'}{$entry->get_value('sophomorixAdminClass')} }, $sam;  
            #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$entry->get_value('sophomorixSchoolname')}{'users_BY_sophomorixType'}{$type} }, $sam;  
        }
    }  # BLOCK computer end
    ############################################################
    # sophomorix rooms/devicegroupes from ldap
    { # BLOCK group start
        my $filter="(& (objectClass=group) (| ".
                   "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ROOM'}.") ".
                   "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}.") ";
        # add defined host group types from sophomorix.ini
        foreach my $type (keys %{ $ref_sophomorix_config->{'LOOKUP'}{'HOST_GROUP_TYPE'} }) {
            $filter=$filter."(sophomorixType=".$type.") ";
        }
        $filter=$filter.") )";

	#print "Filter for device groups: $filter\n";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixStatus',
                                 'sophomorixSchoolname',
                                 'sophomorixType',
                                 'description',
                                 'member',
                                 'sophomorixRoomIPs',
                                 'sophomorixRoomMACs',
                                 'sophomorixRoomComputers',
                                 'sophomorixRoomDefaults',
                                ]);
        my $max_group = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_group sophomorix rooms/devicegroupes found in AD");
        $AD{'RESULT'}{'group'}{'TOTAL'}{'COUNT'}=$max_group;
        $AD{'RESULT'}{'group'}{'room'}{'COUNT'}=0;
        $AD{'RESULT'}{'group'}{$ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}}{'COUNT'}=0;
        for( my $index = 0 ; $index < $max_group ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn = $entry->dn();
            my $sam=$entry->get_value('sAMAccountName');
            my $type=$entry->get_value('sophomorixType');
            my $stat=$entry->get_value('sophomorixStatus');
            my $schoolname=$entry->get_value('sophomorixSchoolname');
            my $description=$entry->get_value('description');

            $AD{$type}{$sam}{'room'}=$sam;
            $AD{$type}{$sam}{'sophomorixStatus'}=$stat;
            $AD{$type}{$sam}{'sophomorixType'}=$type;
            $AD{$type}{$sam}{'description'}=$description;
            # increase role counter 
            $AD{'RESULT'}{'group'}{$type}{'COUNT'}++;

            $AD{$type}{$sam}{'sophomorixSchoolname'}=$schoolname;
            $AD{$type}{$sam}{'DN'}=$dn;

            @{ $AD{$type}{$sam}{'sophomorixRoomIPs'} }=$entry->get_value('sophomorixRoomIPs');
            @{ $AD{$type}{$sam}{'sophomorixRoomMACs'} }=$entry->get_value('sophomorixRoomMACs');
            @{ $AD{$type}{$sam}{'sophomorixRoomComputers'} }=$entry->get_value('sophomorixRoomComputers');
            @{ $AD{$type}{$sam}{'sophomorixRoomDefaults'} }=$entry->get_value('sophomorixRoomDefaults');

            # host groups
            if (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}{$type}){
                $AD{'host_group'}{$sam}=$type;
            }

            # devicegroup memberships
            if ($type eq $ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}){
                @{ $AD{$type}{$sam}{'member'} }=$entry->get_value('member');
                foreach my $dn (@{ $AD{$type}{$sam}{'member'} }){
                    my @parts=split(",",$dn);
                    my ($unused,$memsam)=split("=",$parts[0]);
		    $memsam=~tr/A-Z/a-z/;
                    $AD{$type}{$sam}{'member_sAMAccountName'}{$memsam}="seen";
                }
            }

            # lists
            if ($type eq "room"){
                push @{ $AD{'LISTS'}{'ROOM_BY_sophomorixSchoolname'}{$schoolname}{'rooms'} }, $sam;
            } elsif ($type eq $ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}){
                push @{ $AD{'LIST_DEVICEGROUPS'} }, $sam;
            }
            #push @{ $AD{'LISTS'}{'BY_SCHOOL'}{$schoolname}{'groups_BY_sophomorixType'}{$type} }, $sam; 
            #$AD{'LOOKUP'}{'sophomorixType_BY_sophomorixAdminClass'}{$sam}=$type;
        }
    } # BLOCK group end

    ############################################################
    # sophomorix dnzones and default Zone from ldap from ldap
    { # BLOCK dnsZone start
        my $filter="(objectClass=dnsZone)";
        my $base="DC=DomainDnsZones,".$root_dse;
        $mesg = $ldap->search( # perform a search
                       base   => $base,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['name',
                                 'dc',
                                 'cn',
                                 'dnsZone',
                                 'sophomorixRole',
                                ]);
        my $max_zone = $mesg->count; 
        $AD{'RESULT'}{'dnsZone'}{'TOTAL'}{'COUNT'}=$max_zone;
        $AD{'RESULT'}{'dnsZone'}{'sophomorix'}{'COUNT'}=0;
        $AD{'RESULT'}{'dnsZone'}{'other'}{'COUNT'}=0;

        &Sophomorix::SophomorixBase::print_title("$max_zone dnsZones found");
        for( my $index = 0 ; $index < $max_zone ; $index++) {
            my $entry = $mesg->entry($index);
            my $zone=$entry->get_value('dc');
            my $name=$entry->get_value('name');
            my $role="";
            if (defined $entry->get_value('sophomorixRole') ){
                $role=$entry->get_value('sophomorixRole');
            }
            if($Conf::log_level>=2){
                print "   * ",$entry->get_value('dc'),"\n";
            }
            if ($role eq $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSZONE_ROLE'}){
                # shophomorix dnsZone or default dnsZone
                $AD{'RESULT'}{'dnsZone'}{'sophomorix'}{'COUNT'}++;
                $AD{'dnsZone'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSZONE_ROLE'}}{$zone}{'name'}=$name;
                $AD{'dnsZone'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSZONE_ROLE'}}{$zone}{'sophomorixRole'}=$role;
                $AD{'dnsZone'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSZONE_ROLE'}}{$zone}{'cn'}=$entry->get_value('cn');
            } else {
                # other dnsZone
                $AD{'RESULT'}{'dnsZone'}{'other'}{'COUNT'}++;
                $AD{'dnsZone'}{'otherdnsZone'}{$zone}{'name'}=$name;
            }
        }
    } # BLOCK dnsZone end

    ############################################################
    # sophomorix dnsNodes from ldap
    { # BLOCK dnsNode start
        # alle NODES suchen
        #my $res   = Net::DNS::Resolver->new;
        my $filter="(& (objectClass=dnsNode) (sophomorixRole=*) )";
        my $base="DC=DomainDnsZones,".$root_dse;
        my $mesg = $ldap->search( # perform a search
                          base   => $base,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['dc',
                                    'dnsRecord',
                                    'sophomorixAdminFile',
                                    'sophomorixComment',
                                    'sophomorixDnsNodename',
                                    'sophomorixDnsNodetype',
                                    'sophomorixRole',
                                    'sophomorixSchoolname',
                                    'sophomorixComputerIP',
                                   ]);
        my $max_node = $mesg->count; 
        $AD{'RESULT'}{'dnsNode'}{'TOTAL'}{'COUNT'}=$max_node;
        $AD{'RESULT'}{'dnsNode'}{'sophomorix'}{'COUNT'}=0;
        $AD{'RESULT'}{'dnsNode'}{'other'}{'COUNT'}=0;

        &Sophomorix::SophomorixBase::print_title("$max_node sophomorix dnsNodes found");
        for( my $index = 0 ; $index < $max_node ; $index++) {
            my $entry = $mesg->entry($index);
            my $dn=$entry->dn();
            my $dc=$entry->get_value('dc');
            
            # sophomorixDnsNodetype (lookup/reverse))
            my $dnsnode_type="";
            if (defined $entry->get_value('sophomorixDnsNodetype')){
                $dnsnode_type=$entry->get_value('sophomorixDnsNodetype');
            }

            if ($dnsnode_type eq $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_TYPE_LOOKUP'}){
                # sophomorixdnsNodes
                my $role=$entry->get_value('sophomorixRole');
                my $school=$entry->get_value('sophomorixSchoolname');
                $AD{'RESULT'}{'dnsNode'}{'sophomorix'}{'COUNT'}++;
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'dnsNode'}=$dc;
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'dnsZone'}=$root_dns;
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'sophomorixRole'}=$role;
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'sophomorixSchoolname'}=$school;
                #$AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'IPv4'}=$ip;
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'sophomorixAdminFile'}=
                    $entry->get_value('sophomorixAdminFile');
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'sophomorixComment'}=
                    $entry->get_value('sophomorixComment');
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'sophomorixDnsNodename'}=
                    $entry->get_value('sophomorixDnsNodename');
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'sophomorixDnsNodetype'}=
                    $entry->get_value('sophomorixDnsNodetype');
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'sophomorixComputerIP'}=
                    $entry->get_value('sophomorixComputerIP');
                # get ipv4
                # fast: by attribute
                $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'IPv4'}=
                    $entry->get_value('sophomorixComputerIP');;
                # slow: query dns
                # my ($ip,$message)=&Sophomorix::SophomorixBase::dns_query_ip($res,$dc);
                #if ($message ne "NXDOMAIN" and $message ne "NOERROR"){
                #  $AD{'dnsNode'}{$ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_KEY'}}{$dc}{'IPv4'}=$ip;  
	        #}

                 push @{ $AD{'LISTS'}{'DEVICE_BY_sophomorixSchoolname'}{$school}{$role} }, $dc; 
                 push @{ $AD{'LISTS'}{'DEVICE_BY_sophomorixSchoolname'}{$school}{'dnsNodes'} }, $dc; 
            } elsif ($dnsnode_type eq $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_TYPE_REVERSE'}){
                # do not know if they are treaded separately
            } else {
                # other dnsNodes
                $AD{'RESULT'}{'dnsNode'}{'other'}{'COUNT'}++;
            }
        }
    } # BLOCK dnsNode end
    &Sophomorix::SophomorixBase::print_title("Sorting lists ...");

    # sort LISTS
    foreach my $key (keys %{ $AD{'LISTS'} }) {
        foreach my $school (keys %{ $AD{'LISTS'}{$key} }) {
            foreach my $list (keys %{ $AD{'LISTS'}{$key}{$school} }) {
		@{ $AD{'LISTS'}{$key}{$school}{$list} } = sort @{ $AD{'LISTS'}{$key}{$school}{$list} };
            }
        }
    }

    # sort LIST_DEVICEGROUPS
    if($#{ $AD{'LIST_DEVICEGROUPS'}        }>0){
        @{ $AD{'LIST_DEVICEGROUPS'} } = sort @{ $AD{'LIST_DEVICEGROUPS'} };
    }
    # sort some lists under 'room'
    foreach my $room (keys %{$AD{'room'}}) {
        if($#{ $AD{'room'}{$room}{'sophomorixRoomComputers'} }>0){
           @{ $AD{'room'}{$room}{'sophomorixRoomComputers'} } = 
               sort @{ $AD{'room'}{$room}{'sophomorixRoomComputers'} };
        }
        if($#{ $AD{'room'}{$room}{'sophomorixRoomMACs'} }>0){
           @{ $AD{'room'}{$room}{'sophomorixRoomMACs'} } = 
               sort @{ $AD{'room'}{$room}{'sophomorixRoomMACs'} };
        }
        if($#{ $AD{'room'}{$room}{'sophomorixRoomIPs'} }>0){
           @{ $AD{'room'}{$room}{'sophomorixRoomIPs'} } = 
               sort @{ $AD{'room'}{$room}{'sophomorixRoomIPs'} };
        }
    }
    &Sophomorix::SophomorixBase::print_title("Query AD for device (end)");
    return(\%AD);
}


 
sub AD_check_ui {
    my %ui=();
    my $ref_ui=\%ui;
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $ref_AD_check = $arg_ref->{ref_AD_check};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $force = $arg_ref->{force};

    foreach my $sam (keys %{ $ref_AD_check->{'sAMAccountName'} }){
        #print "SAM: $sam\n";
        my @old = sort @{ $ref_AD_check->{'sAMAccountName'}{$sam}{'sophomorixWebuiPermissionsCalculated'} };
        my $old_webui_string=join(",",@old);
        my ($new_webui_string,$role,$school)=&AD_create_new_webui_string($sam,$ref_sophomorix_config,$ref_AD_check);
        #print "  OLD: $old_webui_string\n";
        #print "  NEW: $new_webui_string\n";
        if ($new_webui_string ne $old_webui_string or $force==1){
            # update
            #print "update $sam\n";
            $ui{'UI'}{'USERS'}{$sam}{'displayName'}=$ref_AD_check->{'sAMAccountName'}{$sam}{'displayName'};
            $ui{'UI'}{'USERS'}{$sam}{'dn'}=$ref_AD_check->{'sAMAccountName'}{$sam}{'dn'};
            $ui{'UI'}{'USERS'}{$sam}{'sophomorixAdminClass'}=$ref_AD_check->{'sAMAccountName'}{$sam}{'sophomorixAdminClass'};
            @{ $ui{'UI'}{'USERS'}{$sam}{'sophomorixWebuiPermissionsCalculated'} }=
                @{ $ref_AD_check->{'sAMAccountName'}{$sam}{'sophomorixWebuiPermissionsCalculated'} };
            # create CALC*LISTs from CALC hash
            @{ $ui{'UI'}{'USERS'}{$sam}{'CALCLIST'} }=split(/,/,$new_webui_string);
            push @{ $ui{'LISTS_UPDATE'}{'USER_by_sophomorixSchoolname_by_sophomorixRole'}{$school}{$role} },$sam;
            push @{ $ui{'LISTS_UPDATE'}{'USER_by_sophomorixSchoolname'}{$school} },$sam;
            push @{ $ui{'LISTS_UPDATE'}{'USERS_by_sophomorixRole'}{$role} },$sam;
            push @{ $ui{'LISTS_UPDATE'}{'USERS'} },$sam;
        } else {
            # do not update
        }
    }
    # set total counter
    $ui{'LOOKUP'}{'COUNTER'}{'TOTAL'}=$#{ $ui{'LISTS_UPDATE'}{'USERS'} }+1;
    &Sophomorix::SophomorixBase::print_title("Query AD (end)");
    return(\%ui);
}



sub AD_create_new_mail {
    my ($sam,
	$ref_arguments,
	$ref_sophomorix_config,
	$ref_sophomorix_result,
	$json,
	$role_file,
	$school_file,
        $firstname_old,
	$firstname_new,
	$lastname_old,
	$lastname_new,
	$filename_new,
	$class_new) = @_;

    my $firstname;
    if ($firstname_new ne "---"){
        $firstname=$firstname_new;
    } else {
        $firstname=$firstname_old;
    }
    $firstname=~tr/A-Z/a-z/;
    $firstname=~s/\s+/_/g;
    
    my $lastname;
    if ($lastname_new ne "---"){
        $lastname=$lastname_new;
    } else {
        $lastname=$lastname_old;
    }
    $lastname=~tr/A-Z/a-z/;
    $lastname=~s/\s+/_/g;
    
    if (not defined $role_file){
        # existing user
        $role=$ref_AD_check->{'sAMAccountName'}{$sam}{'sophomorixRole'};
        $school=$ref_AD_check->{'sAMAccountName'}{$sam}{'sophomorixSchoolname'};
    } else {
        # called from sophomorix-check to look for updates:
        # use NEW role and NEW school
        $role=$role_file;
        $school=$school_file;
    }
    my $mail;

    # MAIL_LOCAL_PART part
    my $mail_local_part;
    $mail_local_part=$sam; # default
    if ($ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_SCHEME'} eq "firstname"){
	$mail_local_part=$firstname;
    } elsif ($ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_SCHEME'} eq "lastname"){
	$mail_local_part=$lastname;
    } elsif ($ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_SCHEME'} eq "firstname.lastname"){
	$mail_local_part=$firstname.".".$lastname;
    } elsif ($ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_SCHEME'} eq "lastname.firstname"){
	$mail_local_part=$lastname.".".$firstname;
    } elsif ($ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_SCHEME'} ne ""){
        my $error_message="$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_SCHEME'} not allowed as 'MAIL_LOCAL_PART_SCHEME' in school '".$school_file.
                          "' | Allowed: firstname|lastname|firstname.lastname|lastname.firstname";
        &Sophomorix::SophomorixBase::log_script_exit($error_message,1,1,0,
                         $ref_arguments,$ref_sophomorix_result,$ref_sophomorix_config,$json);

    }

    # override MAIL_LOCAL_PART by MAIL_LOCAL_PART_MAP, if there
    if (exists $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_MAP_LOOKUP'}{$sam}{'MAIL_LOCAL_PART'}){
        $mail_local_part=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_MAP_LOOKUP'}{$sam}{'MAIL_LOCAL_PART'};
        $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAIL_LOCAL_PART_MAP_LOOKUP'}{$sam}{'USED'}="TRUE";
    }

    # MAILDOMAIN part
    if ($ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAILDOMAIN'} eq "NONE"){
        $mail="NONE";
    } else {
	# set maildomain by role
        my $maildomain=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'MAILDOMAIN'};
	# override maildomain by MAILDOMAIN_BY_GROUP option
	if (exists $ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename_new}{'MAILDOMAIN_BY_GROUP_LOOKUP'}{$class_new}){
	    $maildomain=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$filename_new}{'MAILDOMAIN_BY_GROUP_LOOKUP'}{$class_new};
	}
        $mail=$mail_local_part."@".$maildomain;
    }

    return $mail;
}
 


sub AD_create_new_webui_string {
    my ($sam,$ref_sophomorix_config,$ref_AD_check,$role_file,$school_file) = @_;
    my $role;
    my $school;
    my %new_webui=();
    my @new_webui=();
    if (not defined $role_file){
        # existing user
        $role=$ref_AD_check->{'sAMAccountName'}{$sam}{'sophomorixRole'};
        $school=$ref_AD_check->{'sAMAccountName'}{$sam}{'sophomorixSchoolname'};
    } else {
        # called from sophomorix-check to look for updates:
        # use NEW role and NEW school
        $role=$role_file;
        $school=$school_file;
    }
    #print "Working on $sam in school $school with role $role\n";

    # 1) set the webui according to school and role
    foreach my $mod (keys %{ $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'} }){
        #print "     $mod ---> $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'}{$mod}\n";
        $new_webui{'UI'}{$mod}=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'UI'}{'WEBUI_PERMISSIONS_LOOKUP'}{$mod};
    }

    # 2) set the webui with individual settings from  AD (sophomorixWebuiPermissions)
    foreach my $perm ( @{ $ref_AD_check->{'sAMAccountName'}{$sam}{'sophomorixWebuiPermissions'}  } ){ 
        #print "    $sam (individual): $perm\n";
        my ($mod_path,$setting)=&Sophomorix::SophomorixBase::test_webui_permission($perm,
            $ref_sophomorix_config,
            "sophomorixWebuiPermissions of $sam in $school",
            "check",
            $school,
            $role);
        #print "        $mod_path --> $setting\n";
        $new_webui{'UI'}{$mod_path}=$setting;
    }
    
    # create new webui string
    foreach my $mod_path ( keys %{ $new_webui{'UI'} } ){
        push @new_webui,$mod_path." ".$new_webui{'UI'}{$mod_path};
    }
    @new_webui = sort @new_webui;
    my $new_webui_string=join(",",@new_webui);
    #print "NEW: $new_webui_string\n";
    return ($new_webui_string,$role,$school);
}



sub AD_get_quota {
    my %quota=();
    $quota{'QUOTA'}{'UPDATE_COUNTER'}{'SHARES'}=0;
    $quota{'QUOTA'}{'UPDATE_COUNTER'}{'USERS'}=0;
    $quota{'QUOTA'}{'UPDATE_COUNTER'}{'USERMAILQUOTA'}=0;
    # LISTS of %quota
    # LISTS->USER_by_SHARE-><share>->@users  # list which users have quota on the share
    # LISTS->USER_by_SCHOOL-><school>->@users  # list which users have quota on this school
    # LISTS->CLASS_by_SHARE-><share>->@users  # list which classes have quota on the share
    # LISTS->CLASS_by_SCHOOL-><school>->@users  # list which classes have quota on this school
    # LISTS->GROUPS_by_SHARE-><share>->@users  # list which groups have quota on the share
    # LISTS->GROUPS_by_SCHOOL-><school>->@users  # list which groups have quota on this school
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $smbcquotas = $arg_ref->{smbcquotas};
    my $user_opt = $arg_ref->{user};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    # create userlist for smbcquotas query
    my %smbcquotas_users=();
    if (defined $user_opt and $user_opt ne ""){
        my @smbcquotas_users=split(/,/,$user_opt);
        foreach my $user (@smbcquotas_users){
            $smbcquotas_users{$user}="query";
        }
    }

    # USER quota (sophomorix user)
    my $filter2="(&(objectClass=user) (| (sophomorixRole=student) (sophomorixRole=teacher) ) )";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter2,
                   attrs => ['sAMAccountName',
                             'sophomorixSchoolname',
                             'sophomorixRole',
                             'sophomorixAdminFile',
                             'mail',
                             'sn',
                             'givenName',
                             'displayName',
                             'sophomorixAdminClass',
                             'sophomorixSurnameASCII',
                             'sophomorixFirstnameASCII',
                             'memberOf',
                             'sophomorixQuota',
                             'sophomorixMailQuota',
                             'sophomorixMailQuotaCalculated',
                             'sophomorixCloudQuotaCalculated',
                            ]);
    my $max_user = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title(
        "$max_user user found in AD");
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $role=$entry->get_value('sophomorixRole');
        my $file=$entry->get_value('sophomorixAdminFile');
        my $school=$entry->get_value('sophomorixSchoolname');
	my $mailquota = $entry->get_value('sophomorixMailQuota');
	my @quota = $entry->get_value('sophomorixQuota');
	my @memberof = $entry->get_value('memberOf');
	push @{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$school} }, $sam; 
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$dn}=$sam;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'DN_by_sAMAccountName'}{$sam}=$dn;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$dn}=$sam;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'DN_by_sAMAccountName'}{$sam}=$dn;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_sophomorixSchoolname'}{$school}{$sam}=$dn;
        $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sophomorixSchoolname_by_sAMAccountName'}{$sam}{'sophomorixSchoolname'}=$school;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixRole'}=$role;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixAdminFile'}=$file;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixSchoolname'}=$school;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixCloudQuotaCalculated'}=$entry->get_value('sophomorixCloudQuotaCalculated');

        # get SHAREDEFAULT for this role
        $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$school}{'SHAREDEFAULT'}=
            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'QUOTA_DEFAULT_SCHOOL'};
        $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}}{'SHAREDEFAULT'}=
            $ref_sophomorix_config->{'ROLES'}{$school}{$role}{'QUOTA_DEFAULT_GLOBAL'};
        # get MAILQUOTA SCHOOLDEFAULT for this role
        $quota{'QUOTA'}{'USERS'}{$sam}{'MAILQUOTA'}{'SCHOOLDEFAULT'}=
            $ref_sophomorix_config->{'ROLES' }{$school}{$role}{'MAILQUOTA_DEFAULT'};

        # save mail adress/alias
        $quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'MAILLISTMEMBER'}="FALSE"; # may be set to TRUE later
        $quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'mail'}=$entry->get_value('mail');
        $quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'displayName'}=$entry->get_value('displayName');
        ($quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'ALIASNAME'},
         $quota{'QUOTA'}{'USERS'}{$sam}{'MAIL'}{'ALIASNAME_LONG'})=
            &Sophomorix::SophomorixBase::alias_from_name($entry->get_value('sophomorixSurnameASCII'),
                                                         $entry->get_value('sophomorixFirstnameASCII'),
                                                         $root_dns,
                                                         $ref_sophomorix_config); 
        # save USER mailquota
        if (defined $entry->get_value('sophomorixMailQuotaCalculated')){
            $quota{'QUOTA'}{'USERS'}{$sam}{'MAILQUOTA'}{'OLDCALC'}=$entry->get_value('sophomorixMailQuotaCalculated');
	} else {
            $quota{'QUOTA'}{'USERS'}{$sam}{'MAILQUOTA'}{'OLDCALC'}="";
        }
        my ($mailquota_value,$mailquota_comment)=split(/:/,$mailquota);
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixMailQuota'}{'VALUE'}=$mailquota_value;
        $quota{'QUOTA'}{'USERS'}{$sam}{'sophomorixMailQuota'}{'COMMENT'}=$mailquota_comment;
        if ($mailquota_value ne "---" or $mailquota_comment ne "---"){
  	    push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixMailQuota'} }, $mailquota;
            $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixRole'}=$role;
            $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sn'}=$entry->get_value('sn');;
            $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'givenName'}=$entry->get_value('givenName');
            $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'displayName'}=$entry->get_value('displayName');
            $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
	    $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'MAILQUOTA'}{'VALUE'}=$mailquota_value;
	    $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'MAILQUOTA'}{'COMMENT'}=$mailquota_comment;
        }                

        # save USER quota
        foreach my $quota (@quota){
	    my ($share,$value,$oldcalc,$quotastatus,$comment)=split(/:/,$quota);
	    # remember quota
  	    $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$share}{'sophomorixQuota'}=$value;
  	    $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$share}{'OLDCALC'}=$oldcalc;
  	    $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$share}{'QUOTASTATUS'}=$quotastatus;
  	    $quota{'QUOTA'}{'USERS'}{$sam}{'SHARES'}{$share}{'COMMENT'}=$comment;
	    # remember share for later listing
	    push @{ $quota{'QUOTA'}{'USERS'}{$sam}{'SHARELIST'} }, $share;
            # remember on which share have which users quota settings
	    push @{ $quota{'LISTS'}{'USER_by_SHARE'}{$share}}, $sam;
            # remember nondefault quota
            if ($value ne "---" or $comment ne "---"){
    		push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixQuota'} }, $quota;
                $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixRole'}=$role;
                $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sn'}=$entry->get_value('sn');;
                $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'givenName'}=$entry->get_value('givenName');
                $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'displayName'}=$entry->get_value('displayName');
                $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
		$quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'QUOTA'}{$share}{'VALUE'}=$value;
		$quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'QUOTA'}{$share}{'SHARE'}=$share;
		$quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'QUOTA'}{$share}{'OLDCALC'}=$oldcalc;
		$quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'QUOTA'}{$share}{'QUOTASTATUS'}=$quotastatus;
		$quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'QUOTA'}{$share}{'COMMENT'}=$comment;
            }                
        }
        if (exists $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam} and 
            exists $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixAddQuota'} ){
            # sort list if it's there (avoid creation of sophomorixAddQuota if first if fails)
            @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixAddQuota'} }= sort
	        @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'USER'}{$sam}{'sophomorixAddQuota'} };
        }
    } # end USER quota


    # CLASS quota 
    # look for groups with primary membership
    # use the name CLASS in the hash for ADMINCLASS|TEACHERCLASS
    my $filter="(&".
	" (objectClass=group)".
	       "(| ".
               " (sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ADMINCLASS'}.")".
               " (sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'TEACHERCLASS'}.")".
               "))";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   attrs => ['sAMAccountName',
                             'sophomorixSchoolname',
                             'sophomorixType',
                             'member',
                             'memberOf',
                             'mail',
                             'description',
                             'sophomorixQuota',
                             'sophomorixMailQuota',
                             'sophomorixMailList',
                             'sophomorixMailAlias',
                            ]);
    my $max_adminclass = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title(
        "$max_adminclass sophomorix adminclasses found in AD");
    for( my $index = 0 ; $index < $max_adminclass ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $type=$entry->get_value('sophomorixType');
        my $school=$entry->get_value('sophomorixSchoolname');
	my $mailquota = $entry->get_value('sophomorixMailQuota');
	my $maillist = $entry->get_value('sophomorixMailList');
	my $mailalias = $entry->get_value('sophomorixMailAlias');
	my @quota = $entry->get_value('sophomorixQuota');
	my @member = $entry->get_value('member');
	my @memberof = $entry->get_value('memberOf');
        $quota{'QUOTA'}{'LOOKUP'}{'CLASS'}{'sAMAccountName_by_DN'}{$dn}=$sam;
        $quota{'QUOTA'}{'LOOKUP'}{'CLASS'}{'DN_by_sAMAccountName'}{$sam}=$dn;

        # save stuff about classes
  	$quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixSchoolname'}=$school;
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixType'}=$type;
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'mail'}=$entry->get_value('mail');
	push @{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$school} }, $sam; 

        # save maillist stuff about classes
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailList'}=$maillist;
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailAlias'}=$mailalias;
        if ($maillist eq "TRUE"){
            $quota{'MAILLIST'}{$sam}{'mail'}=$entry->get_value('mail');
            push @{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} },$sam;
            $quota{'QUOTA'}{'LOOKUP'}{'MAILLISTS_by_SCHOOL'}{$school}{$sam}{'EXISTS'}="TRUE";
        }

        # mailquota
        my ($mailquota_value,$mailquota_comment)=split(/:/,$mailquota);
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailQuota'}{'VALUE'}=$mailquota_value;
        $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailQuota'}{'COMMENT'}=$mailquota_comment;
        if ($mailquota_value ne "---" or $mailquota_comment ne "---"){
    	    push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixMailQuota'} }, $mailquota;
            $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'description'}=$entry->get_value('description');
	    $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'MAILQUOTA'}{'VALUE'}=$mailquota_value;
	    $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'MAILQUOTA'}{'COMMENT'}=$mailquota_comment;
        }                

        # quota
	foreach my $quota (@quota){
	    my ($share,$value,$comment)=split(/:/,$quota);
            $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixQuota'}{$share}{'VALUE'}=$value;
            $quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixQuota'}{$share}{'COMMENT'}=$comment;
            # remember nondefault quota
            if ($value ne "---" or $comment ne "---"){
    		push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixQuota'} }, $quota;
                $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'description'}=$entry->get_value('description');
		$quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'QUOTA'}{$share}{'VALUE'}=$value;
		$quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'QUOTA'}{$share}{'SHARE'}=$share;
		$quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'QUOTA'}{$share}{'COMMENT'}=$comment;
            }                
	    push @{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} }, $sam; 
        }
        if (exists $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam} and
            exists $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixQuota'}){
            # sort list if its there (avoid creation of sophomorixQuota if first if fails)
            @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixQuota'} }= sort
	        @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'CLASS'}{$sam}{'sophomorixQuota'} };
        }

        foreach my $member (@member){
	    my $sam_user;
	    if ( not exists $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$member}){
		# if member ist not a user, skip
                next;
	    } else {
		$sam_user=$quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$member};
                $quota{'QUOTA'}{'LOOKUP'}{'MEMBERS_by_CLASS'}{$sam}{$sam_user}=$member;
	    }
            # save data about class at user
            $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sAMAccountName'}=$sam;
            $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixType'}=$type;

            # save member in maillist if requested
            if ($quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailList'} eq "TRUE"){
                push @{ $quota{'MAILLIST'}{$sam}{LIST} },$quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'mail'};
                # set maillist membership at user
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'MAILLISTMEMBER'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'MAILLIST_MEMBERSHIPS'}{$sam}=$entry->get_value('mail');
            }

            # save alias=TRUE at user if class requests alias
            if ($quota{'QUOTA'}{'CLASSES'}{$sam}{'sophomorixMailAlias'} eq "TRUE"){
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'ALIAS'}="TRUE";
            } else {
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'ALIAS'}="FALSE";
            }

            # save mailquota for class at user
            my ($mailquota_value,$mailquota_comment)=split(/:/,$mailquota);
            $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'}=$mailquota_value;
            $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixMailQuota'}{'COMMENT'}=$mailquota_comment;

	    # save quota for class at user
	    foreach my $quota (@quota){
	        my ($share,$value,$comment)=split(/:/,$quota);
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixQuota'}{$share}{'VALUE'}=$value;
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'CLASS'}{'sophomorixQuota'}{$share}{'COMMENT'}=$value;
		# remember share for later listing
		push @{ $quota{'QUOTA'}{'USERS'}{$sam_user}{'SHARELIST'} }, $share;
                # remember on which share have which users quota settings
		push @{ $quota{'LISTS'}{'USER_by_SHARE'}{$share}}, $sam_user;  
	    }
	}
    } # end CLASS

    # GROUP quota 
    my $filter3="(&".
	" (objectClass=group) (| ".
               " (sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'PROJECT'}.")".
               " (sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'GROUP'}.")".
               " ) )";
    $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter3,
                   attrs => ['sAMAccountName',
                             'sophomorixSchoolname',
                             'sophomorixType',
                             'member',
                             'memberOf',
                             'mail',
                             'description',
                             'sophomorixAddQuota',
                             'sophomorixAddMailQuota',
                             'sophomorixMailList',
                             'sophomorixMailAlias',
                            ]);
    my $max_group = $mesg->count; 
    &Sophomorix::SophomorixBase::print_title(
        "$max_group sophomorix projects/sophomorix-groups found in AD");
    # walk through all GROUPS
    # create GROUPS LOOKUP table
    for( my $index = 0 ; $index < $max_group ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $school=$entry->get_value('sophomorixSchoolname');
	my @member = $entry->get_value('member');
        $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'sAMAccountName_by_DN'}{$dn}=$sam;
        $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'DN_by_sAMAccountName'}{$sam}=$dn;
	push @{ $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'MEMBER'}{$sam} }, @member;
    }

    # walk through all GROUPS
    # this time, update user quota
    for( my $index = 0 ; $index < $max_group ; $index++) {
        my $entry = $mesg->entry($index);
	my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $type=$entry->get_value('sophomorixType');
        my $school=$entry->get_value('sophomorixSchoolname');
	my $addmailquota = $entry->get_value('sophomorixAddMailQuota');
	my $maillist = $entry->get_value('sophomorixMailList');
	my $mailalias = $entry->get_value('sophomorixMailAlias');
	my @addquota = $entry->get_value('sophomorixAddQuota');
	my @member = $entry->get_value('member');
	my @memberof = $entry->get_value('memberOf');

	my $count=0;

        # save stuff about GROUPS
  	$quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixSchoolname'}=$school;
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixType'}=$type;
	push @{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$school} }, $sam; 

        # save maillist stuff about GROUPS
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixMailList'}=$maillist;
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixMailAlias'}=$mailalias;
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'mail'}=$entry->get_value('mail');
        if ($maillist eq "TRUE"){
            $quota{'MAILLIST'}{$sam}{'mail'}=$entry->get_value('mail');
            push @{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} },$sam;
            $quota{'QUOTA'}{'LOOKUP'}{'MAILLISTS_by_SCHOOL'}{$school}{$sam}{'EXISTS'}="TRUE";
        }

        # addmailquota
        my ($addmailquota_value,$addmailquota_comment)=split(/:/,$addmailquota);
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'VALUE'}=$addmailquota_value;
        $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'COMMENT'}=$addmailquota_comment;
        # remember nondefault mailquota
        if ($addmailquota_value ne "---" or $addmailquota_comment ne "---"){
  	    push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'} }, $addmailquota;
            $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'description'}=$entry->get_value('description');
	    $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'ADDMAILQUOTA'}{'VALUE'}=$addmailquota_value;
	    $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'ADDMAILQUOTA'}{'COMMENT'}=$addmailquota_comment;
        }                

        # addquota
	foreach my $addquota (@addquota){
	    my ($share,$value,$comment)=split(/:/,$addquota);
            $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'VALUE'}=$value;
            $quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'COMMENT'}=$comment;
            # remember nondefault quota
            if ($value ne "---" or $comment ne "---"){
  	        push @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddQuota'} }, $addquota;
                $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'description'}=$entry->get_value('description');
		$quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'ADDQUOTA'}{$share}{'VALUE'}=$value;
		$quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'ADDQUOTA'}{$share}{'COMMENT'}=$comment;
            }                
	    push @{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} }, $sam; 
        }
        if (exists $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam} and
            exists $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddQuota'}){
            # sort list if its there (avoid creation of sophomorixAddQuota if first if fails)
            @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddQuota'} }= sort
	        @{ $quota{'NONDEFAULT_QUOTA'}{$school}{'GROUPS'}{$sam}{'sophomorixAddQuota'} };
        }

	my $count_initial_member=$#member+1;
	# @addquota contains addquota info of the group
        foreach my $member (@member){
	    if (exists $seen{$member}){
                if($Conf::log_level>=3){
                    print "skipping (seen already): $member\n";
                }
                next;
	    } else {
                $seen{$member}="seen";
	    }
	    $count++;
	    
	    # walk through all members: (user,class,groups)
	    if (exists $quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$member}){
                ########################################
                # member is a user
                my $sam_user=$quota{'QUOTA'}{'LOOKUP'}{'USER'}{'sAMAccountName_by_DN'}{$member};
                #print "$sam_user is a member-USER of group $sam\n";
                # save data about GROUP at user
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixType'}=$type;
                if ($count>$count_initial_member){
                    # appended memberships		
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'REASON'}{'GROUP'}="TRUE";
                } else {
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'REASON'}{'USER'}="TRUE";
                }

                # save member in maillist if requested 
                if ($quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixMailList'} eq "TRUE"){
                    push @{ $quota{'MAILLIST'}{$sam}{LIST} },$quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'mail'};
                    # set maillist membership at user
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'MAILLISTMEMBER'}="TRUE";
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'MAILLIST_MEMBERSHIPS'}{$sam}=$entry->get_value('mail');
                }

                # save alias=TRUE at user if class requests alias
                if ($quota{'QUOTA'}{'GROUPS'}{$sam}{'sophomorixMailAlias'} eq "TRUE"){
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'ALIAS'}="TRUE";
                } else {
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'MAIL'}{'ALIAS'}="FALSE";
                }

                # save mailquota info at user
                my ($addmailquota_value,$addmailquota_comment)=split(/:/,$addmailquota);
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'VALUE'}=$addmailquota_value;
                $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'COMMENT'}=$addmailquota_comment;

	        # save quota info at user
	        foreach my $addquota (@addquota){
	            my ($share,$value,$comment)=split(/:/,$addquota);
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'VALUE'}=$value;
                    $quota{'QUOTA'}{'USERS'}{$sam_user}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'COMMENT'}=$comment;
		    # remember share for later listing
		    push @{ $quota{'QUOTA'}{'USERS'}{$sam_user}{'SHARELIST'} }, $share;
	        }
	    } elsif (exists $quota{'QUOTA'}{'LOOKUP'}{'CLASS'}{'sAMAccountName_by_DN'}{$member}){
                ########################################		
                # member is a class (adminclass,teacherclass)
                my $sam_class=$quota{'QUOTA'}{'LOOKUP'}{'CLASS'}{'sAMAccountName_by_DN'}{$member};
                #print "$sam_class is a member-CLASS of group $sam\n";
		# save quota info at each user of member-CLASS
		foreach my $user (keys %{ $quota{'QUOTA'}{'LOOKUP'}{'MEMBERS_by_CLASS'}{$sam_class} }) {
                    $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixType'}=$type;
                    if ($count>$count_initial_member){
                        # appended memberships		
                        $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'REASON'}{'GROUP'}="TRUE";
                    } else {
                        $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'REASON'}{'CLASS'}="TRUE";
                    }

                    # save mailquota info at user
                    my ($addmailquota_value,$addmailquota_comment)=split(/:/,$addmailquota);
                    $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'VALUE'}=$addmailquota_value;
                    $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}{'COMMENT'}=$addmailquota_comment;

	            # save quota info at user
	            foreach my $addquota (@addquota){
	                my ($share,$value,$comment)=split(/:/,$addquota);
                        $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'VALUE'}=$value;
                        $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$sam}{'sophomorixAddQuota'}{$share}{'COMMENT'}=$comment;
		        # remember share for later listing
		        push @{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }, $share;
                        # remember on which share have which users quota settings
	    	        push @{ $quota{'LISTS'}{'USER_by_SHARE'}{$share}}, $user;                
	            }
		}
	    } elsif (exists $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'sAMAccountName_by_DN'}{$member}){
		########################################
		# member is a GROUP
                my $sam_group=$quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'sAMAccountName_by_DN'}{$member};
                #print "$sam_group is a member-GROUP of GROUP $sam\n";
		# append the members of the group so that this foreach-loop will analyse it, too
	        push @member, @{ $quota{'QUOTA'}{'LOOKUP'}{'GROUPS'}{'MEMBER'}{$sam_group} };
	    }
	}
    } # end GROUP quota


    ############################################################
    # update share info in %quota
    my %updated_user=();
    foreach my $user (keys %{ $quota{'QUOTA'}{'USERS'} }) {
        # uniquefi and sort sharelist
	@{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }= 
            uniq(@{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} });
	@{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }= 
            sort @{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} };

        # create alphabetical group list (is unique alredy)
        foreach my $group (keys %{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'} }) {
            push @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'}}, $group; 
        }
        if (exists $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'}){
	    @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }= 
                sort @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} };
	}

        ############################################################
        # sum up AddMailQuota from GROUPS for each share
        my $mailcalc=1;
        my $mail_group_sum=0;
        my $mail_group_string="---";
         foreach my $group ( @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }) {
             if (exists $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'}){
                 if ($quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'} ne "---"){
                     my $add=$quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddMailQuota'}{'VALUE'};
                     $mail_group_sum=$mail_group_sum+$add;
                     if ($mail_group_string eq "---"){
                         $mail_group_string=$add;
                     } else {
                         $mail_group_string=$mail_group_string."+".$add;
                     }
                 }
             }
        }
        $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'GROUPSTRING'}=$mail_group_string;
        $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'GROUPSUM'}=$mail_group_sum;

        ############################################################
        # add everything up (mailquota)
        if ($quota{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'VALUE'} eq "---"){
            # start with nothing as quota
            my $base=$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NOQUOTA'};
            if ($quota{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'} ne "---"){
                $base=$quota{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixMailQuota'}{'VALUE'};
            } elsif (exists $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'SCHOOLDEFAULT'}){
                $base=$quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'SCHOOLDEFAULT'};
            }
            $mailcalc=$base+$mail_group_sum;
        } else {
            $mailcalc=$quota{'QUOTA'}{'USERS'}{$user}{'sophomorixMailQuota'}{'VALUE'}
        }
        # add addmailquota
        $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'CALC'}=$mailcalc;

        # check for updates
        if (not defined $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'OLDCALC'}){
            # nothing set
            $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'}="TRUE";
            $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'REASON'}{'Not set: sophomorixMailQuotaCalculated'}="TRUE";
        } else {
            # sophomorixMailQuotaCalculated defined
            if ($mailcalc ne $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'OLDCALC'}){
               # new caluladed value
                $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'REASON'}{'Not set: sophomorixMailQuotaCalculated'}="TRUE";
            }
        }
        # update user counter
        if (defined $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'} and
                $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'} eq "TRUE"){
            $quota{'QUOTA'}{'UPDATE_COUNTER'}{'USERMAILQUOTA'}++;
	}
        # FALSE if not set to TRUE
        if (not exists $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'}){
                $quota{'QUOTA'}{'USERS'}{$user}{'MAILQUOTA'}{'ACTION'}{'UPDATE'}="FALSE";
        }


        ############################################################
        # sum up AddQuota from GROUPS for each share
        my $calc=1;
        foreach my $share ( @{ $quota{'QUOTA'}{'USERS'}{$user}{'SHARELIST'} }) {
            my $group_sum=0;
            my $group_string="---";
            my $quota_user;
  	    if (defined $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'sophomorixQuota'}){
	         $quota_user=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'sophomorixQuota'};
	    } else {
                $quota_user="---";
	    }
            my $quota_class; # for this share
	    if (defined $quota{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixQuota'}{$share}{'VALUE'}){
	        $quota_class=$quota{'QUOTA'}{'USERS'}{$user}{'CLASS'}{'sophomorixQuota'}{$share}{'VALUE'};
	    } else {
                $quota_class="---";
            }
            # save the quota values of a GROUP for later use
            foreach my $group ( @{ $quota{'QUOTA'}{'USERS'}{$user}{'GROUPLIST'} }) {
                if (exists $quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'}){
                    if ($quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'} ne "---"){
                        my $add=$quota{'QUOTA'}{'USERS'}{$user}{'GROUPS'}{$group}{'sophomorixAddQuota'}{$share}{'VALUE'};
                        $group_sum=$group_sum+$add;
                        if ($group_string eq "---"){
                            $group_string=$add;
                        } else {
                            $group_string=$group_string."+".$add;
                        }
                    }
                }
            } # end group

            $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'GROUPSTRING'}=$group_string;
            $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'GROUPSUM'}=$group_sum;

            ############################################################
            # add everything up (quota)
            if ($quota_user eq "---"){
                # start with nothing as quota
                my $base=$ref_sophomorix_config->{'INI'}{'QUOTA'}{'NOQUOTA'};
                # check for class quota
                if ($quota_class ne "---"){
                    $base=$quota_class;
	        } elsif (exists $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'SHAREDEFAULT'}) {
                    $base=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'SHAREDEFAULT'};
                }
                # add addquota
                $calc=$base+$group_sum;
            } else {
                # override with quota from user attribute
                $calc=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'sophomorixQuota'};
            }
            # update CALC
            $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'CALC'}=$calc;
            # update sophomorixCloudQuotaCalculated
            if ($share eq $quota{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'}){
                my $role=$quota{'QUOTA'}{'USERS'}{$user}{'sophomorixRole'};
                my $school=$quota{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'};
                my $percentage=$ref_sophomorix_config->{'ROLES'}{$school}{$role}{'CLOUDQUOTA_PERCENTAGE'};
                my $cloudquota_calc=int($calc*$percentage/100);
                $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'PERCENTAGE'}=$percentage;
                $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC'}=$cloudquota_calc." MB";
                $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC_MB'}=$cloudquota_calc;
            }

            # add --- for undefined values
            if (not defined $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'OLDCALC'}){
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'OLDCALC'}="---";
            }
            if (not defined $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'}){
		$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'}="---";
            }

            # some shortnames for vars
            $oldcalc=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'OLDCALC'};
            $quotastatus=$quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'QUOTASTATUS'};

            # check for updates
            if ($quotastatus=~/[^0-9]/){
                # nonumbers
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'REASON'}{'NonNumbers in QUOTASTATUS'}="TRUE";
            }

            if ($calc ne $oldcalc){
                # new caluladed value
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'REASON'}{'CALC differs from OLDCALC'}="TRUE";
            }

            if ($oldcalc eq "---"){
                # no oldcalc set
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}="TRUE";
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'REASON'}{'OLDCALC is ---'}="TRUE";
            }

            # check update of sophomorixCloudQuotaCalculated
            if ($share eq $quota{'QUOTA'}{'USERS'}{$user}{'sophomorixSchoolname'}){
                if ($quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'CALC'} ne 
                    $quota{'QUOTA'}{'USERS'}{$user}{'sophomorixCloudQuotaCalculated'}){
                    $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'ACTION'}{'UPDATE'}="TRUE";
                } else {
                    $quota{'QUOTA'}{'USERS'}{$user}{'CLOUDQUOTA'}{'ACTION'}{'UPDATE'}="FALSE";
                }
            }

            # increase share counter
            if (defined $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'} and
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'} eq "TRUE"){
                if ( not exists $updated_user{$user} ){
                    # update user counter only once for a user
                    $updated_user{$user}="updated";
                    $quota{'QUOTA'}{'UPDATE_COUNTER'}{'USERS'}++;
                }
                $quota{'QUOTA'}{'UPDATE_COUNTER'}{'SHARES'}++;
            }

            # FALSE if not set to TRUE
            if (not exists $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}){
                $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'ACTION'}{'UPDATE'}="FALSE";
            }

            # use smbcquotas
            if ($smbcquotas==1){
		if ( exists $smbcquotas_users{$user} or
                     $user_opt eq ""
                   ){
                    # Add the smbcquotas result to the JSON object
                    ($quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'USED'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SOFTLIMIT'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'HARDLIMIT'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'USED_KiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SOFTLIMIT_KiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'HARDLIMIT_KiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'USED_MiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SOFTLIMIT_MiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'HARDLIMIT_MiB'},
                        $quota{'QUOTA'}{'USERS'}{$user}{'SHARES'}{$share}{'smbcquotas'}{'SMBCQUOTAS_RETURN_STRING'},
                    )=&AD_smbcquotas_queryuser(
                        $root_dns,
                        $smb_admin_pass,
                        $user,
                        $share,
			$ref_sophomorix_config);
	        }
            }
	} # end share
    } # end user
    
    # uniquify and sort sharelist at all users
    foreach my $share (keys %{ $quota{'LISTS'}{'USER_by_SHARE'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'USER_by_SHARE'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'USER_by_SHARE'}{$share} });
	@{ $quota{'LISTS'}{'USER_by_SHARE'}{$share} }= 
            sort @{ $quota{'LISTS'}{'USER_by_SHARE'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'USER_by_SCHOOL'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$share} });
	@{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$share} }= 
            sort @{ $quota{'LISTS'}{'USER_by_SCHOOL'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'CLASS_by_SCHOOL'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$share} });
	@{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$share} }= 
            sort @{ $quota{'LISTS'}{'CLASS_by_SCHOOL'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'CLASS_by_SHARE'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} });
	@{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} }= 
            sort @{ $quota{'LISTS'}{'CLASS_by_SHARE'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$share} });
	@{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$share} }= 
            sort @{ $quota{'LISTS'}{'GROUPS_by_SCHOOL'}{$share} };
    }
    foreach my $share (keys %{ $quota{'LISTS'}{'GROUPS_by_SHARE'} }) {
        # uniquefi and sort users
	@{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} }= 
            uniq(@{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} });
	@{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} }= 
            sort @{ $quota{'LISTS'}{'GROUPS_by_SHARE'}{$share} };
    }
    # sort maillist stuff
    foreach my $school (keys %{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'} }) {
        @{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} } = sort @{ $quota{'LISTS'}{'MAILLISTS_by_SCHOOL'}{$school} };
        foreach my $maillist (keys %{ $quota{'MAILLIST'} } ){
            if ($#{$quota{'MAILLIST'}{$maillist}{'LIST'} } >0){
	        @{ $quota{'MAILLIST'}{$maillist}{'LIST'} } = sort @{ $quota{'MAILLIST'}{$maillist}{'LIST'} };
            }
        }
    }

    return(\%quota);
}



sub AD_get_full_groupdata {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $grouplist = $arg_ref->{grouplist};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my @grouplist=split(/,/,$grouplist);
    my $filter;
    if ($#grouplist==0){
        $filter="(& (sophomorixType=*) (sAMAccountName=".$grouplist[0]."))"; 
    } else {
        $filter="(& (sophomorixType=*) (|";
        foreach my $group (@grouplist){
           $filter=$filter." (sAMAccountName=".$group.")";

        } 
        $filter=$filter." ))";
    }

    #print "$filter\n";
    my %groups=();
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                       );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $sam=$entry->get_value('sAMAccountName');
        push @{ $groups{'LISTS'}{'GROUPS'} }, $sam;

        $groups{'GROUPS'}{$sam}{'dn'}=$entry->dn();
        $groups{'GROUPS'}{$sam}{'sAMAccountName'}=$entry->get_value('sAMAccountName');
        $groups{'GROUPS'}{$sam}{'sAMAccountType'}=$entry->get_value('sAMAccountType');
        $groups{'GROUPS'}{$sam}{'cn'}=$entry->get_value('cn');
        $groups{'GROUPS'}{$sam}{'description'}=$entry->get_value('description');

        # sid
        #$groups{'GROUPS'}{$sam}{'objectSid_BINARY'}=$entry->get_value('objectSid');
        my $sid = Net::LDAP::SID->new($entry->get_value('objectSid'));
        $groups{'GROUPS'}{$sam}{'objectSid'}=$sid->as_string;

        $groups{'GROUPS'}{$sam}{'gidNumber'}=$entry->get_value('gidNumber');
        $groups{'GROUPS'}{$sam}{'displayName'}=$entry->get_value('displayName');
        $groups{'GROUPS'}{$sam}{'mail'}=$entry->get_value('mail');
        @{ $groups{'GROUPS'}{$sam}{'memberOf'} } = sort $entry->get_value('memberOf');
        @{ $groups{'GROUPS'}{$sam}{'member'} } = sort $entry->get_value('member');

        $groups{'GROUPS'}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
        $groups{'GROUPS'}{$sam}{'sophomorixType'}=$entry->get_value('sophomorixType');
        $groups{'GROUPS'}{$sam}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
        $groups{'GROUPS'}{$sam}{'sophomorixCreationDate'}=$entry->get_value('sophomorixCreationDate');
        $groups{'GROUPS'}{$sam}{'sophomorixJoinable'}=$entry->get_value('sophomorixJoinable');
        $groups{'GROUPS'}{$sam}{'sophomorixHidden'}=$entry->get_value('sophomorixHidden');
        $groups{'GROUPS'}{$sam}{'sophomorixMaxMembers'}=$entry->get_value('sophomorixMaxMembers');
        $groups{'GROUPS'}{$sam}{'sophomorixMailList'}=$entry->get_value('sophomorixMailList');
        $groups{'GROUPS'}{$sam}{'sophomorixMailAlias'}=$entry->get_value('sophomorixMailAlias');
        $groups{'GROUPS'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
        $groups{'GROUPS'}{$sam}{'sophomorixMailQuota'}=$entry->get_value('sophomorixMailQuota');
        $groups{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}=$entry->get_value('sophomorixAddMailQuota');

        @{ $groups{'GROUPS'}{$sam}{'sophomorixQuota'} } = sort $entry->get_value('sophomorixQuota');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixAddQuota'} } = sort $entry->get_value('sophomorixAddQuota');

        @{ $groups{'GROUPS'}{$sam}{'sophomorixAdmins'} } = sort $entry->get_value('sophomorixAdmins');
        $groups{'GROUPS'}{$sam}{'sophomorixAdmins_count'} = $#{ $groups{'GROUPS'}{$sam}{'sophomorixAdmins'} }+1;

        @{ $groups{'GROUPS'}{$sam}{'sophomorixMembers'} } = sort $entry->get_value('sophomorixMembers');
        $groups{'GROUPS'}{$sam}{'sophomorixMembers_count'} = $#{ $groups{'GROUPS'}{$sam}{'sophomorixMembers'} }+1;

        @{ $groups{'GROUPS'}{$sam}{'sophomorixAdminGroups'} } = sort $entry->get_value('sophomorixAdminGroups');
        $groups{'GROUPS'}{$sam}{'sophomorixAdminGroups_count'} = $#{ $groups{'GROUPS'}{$sam}{'sophomorixAdminGroups'} }+1;

        @{ $groups{'GROUPS'}{$sam}{'sophomorixMemberGroups'} } = sort $entry->get_value('sophomorixMemberGroups');
        $groups{'GROUPS'}{$sam}{'sophomorixMemberGroups_count'} = $#{ $groups{'GROUPS'}{$sam}{'sophomorixMemberGroups'} }+1;

	@{ $groups{'GROUPS'}{$sam}{'proxyAddresses'} } = sort $entry->get_value('proxyAddresses');

        # intrinsic
        $groups{'GROUPS'}{$sam}{'sophomorixIntrinsic1'}=$entry->get_value('sophomorixIntrinsic1');
        $groups{'GROUPS'}{$sam}{'sophomorixIntrinsic2'}=$entry->get_value('sophomorixIntrinsic2');
        $groups{'GROUPS'}{$sam}{'sophomorixIntrinsic3'}=$entry->get_value('sophomorixIntrinsic3');
        $groups{'GROUPS'}{$sam}{'sophomorixIntrinsic4'}=$entry->get_value('sophomorixIntrinsic4');
        $groups{'GROUPS'}{$sam}{'sophomorixIntrinsic5'}=$entry->get_value('sophomorixIntrinsic5');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixIntrinsicMulti1'} } = sort $entry->get_value('sophomorixIntrinsicMulti1');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixIntrinsicMulti2'} } = sort $entry->get_value('sophomorixIntrinsicMulti2');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixIntrinsicMulti3'} } = sort $entry->get_value('sophomorixIntrinsicMulti3');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixIntrinsicMulti4'} } = sort $entry->get_value('sophomorixIntrinsicMulti4');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixIntrinsicMulti5'} } = sort $entry->get_value('sophomorixIntrinsicMulti5');

        # custom
        $groups{'GROUPS'}{$sam}{'sophomorixCustom1'}=$entry->get_value('sophomorixCustom1');
        $groups{'GROUPS'}{$sam}{'sophomorixCustom2'}=$entry->get_value('sophomorixCustom2');
        $groups{'GROUPS'}{$sam}{'sophomorixCustom3'}=$entry->get_value('sophomorixCustom3');
        $groups{'GROUPS'}{$sam}{'sophomorixCustom4'}=$entry->get_value('sophomorixCustom4');
        $groups{'GROUPS'}{$sam}{'sophomorixCustom5'}=$entry->get_value('sophomorixCustom5');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixCustomMulti1'} } = sort $entry->get_value('sophomorixCustomMulti1');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixCustomMulti2'} } = sort $entry->get_value('sophomorixCustomMulti2');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixCustomMulti3'} } = sort $entry->get_value('sophomorixCustomMulti3');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixCustomMulti4'} } = sort $entry->get_value('sophomorixCustomMulti4');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixCustomMulti5'} } = sort $entry->get_value('sophomorixCustomMulti5');

        # room stuff
        @{ $groups{'GROUPS'}{$sam}{'sophomorixRoomComputers'} } = sort $entry->get_value('sophomorixRoomComputers');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixRoomIPs'} } = sort $entry->get_value('sophomorixRoomIPs');
        @{ $groups{'GROUPS'}{$sam}{'sophomorixRoomMACs'} } = sort $entry->get_value('sophomorixRoomMACs');


    }
    $groups{'COUNTER'}{'TOTAL'}=$max;
    if ($max>0){
        @{ $groups{'LISTS'}{'GROUPS'} } = sort @{ $groups{'LISTS'}{'GROUPS'} };
    }    
    if ($max==0){
        print "0 groups found\n";
    }
    return \%groups;
}



sub AD_get_full_userdata {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $userlist = $arg_ref->{userlist};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my @userlist=split(/,/,$userlist); # list of parameters, could be 'beck*'
    my $filter;
    my %users=();

    if ($#userlist==0){
        $filter="(& (sophomorixRole=*) (sAMAccountName=".$userlist[0]."))"; 
    } else {
        $filter="(& (sophomorixRole=*) (|";
        foreach my $user (@userlist){
            $filter=$filter." (sAMAccountName=".$user.")";
        } 
        $filter=$filter." ))";
    }
    #print "$filter\n";
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                       );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $sam=$entry->get_value('sAMAccountName');

        # this is the userlist of all users found, i.e. 'becker,beckerle'
        push @{ $users{'LISTS'}{'USERS'} }, $sam;

        $users{'USERS'}{$sam}{'dn'}=$entry->dn();
        $users{'USERS'}{$sam}{'sAMAccountName'}=$entry->get_value('sAMAccountName');
        $users{'USERS'}{$sam}{'sophomorixStatus'}=$entry->get_value('sophomorixStatus');
        $users{'USERS'}{$sam}{'sophomorixRole'}=$entry->get_value('sophomorixRole');
        $users{'USERS'}{$sam}{'sophomorixUserToken'}=$entry->get_value('sophomorixUserToken');
        $users{'USERS'}{$sam}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
        $users{'USERS'}{$sam}{'sophomorixCreationDate'}=$entry->get_value('sophomorixCreationDate');
        $users{'USERS'}{$sam}{'sophomorixTolerationDate'}=$entry->get_value('sophomorixTolerationDate');
        $users{'USERS'}{$sam}{'sophomorixDeactivationDate'}=$entry->get_value('sophomorixDeactivationDate');
        $users{'USERS'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
        $users{'USERS'}{$sam}{'sophomorixExitAdminClass'}=$entry->get_value('sophomorixExitAdminClass');
        $users{'USERS'}{$sam}{'sophomorixFirstPassword'}=$entry->get_value('sophomorixFirstPassword');
        $users{'USERS'}{$sam}{'sophomorixFirstnameASCII'}=$entry->get_value('sophomorixFirstnameASCII');
        $users{'USERS'}{$sam}{'sophomorixSurnameASCII'}=$entry->get_value('sophomorixSurnameASCII');

        $users{'USERS'}{$sam}{'sophomorixFirstnameInitial'}=$entry->get_value('sophomorixFirstnameInitial');
        $users{'USERS'}{$sam}{'sophomorixSurnameInitial'}=$entry->get_value('sophomorixSurnameInitial');

        $users{'USERS'}{$sam}{'sophomorixBirthdate'}=$entry->get_value('sophomorixBirthdate');
        $users{'USERS'}{$sam}{'sophomorixUnid'}=$entry->get_value('sophomorixUnid');
        @{ $users{'USERS'}{$sam}{'sophomorixWebuiPermissions'} } = 
             sort $entry->get_value('sophomorixWebuiPermissions');
        @{ $users{'USERS'}{$sam}{'sophomorixWebuiPermissionsCalculated'} } = 
             sort $entry->get_value('sophomorixWebuiPermissionsCalculated');

        $users{'USERS'}{$sam}{'sn'}=$entry->get_value('sn');
        $users{'USERS'}{$sam}{'givenName'}=$entry->get_value('givenName');
        $users{'USERS'}{$sam}{'cn'}=$entry->get_value('cn');
        $users{'USERS'}{$sam}{'displayName'}=$entry->get_value('displayName');
        $users{'USERS'}{$sam}{'userAccountControl'}=$entry->get_value('userAccountControl');
        $users{'USERS'}{$sam}{'mail'}=$entry->get_value('mail');
        @{ $users{'USERS'}{$sam}{'proxyAddresses'} } = 
             sort $entry->get_value('proxyAddresses');
        $users{'USERS'}{$sam}{'sophomorixSchoolPrefix'}=$entry->get_value('sophomorixSchoolPrefix');
        $users{'USERS'}{$sam}{'sophomorixAdminFile'}=$entry->get_value('sophomorixAdminFile');
        $users{'USERS'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
        $users{'USERS'}{$sam}{'sophomorixExamMode'}=$entry->get_value('sophomorixExamMode');
        $users{'USERS'}{$sam}{'sophomorixCloudQuotaCalculated'}=$entry->get_value('sophomorixCloudQuotaCalculated');
        $users{'USERS'}{$sam}{'sophomorixMailQuotaCalculated'}=$entry->get_value('sophomorixMailQuotaCalculated');
        $users{'USERS'}{$sam}{'sophomorixMailQuota'}=$entry->get_value('sophomorixMailQuota');
        @{ $users{'USERS'}{$sam}{'memberOf'} } = sort $entry->get_value('memberOf');
        @{ $users{'USERS'}{$sam}{'sophomorixQuota'} } = sort $entry->get_value('sophomorixQuota');

        # Intrinsic attributes
        $users{'USERS'}{$sam}{'sophomorixIntrinsic1'}=$entry->get_value('sophomorixIntrinsic1');
        $users{'USERS'}{$sam}{'sophomorixIntrinsic2'}=$entry->get_value('sophomorixIntrinsic2');
        $users{'USERS'}{$sam}{'sophomorixIntrinsic3'}=$entry->get_value('sophomorixIntrinsic3');
        $users{'USERS'}{$sam}{'sophomorixIntrinsic4'}=$entry->get_value('sophomorixIntrinsic4');
        $users{'USERS'}{$sam}{'sophomorixIntrinsic5'}=$entry->get_value('sophomorixIntrinsic5');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti1'} } = sort $entry->get_value('sophomorixIntrinsicMulti1');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti2'} } = sort $entry->get_value('sophomorixIntrinsicMulti2');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti3'} } = sort $entry->get_value('sophomorixIntrinsicMulti3');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti4'} } = sort $entry->get_value('sophomorixIntrinsicMulti4');
        @{ $users{'USERS'}{$sam}{'sophomorixIntrinsicMulti5'} } = sort $entry->get_value('sophomorixIntrinsicMulti5');

        # custom attributes
        $users{'USERS'}{$sam}{'sophomorixCustom1'}=$entry->get_value('sophomorixCustom1');
        $users{'USERS'}{$sam}{'sophomorixCustom2'}=$entry->get_value('sophomorixCustom2');
        $users{'USERS'}{$sam}{'sophomorixCustom3'}=$entry->get_value('sophomorixCustom3');
        $users{'USERS'}{$sam}{'sophomorixCustom4'}=$entry->get_value('sophomorixCustom4');
        $users{'USERS'}{$sam}{'sophomorixCustom5'}=$entry->get_value('sophomorixCustom5');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti1'} } = sort $entry->get_value('sophomorixCustomMulti1');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti2'} } = sort $entry->get_value('sophomorixCustomMulti2');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti3'} } = sort $entry->get_value('sophomorixCustomMulti3');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti4'} } = sort $entry->get_value('sophomorixCustomMulti4');
        @{ $users{'USERS'}{$sam}{'sophomorixCustomMulti5'} } = sort $entry->get_value('sophomorixCustomMulti5');

        # samba
        $users{'USERS'}{$sam}{'homeDirectory'}=$entry->get_value('homeDirectory');
        $users{'USERS'}{$sam}{'homeDrive'}=$entry->get_value('homeDrive');
        $users{'USERS'}{$sam}{'accountExpires'}=$entry->get_value('accountExpires');
        $users{'USERS'}{$sam}{'badPasswordTime'}=$entry->get_value('badPasswordTime');
        $users{'USERS'}{$sam}{'badPwdCount'}=$entry->get_value('badPwdCount');
        $users{'USERS'}{$sam}{'codePage'}=$entry->get_value('codePage');
        $users{'USERS'}{$sam}{'countryCode'}=$entry->get_value('countryCode');
        $users{'USERS'}{$sam}{'lastLogoff'}=$entry->get_value('lastLogoff');
        $users{'USERS'}{$sam}{'lastLogon'}=$entry->get_value('lastLogon');
        $users{'USERS'}{$sam}{'logonCount'}=$entry->get_value('logonCount');

        # sid
        #$users{'USERS'}{$sam}{'objectSid_BINARY'}=$entry->get_value('objectSid');
        my $sid = Net::LDAP::SID->new($entry->get_value('objectSid'));
        $users{'USERS'}{$sam}{'objectSid'}=$sid->as_string;

        # GUID
        #$users{'USERS'}{$sam}{'objectGUID_BINARY'}=$entry->get_value('objectGUID');

        $users{'USERS'}{$sam}{'pwdLastSet'}=$entry->get_value('pwdLastSet');
        $users{'USERS'}{$sam}{'sAMAccountType'}=$entry->get_value('sAMAccountType');
        $users{'USERS'}{$sam}{'userPrincipalName'}=$entry->get_value('userPrincipalName');
        $users{'USERS'}{$sam}{'uSNChanged'}=$entry->get_value('uSNChanged');
        $users{'USERS'}{$sam}{'uSNCreated'}=$entry->get_value('uSNCreated');
        # unix
        $users{'USERS'}{$sam}{'unixHomeDirectory'}=$entry->get_value('unixHomeDirectory');
        $users{'USERS'}{$sam}{'primaryGroupID'}=$entry->get_value('primaryGroupID');
        # password from file
        if (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_ALLADMINS'}{$entry->get_value('sophomorixRole')}){
            # check for password file
            my $pwf="FALSE";
            my $password="Password was not saved on the server!";
            my $pwd_file=$ref_sophomorix_config->{'INI'}{'PATHS'}{'SECRET_PWD'}."/".$sam;
            if (-e $pwd_file){
                $pwf="TRUE";
                $password=`cat $pwd_file`;
            }
            $users{'USERS'}{$sam}{'PWDFile'}=$pwd_file;
            $users{'USERS'}{$sam}{'PWDFileExists'}=$pwf;
            $users{'USERS'}{$sam}{'PASSWORD'}=$password;
        }
        
    }
    $users{'COUNTER'}{'TOTAL'}=$max;
    if ($max>0){
        @{ $users{'LISTS'}{'USERS'} } = sort @{ $users{'LISTS'}{'USERS'} };
    }    

    # read logfiles for each user that was found
    foreach my $user (@{ $users{'LISTS'}{'USERS'} }){
        my $anything_found=0;
        my $log_add=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	    $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_ADD'};
        my $log_update=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	    $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_UPDATE'};
        my $log_kill=$ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_LOGDIR'}."/".
	    $ref_sophomorix_config->{'INI'}{'USERLOG'}{'USER_KILL'};
        # ADD
        if (-f $log_add){
            open(ADD,"<$log_add");
            while (<ADD>) {
                my ($add,$epoch,$date,$school,$login,$last,$first,$group,$role,$unid) = split(/::/);
                if ($login eq $user){
                    $anything_found++;
                    $users{'LOOKUP'}{'LOGUSERS'}{$user}{'FOUND'}="TRUE";
                    if (not exists $users{'USERS'}{$user}{'sAMAccountName'}){
                        push @{ $users{'LISTS'}{'DELETED_USERS'} }, $user;
                    }
                    my $human_date=&Sophomorix::SophomorixBase::ymdhms_to_date($date);
                    my $logline="ADD:  $human_date  $login ($last, $first) in $group as $role";
                    push @{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} },$epoch ;
                    $users{'USERS'}{$user}{'HISTORY'}{'EPOCH'}{$epoch}=$logline;
                }
            }
            close(ADD);
        }

        # KILL
        if (-f $log_kill){
            open(KILL,"<$log_kill");
            while (<KILL>) {
                my ($kill,$epoch,$date,$school,$login,$last,$first,$group,$role,$unid,$info) = split(/::/);
                if ($login eq $user){
                    $anything_found++;
                    $users{'LOOKUP'}{'LOGUSERS'}{$user}{'FOUND'}="TRUE";
                    if (not exists $users{'USERS'}{$user}{'sAMAccountName'}){
                        push @{ $users{'LISTS'}{'DELETED_USERS'} }, $user;
                    }
                    my $human_date=&Sophomorix::SophomorixBase::ymdhms_to_date($date);
                    my $logline;
                    if ($info eq "MIGRATED"){
                        $logline="KILL: $human_date  $login ($last, $first), MIGRATED";
                    } else {
                        $logline="KILL: $human_date  $login ($last, $first) in $group as $role";
                    }
                    push @{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} },$epoch ;
                    $users{'USERS'}{$user}{'HISTORY'}{'EPOCH'}{$epoch}=$logline;
                }
            }
            close(KILL);
        }
        if ($anything_found==0 and not exists $users{'USERS'}{$user}){
            push @{ $users{'LISTS'}{'UNKNOWN_USERS'} }, $user;
        }
        # order epoch entries
        if ($#{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }>0){
	    @{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }=sort @{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} };
            $users{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'}=$#{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }+1;
        } else {
            $users{'USERS'}{$user}{'HISTORY'}{'ENTRY_COUNT'}=$#{ $users{'USERS'}{$user}{'HISTORY'}{'LIST_by_EPOCH'} }+1;
        }
    }

    if ($max==0){
        print "0 users found in AD\n";
    }
    @{ $users{'LISTS'}{'DELETED_USERS'} } = uniq(@{ $users{'LISTS'}{'DELETED_USERS'} });
    return \%users;
}



sub AD_get_full_devicedata {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $devicelist = $arg_ref->{devicelist};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my @devicelist=split(/,/,$devicelist); # list of parameters, could be 'j1010*'
    my %devices=();

    ############################################################
    # look for dnsNode
    my $filter_node=&_create_filter_alldevices(\@devicelist,
                                               $ref_sophomorix_config,
                                               "dnsNode",
                                               "sophomorixDnsNodename");
    # search
    my $base="DC=DomainDnsZones,".$root_dse;
    my $mesg_node = $ldap->search(
                           base   => $base,
                           scope => 'sub',
                           filter => $filter_node,
                          );
    &AD_debug_logdump($mesg_node,2,(caller(0))[3]);
    my $max_node = $mesg_node->count;
    for( my $index = 0 ; $index < $max_node ; $index++) {
        my $entry = $mesg_node->entry($index);
        my $name=$entry->get_value('name');
        my $dn=$entry->dn();
        my $cn=$entry->get_value('cn');
        # sophomorixDnsNodetype (lookup/reverse))
        my $dnsnode_type="";
        if (defined $entry->get_value('sophomorixDnsNodetype')){
            $dnsnode_type=$entry->get_value('sophomorixDnsNodetype');
        }

        if ($dnsnode_type eq $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_TYPE_REVERSE'}){
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dn'}=$dn;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'cn'}=$cn;

            # dnsRecord: see https://msdn.microsoft.com/en-us/library/ee898781.aspx
            my $dns_blob=$entry->get_value('dnsRecord');
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord'}=$dns_blob;
            my $blob = decode_base64($dns_blob);
            my ($dataLength,    # 2 bytes
                $type,          # 2 bytes
                $version,       # 1 byte
                $rank,          # 1 byte
                $flags,         # 2 bytes 
                $serial,        # 4 bytes 
                $ttl,           # 4 bytes 
                $reserved,      # 4 bytes 
                $timestamp,     # 4 bytes
                $data ) = unpack( 'S S C C S L N L L a*', $dns_blob );
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_DataLength'}=$dataLength;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_Type'}=$type;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_Version'}=$version;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_Rank'}=$rank;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_Flags'}=$flags;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_Serial'}=$serial;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_TtlSeconds'}=$ttl;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_Reserved'}=$reserved;
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_TimeStamp'}=$timestamp;
            #$devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'dnsRecord_Data'}=inet_ntoa($data);

            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'name'}=
                $entry->get_value('name');
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'sophomorixAdminFile'}=
                $entry->get_value('sophomorixAdminFile');
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'sophomorixComment'}=
                $entry->get_value('sophomorixComment');
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'sophomorixDnsNodename'}=
                $entry->get_value('sophomorixDnsNodename');
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'sophomorixDnsNodetype'}=
                $entry->get_value('sophomorixDnsNodetype');
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'sophomorixRole'}=
                $entry->get_value('sophomorixRole');
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'sophomorixSchoolname'}=
                $entry->get_value('sophomorixSchoolname');
            $devices{'DEVICES'}{$cn}{'dnsNode_REVERSE'}{$cn}{'sophomorixComputerIP'}=
                $entry->get_value('sophomorixComputerIP');
            # list of results
            push @{ $devices{'LISTS'}{'dnsNode_REVERSE'} }, $name;
        } elsif ($dnsnode_type eq $ref_sophomorix_config->{'INI'}{'DNS'}{'DNSNODE_TYPE_LOOKUP'}) {
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dn'}=$dn;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'cn'}=$cn;
            my $dns_blob=$entry->get_value('dnsRecord');
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord'}=$dns_blob;
            my $blob = decode_base64($dns_blob);
            my ($dataLength,    # 2 bytes
                $type,          # 2 bytes
                $version,       # 1 byte
                $rank,          # 1 byte
                $flags,         # 2 bytes 
                $serial,        # 4 bytes 
                $ttl,           # 4 bytes 
                $reserved,      # 4 bytes 
                $timestamp,     # 4 bytes
                $data ) = unpack( 'S S C C S L N L L a*', $dns_blob );
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_DataLength'}=$dataLength;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_Type'}=$type;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_Version'}=$version;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_Rank'}=$rank;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_Flags'}=$flags;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_Serial'}=$serial;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_TtlSeconds'}=$ttl;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_Reserved'}=$reserved;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_TimeStamp'}=$timestamp;
            #$devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'dnsRecord_Data'}=inet_ntoa($data);

            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'name'}=
                $entry->get_value('name');;
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'sophomorixAdminFile'}=
                $entry->get_value('sophomorixAdminFile');
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'sophomorixComment'}=
                $entry->get_value('sophomorixComment');
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'sophomorixDnsNodename'}=
                $entry->get_value('sophomorixDnsNodename');
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'sophomorixDnsNodetype'}=
                $entry->get_value('sophomorixDnsNodetype');
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'sophomorixRole'}=
                $entry->get_value('sophomorixRole');
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'sophomorixSchoolname'}=
                $entry->get_value('sophomorixSchoolname');
            $devices{'DEVICES'}{$cn}{'dnsNode'}{$cn}{'sophomorixComputerIP'}=
                $entry->get_value('sophomorixComputerIP');
            # list of results
            push @{ $devices{'LISTS'}{'dnsNode'} }, $name;
        } else {
            # all sophomorix node have sophomorixDnsNodetype = lookup/reverse 
        }
    }

    ############################################################
    # look for computer account
    ### create filter
    my $filter=&_create_filter_alldevices(\@devicelist,
                                          $ref_sophomorix_config,
                                          "computer",
                                          "sAMAccountName");
    # search
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                       );
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $sam=$entry->get_value('sAMAccountName');
        my $device=$entry->get_value('sophomorixDnsNodename');
        $devices{'DEVICES'}{$device}{'computer'}{'dn'}=$entry->dn();
        $devices{'DEVICES'}{$device}{'computer'}{'sAMAccountName'}=
            $entry->get_value('sAMAccountName');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixStatus'}=
            $entry->get_value('sophomorixStatus');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixRole'}=
            $entry->get_value('sophomorixRole');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixSchoolname'}=
            $entry->get_value('sophomorixSchoolname');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCreationDate'}=
            $entry->get_value('sophomorixCreationDate');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixAdminClass'}=
            $entry->get_value('sophomorixAdminClass');
        $devices{'DEVICES'}{$device}{'computer'}{'cn'}=
            $entry->get_value('cn');
        $devices{'DEVICES'}{$device}{'computer'}{'name'}=
            $entry->get_value('name');
        $devices{'DEVICES'}{$device}{'computer'}{'displayName'}=
            $entry->get_value('displayName');
        $devices{'DEVICES'}{$device}{'computer'}{'userAccountControl'}=
            $entry->get_value('userAccountControl');
        @{  $devices{'DEVICES'}{$device}{'computer'}{'servicePrincipalName'} }= 
            sort $entry->get_value('servicePrincipalName');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixSchoolPrefix'}=
            $entry->get_value('sophomorixSchoolPrefix');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixAdminFile'}=
            $entry->get_value('sophomorixAdminFile');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixComment'}=
            $entry->get_value('sophomorixComment');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixDnsNodename'}=
            $entry->get_value('sophomorixDnsNodename');
        $devices{'DEVICES'}{$device}{'computer'}{'dNSHostName'}=
            $entry->get_value('dNSHostName');
        @{  $devices{'DEVICES'}{$device}{'computer'}{'memberOf'} }= 
            sort $entry->get_value('memberOf');

	# Intrinsic attributes
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic1'}=$entry->get_value('sophomorixIntrinsic1');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic2'}=$entry->get_value('sophomorixIntrinsic2');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic3'}=$entry->get_value('sophomorixIntrinsic3');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic4'}=$entry->get_value('sophomorixIntrinsic4');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsic5'}=$entry->get_value('sophomorixIntrinsic5');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti1'} } = sort $entry->get_value('sophomorixIntrinsicMulti1');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti2'} } = sort $entry->get_value('sophomorixIntrinsicMulti2');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti3'} } = sort $entry->get_value('sophomorixIntrinsicMulti3');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti4'} } = sort $entry->get_value('sophomorixIntrinsicMulti4');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixIntrinsicMulti5'} } = sort $entry->get_value('sophomorixIntrinsicMulti5');

        # custom attributes
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustom1'}=$entry->get_value('sophomorixCustom1');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustom2'}=$entry->get_value('sophomorixCustom2');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustom3'}=$entry->get_value('sophomorixCustom3');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustom4'}=$entry->get_value('sophomorixCustom4');
        $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustom5'}=$entry->get_value('sophomorixCustom5');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti1'} } = sort $entry->get_value('sophomorixCustomMulti1');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti2'} } = sort $entry->get_value('sophomorixCustomMulti2');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti3'} } = sort $entry->get_value('sophomorixCustomMulti3');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti4'} } = sort $entry->get_value('sophomorixCustomMulti4');
        @{ $devices{'DEVICES'}{$device}{'computer'}{'sophomorixCustomMulti5'} } = sort $entry->get_value('sophomorixCustomMulti5');
	
        # samba
        $devices{'DEVICES'}{$device}{'computer'}{'accountExpires'}=
            $entry->get_value('accountExpires');
        $devices{'DEVICES'}{$device}{'computer'}{'badPasswordTime'}=
            $entry->get_value('badPasswordTime');
        $devices{'DEVICES'}{$device}{'computer'}{'badPwdCount'}=
            $entry->get_value('badPwdCount');
        $devices{'DEVICES'}{$device}{'computer'}{'codePage'}=
            $entry->get_value('codePage');
        $devices{'DEVICES'}{$device}{'computer'}{'countryCode'}=
            $entry->get_value('countryCode');
        $devices{'DEVICES'}{$device}{'computer'}{'lastLogoff'}=
            $entry->get_value('lastLogoff');
        $devices{'DEVICES'}{$device}{'computer'}{'lastLogon'}=
            $entry->get_value('lastLogon');
        $devices{'DEVICES'}{$device}{'computer'}{'logonCount'}=
            $entry->get_value('logonCount');
        $devices{'DEVICES'}{$device}{'computer'}{'objectSid'}=
            $entry->get_value('objectSid');
        $devices{'DEVICES'}{$device}{'computer'}{'objectGUID'}=
            $entry->get_value('objectGUID');
        $devices{'DEVICES'}{$device}{'computer'}{'pwdLastSet'}=
            $entry->get_value('pwdLastSet');
        $devices{'DEVICES'}{$device}{'computer'}{'sAMAccountType'}=
            $entry->get_value('sAMAccountType');
        $devices{'DEVICES'}{$device}{'computer'}{'uSNChanged'}=
            $entry->get_value('uSNChanged');
        $devices{'DEVICES'}{$device}{'computer'}{'uSNCreated'}=
            $entry->get_value('uSNCreated');
        # unix
        $devices{'DEVICES'}{$device}{'computer'}{'primaryGroupID'}=
            $entry->get_value('primaryGroupID');
        # list of results
        push @{ $devices{'LISTS'}{'computer'} }, $device;
    }

    $devices{'COUNTER'}{'dnsNode'}{'TOTAL'}=$#{ $devices{'LISTS'}{'dnsNode'} }+1;
    $devices{'COUNTER'}{'dnsNode_REVERSE'}{'TOTAL'}=$#{ $devices{'LISTS'}{'dnsNode_REVERSE'} }+1;
    $devices{'COUNTER'}{'computer'}{'TOTAL'}=$#{ $devices{'LISTS'}{'computer'} }+1;
    
    return \%devices;
}



sub AD_get_groups_v {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my %groups=();
    foreach my $school (@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} }){
        # set back school counters
        $groups{'COUNTER'}{$school}{'by_type'}{'project'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'adminclass'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'extraclass'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'teacherclass'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'class'}=0;
        $groups{'COUNTER'}{$school}{'by_type'}{'sophomorix-group'}=0;
    }

    ############################################################
    # create lookup dn -> role
    ############################################################
    my $user_filter="(objectClass=user)"; 
    # print "Filter: $user_filter\n";
    my $mesg0 = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $user_filter,
                      attr => ['sAMAccountName',
                               'dn',
                               'sophomorixRole',
                              ]);
    &AD_debug_logdump($mesg0,2,(caller(0))[3]);
    my $max_user = $mesg0->count;
    for( my $index = 0 ; $index < $max_user ; $index++) {
        my $entry = $mesg0->entry($index);
        $groups{'LOOKUP'}{'sophomorixRole_by_DN'}{$entry->dn()}=$entry->get_value('sophomorixRole');
    }

    ##################################################
    # search for all sophomorix groups
    # Setting the filters
    my $filter="(objectClass=group)"; 
    # print "Filter: $filter\n";
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attr => ['sAMAccountName',
                               'cn',
                               'displayName',
                               'description',
                               'sophomorixType',
                               'sophomorixHidden',
                               'sophomorixStatus',
                               'sophomorixQuota',
                               'sophomorixMailQuota',
                               'sophomorixAddQuota',
                               'sophomorixAddMailQuota',
                               'sophomorixMailAlias',
                               'sophomorixMailList',
                               'sophomorixJoinable',
                               'sophomorixMaxMembers',
                               'sophomorixSchoolname',
                               'sophomorixAdmins',
                               'member',
                              ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;
    ##################################################
    # walk through all results
    # save results in lists
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $type=$entry->get_value('sophomorixType');
        my $status=$entry->get_value('sophomorixStatus');
        my $schoolname=$entry->get_value('sophomorixSchoolname');
        if (not defined $type or not defined $status){
            # non sophomorix group
            $groups{'COUNTER'}{'OTHER'}++;
            $groups{'GROUPS_by_sophomorixType'}{'OTHER'}{$sam}=$dn;
            $groups{'GROUPS'}{$sam}{'DN'}=$dn;
       } else {
            # sophomorix group
            $groups{'COUNTER'}{$schoolname}{'TOTAL'}++;
            $groups{'COUNTER'}{$schoolname}{'status_by_type'}{$type}{$status}++;
            $groups{'COUNTER'}{$schoolname}{'by_type'}{$type}++;
            push @{ $groups{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$schoolname}{$type} },$sam;
            if ($type eq "adminclass" or $type eq "teacherclass" or $type eq "extraclass"){
                $groups{'COUNTER'}{$schoolname}{'by_type'}{'class'}++;
                push @{ $groups{'LISTS'}{'GROUP_by_sophomorixSchoolname'}{$schoolname}{'class'} },$sam;
            }
            $groups{'GROUPS'}{$sam}{'DN'}=$dn;
            $groups{'GROUPS'}{$sam}{'sophomorixStatus'}=$status;
            $groups{'GROUPS'}{$sam}{'sophomorixType'}=$type;
            $groups{'GROUPS'}{$sam}{'displayName'}=$entry->get_value('displayName');
            $groups{'GROUPS'}{$sam}{'sophomorixMailQuota'}=$entry->get_value('sophomorixMailQuota');
            $groups{'GROUPS'}{$sam}{'sophomorixAddMailQuota'}=$entry->get_value('sophomorixAddMailQuota');
            @{ $groups{'GROUPS'}{$sam}{'sophomorixQuota'} }=$entry->get_value('sophomorixQuota');
            @{ $groups{'GROUPS'}{$sam}{'sophomorixAddQuota'} }=$entry->get_value('sophomorixAddQuota');
            $groups{'GROUPS'}{$sam}{'sophomorixMaxMembers'}=$entry->get_value('sophomorixMaxMembers');
            $groups{'GROUPS'}{$sam}{'sophomorixHidden'}=$entry->get_value('sophomorixHidden');
            $groups{'GROUPS'}{$sam}{'sophomorixMailAlias'}=$entry->get_value('sophomorixMailAlias');
            $groups{'GROUPS'}{$sam}{'sophomorixMailList'}=$entry->get_value('sophomorixMailList');
            $groups{'GROUPS'}{$sam}{'sophomorixJoinable'}=$entry->get_value('sophomorixJoinable');
            $groups{'GROUPS'}{$sam}{'description'}=$entry->get_value('description');
            $groups{'GROUPS'}{$sam}{'sophomorixSchoolname'}=$entry->get_value('sophomorixSchoolname');
            @{ $groups{'GROUPS'}{$sam}{'sophomorixAdmins'} }=$entry->get_value('sophomorixAdmins');
	    # count members
            @{ $groups{'GROUPS'}{$sam}{'member'}{'TOTAL'} }=$entry->get_value('member');
            $groups{'GROUPS'}{$sam}{'member_COUNT'}{'TOTAL'}=$#{ $groups{'GROUPS'}{$sam}{'member'}{'TOTAL'} }+1;
            # sort members into role ????
            # query all users
            # create lookup dn --> role
            foreach my $mem_dn (@{ $groups{'GROUPS'}{$sam}{'member'}{'TOTAL'} }){
                my $role;
                if ( defined $groups{'LOOKUP'}{'sophomorixRole_by_DN'}{$mem_dn} ){
                    $role=$groups{'LOOKUP'}{'sophomorixRole_by_DN'}{$mem_dn};
                } else {
                    $role="OTHER";
                }
                push @{ $groups{'GROUPS'}{$sam}{'member'}{$role} },$mem_dn;
            }
            # count the entries for certain roles
            $groups{'GROUPS'}{$sam}{'member_COUNT'}{'student'}=$#{ $groups{'GROUPS'}{$sam}{'member'}{'student'} }+1;
            $groups{'GROUPS'}{$sam}{'member_COUNT'}{'teacher'}=$#{ $groups{'GROUPS'}{$sam}{'member'}{'teacher'} }+1;
            $groups{'GROUPS'}{$sam}{'member_COUNT'}{'OTHER'}=$#{ $groups{'GROUPS'}{$sam}{'member'}{'OTHER'} }+1;
#            $groups{'GROUPS'}{$sam}{''}=$entry->get_value('');
#            $groups{'GROUPS'}{$sam}{''}=$entry->get_value('');
        }
    }
    return \%groups;
}



sub AD_get_examusers {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my %examusers=();
    $examusers{'COUNTER'}{'TOTAL'}=0;
    foreach my $school (@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} }){
        # set back school counters
        $examusers{'COUNTER'}{$school}=0;
    }

    ##################################################
    my $filter="(&(objectClass=user)".
               "(sophomorixRole=examuser)".
	       "(!(sophomorixExamMode=---)))";

    # print "Filter: $filter\n";
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attr => ['sAMAccountName',
                               'cn',
                               'displayName',
                               'sophomorixRole',
                               'sophomorixStatus',
                               'sophomorixSchoolname',
                               'sophomorixComment',
                               'sophomorixAdminClass',
                               'sophomorixExamMode',
                              ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;

    ##################################################
    # walk through all examusers
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $role=$entry->get_value('sophomorixRole');
        my $status=$entry->get_value('sophomorixStatus');
        my $schoolname=$entry->get_value('sophomorixSchoolname');
        $examusers{'COUNTER'}{$schoolname}++;
        $examusers{'COUNTER'}{'TOTAL'}++;
        $examusers{'EXAMUSERS'}{$sam}{'DN'}=$dn;
        $examusers{'EXAMUSERS'}{$sam}{'sophomorixStatus'}=$status;
        $examusers{'EXAMUSERS'}{$sam}{'displayName'}=$entry->get_value('displayName');
        $examusers{'EXAMUSERS'}{$sam}{'sophomorixRole'}=$role;
        $examusers{'EXAMUSERS'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
        $examusers{'EXAMUSERS'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
        $examusers{'EXAMUSERS'}{$sam}{'sophomorixExamMode'}=$entry->get_value('sophomorixExamMode');
        push @{ $examusers{'LISTS'}{'EXAMUSER_by_sophomorixSchoolname'}{$schoolname}{$role} },$sam;
    }
    return \%examusers;
}



sub AD_get_users_v {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $admins_only = $arg_ref->{admins_only};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    if (not defined $admins_only){
	$admins_only="FALSE";
    }

    my %users=();
    # set back global counters
    $users{'COUNTER'}{'global'}{'by_role'}{'globaladministrator'}=0;
    $users{'COUNTER'}{'global'}{'by_role'}{'globalbinduser'}=0;
    foreach my $school (@{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} }){
        # set back school counters
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'P'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'P'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'U'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'U'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'A'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'A'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'E'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'E'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'S'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'S'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'T'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'T'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'M'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'M'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'D'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'D'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'L'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'L'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'F'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'F'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'R'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'R'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'student'}{'K'}=0;
        $users{'COUNTER'}{$school}{'status_by_role'}{'teacher'}{'K'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'student'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'teacher'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'schooladministrator'}=0;
        $users{'COUNTER'}{$school}{'by_role'}{'schoolbinduser'}=0;
        $users{'COUNTER'}{$school}{'TOTAL'}=0;
    }

    ##################################################
    # search for all users but not computers
    # Setting the filters
    my $filter;
    if ($admins_only eq "TRUE"){
        $filter="(&(objectClass=user) (| ".
                "(sophomorixRole=schoolbinduser) ".
                "(sophomorixRole=globalbinduser) ".
                "(sophomorixRole=schooladministrator) ".
                "(sophomorixRole=globaladministrator)) )";
    } else {
        $filter="( &(objectClass=user) (!(objectClass=computer)) )"; 
    }
    # print "Filter: $filter\n";
    my $mesg = $ldap->search(
                      base   => $root_dse,
                      scope => 'sub',
                      filter => $filter,
                      attr => ['sAMAccountName',
                               'cn',
                               'displayName',
                               'sophomorixRole',
                               'sophomorixStatus',
                               'sophomorixSchoolname',
                               'sophomorixComment',
                               'sophomorixAdminClass',
                              ]);
    &AD_debug_logdump($mesg,2,(caller(0))[3]);
    my $max = $mesg->count;

    ##################################################
    # walk through all users
    # save results in lists
    for( my $index = 0 ; $index < $max ; $index++) {
        my $entry = $mesg->entry($index);
        my $dn=$entry->dn();
        my $sam=$entry->get_value('sAMAccountName');
        my $role=$entry->get_value('sophomorixRole');
        my $status=$entry->get_value('sophomorixStatus');
        my $schoolname=$entry->get_value('sophomorixSchoolname');
        if (not defined $role or not defined $status){
            # non sophomorix user
            $users{'COUNTER'}{'OTHER'}++;
            $users{'USERS_by_sophomorixRole'}{'OTHER'}{$sam}=$dn;
            $users{'USERS'}{$sam}{'DN'}=$dn;
            push @{ $users{'LISTS'}{'USER_by_SCHOOL'}{'OTHER'}{'OTHER'} },$sam;
        } else {
            # sophomorix user
            $users{'COUNTER'}{$schoolname}{'TOTAL'}++;
            $users{'COUNTER'}{$schoolname}{'status_by_role'}{$role}{$status}++;
            $users{'COUNTER'}{$schoolname}{'by_role'}{$role}++;
            $users{'USERS'}{$sam}{'DN'}=$dn;
            $users{'USERS'}{$sam}{'sophomorixStatus'}=$status;
            $users{'USERS'}{$sam}{'displayName'}=$entry->get_value('displayName');
            $users{'USERS'}{$sam}{'sophomorixComment'}=$entry->get_value('sophomorixComment');
            $users{'USERS'}{$sam}{'sophomorixAdminClass'}=$entry->get_value('sophomorixAdminClass');
            push @{ $users{'LISTS'}{'USER_by_sophomorixSchoolname'}{$schoolname}{$role} },$sam;
            # if its an administrator
            if (exists $ref_sophomorix_config->{'LOOKUP'}{'ROLES_ALLADMINS'}{$role}){
                # check for password file
                my $pwf="FALSE";
                my $pwd_file=$ref_sophomorix_config->{'INI'}{'PATHS'}{'SECRET_PWD'}."/".$sam;
                if (-e $pwd_file){
                    $pwf="TRUE";
                }
                $users{'USERS'}{$sam}{'PWDFileExists'}=$pwf;
            }
        }
    }
    return \%users;
}



sub AD_get_shares_v {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    my %shares=();

    # helper lists
    my @other=();   # other shares
    my @schools=(); # schools

    # add all schools to lists
    foreach my $school ( @{ $ref_sophomorix_config->{'LISTS'}{'SCHOOLS'} } ) {
        $shares{'SHARES'}{$school}{'TYPE'}="SCHOOL";
        push @schools, $school;
    }

    # add all shares to lists
    foreach my $share ( @{ $ref_sophomorix_config->{'LISTS'}{'SHARES'} } ) {
        if (exists $ref_sophomorix_config->{'SCHOOLS'}{$share} ) {
            # school
            $shares{'SHARES'}{$share}{'TYPE'}="SCHOOL";
            push @schools, $share;
        } elsif ($share eq $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}){
            # push not in a list, prepended later
            $shares{'SHARES'}{$share}{'TYPE'}="GLOBAL";
        } else {
            # other
            $shares{'SHARES'}{$share}{'TYPE'}="OTHER_SHARE";
            push @other, $share;
        }
    }

    # uniquifi the schools
    @schools = uniq(@schools);
    @schools = sort @schools;

    # create list: global,schools,other shares
    my @shares=($ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'},@schools,@other);

    foreach my $share ( @shares ) {
        push @{ $shares{'LISTS'}{'SHARES'} },$share;


        # files
        if ($shares{'SHARES'}{$share}{'TYPE'} eq "SCHOOL"){
            # SCHOOL
            push @{ $shares{'LISTS'}{'SCHOOLS'} },$share;
            # add some stuff
            $shares{'SHARES'}{$share}{'OU_TOP'}=$ref_sophomorix_config->{'SCHOOLS'}{$share}{'OU_TOP'};
            @{ $shares{'SHARES'}{$share}{'FILELIST'} }=@{ $ref_sophomorix_config->{'SCHOOLS'}{$share}{'FILELIST'} };
            foreach my $file ( @{ $shares{'SHARES'}{$share}{'FILELIST'} } ){
                if (-e $file ){
                    $shares{'SHARES'}{$share}{'FILE'}{$file}{'EXISTS'}="TRUE";
                    $shares{'SHARES'}{$share}{'FILE'}{$file}{'EXISTSDISPLAY'}="*";
                } else {
                    $shares{'SHARES'}{$share}{'FILE'}{$file}{'EXISTS'}="FALSE";
                   $shares{'SHARES'}{$share}{'FILE'}{$file}{'EXISTSDISPLAY'}="-";
                } 
            }
        } elsif ($shares{'SHARES'}{$share}{'TYPE'} eq "OTHER_SHARE"){
            push @{ $shares{'LISTS'}{'OTHER_SHARES'} },$share;
        } elsif ($shares{'SHARES'}{$share}{'TYPE'} eq "GLOBAL"){
            push @{ $shares{'LISTS'}{'GLOBAL'} },$share;
        }


        # TESTS
        # SMB-SHARE
        if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}){
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTS'}="TRUE";
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTSDISPLAY'}="OK";
        } else {
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTS'}="FALSE";
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTSDISPLAY'}="NONEXISTING";
        }
        # MSDFS entry
        if (exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}{'msdfs root'}){
            my $msdfs=$ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}{'msdfs root'};
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFS'}=$msdfs;
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFSDISPLAY'}="???";
	} else {
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFSDISPLAY'}="NOT OK";
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'MSDFS'}="not configured. probably yes";

        }
        # test aquota.user file on share
        &AD_smbclient_testfile($root_dns,$smb_admin_pass,$share,"aquota.user",$ref_sophomorix_config,\%shares);
        # test quota
        if ( $shares{'SHARES'}{$share}{'SMB_SHARE'}{'EXISTS'} eq "TRUE"){
            &AD_smbcquotas_testshare($root_dns,$smb_admin_pass,$share,$ref_sophomorix_config,\%shares);
        } else {
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTAS'}="FALSE";
            $shares{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTASDISPLAY'}="NO SHARE";
        }
    }
    
    # sort some shares
    if ($#{ $shares{'LISTS'}{'OTHER_SHARES'} }>0){
        @{ $shares{'LISTS'}{'OTHER_SHARES'} } = sort @{ $shares{'LISTS'}{'OTHER_SHARES'} };
    }
    if ($#{ $shares{'LISTS'}{'GLOBAL'} }>0){
        @{ $shares{'LISTS'}{'GLOBAL'} } = sort @{ $shares{'LISTS'}{'GLOBAL'} };
    }
    if ($#{ $shares{'LISTS'}{'SHARES'} }>0){
        @{ $shares{'LISTS'}{'SHARES'} } = sort @{ $shares{'LISTS'}{'SHARES'} };
    }
    if ($#{ $shares{'LISTS'}{'SCHOOLS'} }>0){
        @{ $shares{'LISTS'}{'SCHOOLS'} } = sort @{ $shares{'LISTS'}{'SCHOOLS'} };
    }
    return \%shares;
}



sub AD_get_printdata {
    my %AD_printdata=();
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $school = $arg_ref->{school};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $users = $arg_ref->{users};
    if (not defined $users){$users="FALSE"};

    if ($users eq "TRUE"){
        # sophomorix students,teachers from ldap
        my $filter="(&(objectClass=user)(sophomorixSchoolname=".
           $school.")(|(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'STUDENT'}.")(sophomorixRole=".
           $ref_sophomorix_config->{'INI'}{'ROLE_USER'}{'TEACHER'}.")))";
        $mesg = $ldap->search( # perform a search
                       base   => $root_dse,
                       scope => 'sub',
                       filter => $filter,
                       attrs => ['sAMAccountName',
                                 'sophomorixAdminClass',
                                 'givenName',
                                 'sn',
                                 'sophomorixFirstnameASCII',
                                 'sophomorixSurnameASCII',
                                 'sophomorixSchoolname',
                                 'sophomorixRole',
                                 'sophomorixCreationDate',
                                 'sophomorixFirstPassword',
                                 'sophomorixUnid',
                                ]);
        my $max_user = $mesg->count; 
        &Sophomorix::SophomorixBase::print_title("$max_user sophomorix users found for password printout");
        $AD_printdata{'RESULT'}{'user'}{'student'}{'COUNT'}=$max_user;
        my %seen_classes=();
        for( my $index = 0 ; $index < $max_user ; $index++) {
            my $entry = $mesg->entry($index);
            my $line=$entry->get_value('sn').";".
                     $entry->get_value('givenName').";".
                     $entry->get_value('sAMAccountName').";".
                     $entry->get_value('sophomorixFirstPassword').";".
                     $entry->get_value('sophomorixSchoolname').";".
                     $entry->get_value('sophomorixAdminClass').";".
                     $entry->get_value('sophomorixSurnameASCII').";".
                     $entry->get_value('sophomorixFirstnameASCII').";".
                     $entry->get_value('sophomorixRole').";".
                     $entry->get_value('sophomorixCreationDate').";".
                     $entry->get_value('sophomorixUnid').";";
            if (not exists $seen_classes{$entry->get_value('sophomorixAdminClass')}){
                push @{ $AD_printdata{'LIST_BY_sophomorixSchoolname_sophomorixAdminClass'}
		                      {$entry->get_value('sophomorixSchoolname')} },$entry->get_value('sophomorixAdminClass');
                $seen_classes{$entry->get_value('sophomorixAdminClass')}="seen";
		$seen_classes{'ONE'}="seen";
            }
            push @{ $AD_printdata{'LIST_BY_sophomorixAdminClass'}
                                  {$entry->get_value('sophomorixAdminClass')} }, 
                                  $line; 
            push @{ $AD_printdata{'LIST_BY_sophomorixSchoolname'}
                                  {$entry->get_value('sophomorixSchoolname')} }, 
                                  $line; 
            push @{ $AD_printdata{'LIST_BY_sophomorixCreationDate'}{$entry->get_value('sophomorixCreationDate')} }, 
                                  $line;
            # lookup creation
            $AD_printdata{'LOOKUP_BY_sAMAccountName'}{$entry->get_value('sAMAccountName')}=$line;
            $AD_printdata{'LOOKUP_BY_sophomorixAdminClass'}{$entry->get_value('sophomorixAdminClass')}="exists";
        }
    }

    # create list for --back-in-time
    foreach my $date ( keys %{ $AD_printdata{'LIST_BY_sophomorixCreationDate'} } ){
        push @{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} },$date;
    }
    # sort list for --back-in-time (reverse order)
    if ( $#{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} }>0){
        @{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} } = 
            sort{$b cmp $a} @{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} }
    }
    # counter for history
    $AD_printdata{'RESULT'}{'HISTORY'}{'TOTAL'}=$#{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} }+1;
    $AD_printdata{'RESULT'}{'BACK_IN_TIME_MAX'}=$#{ $AD_printdata{'LISTS'}{'sophomorixCreationDate'} };
    return(\%AD_printdata);
}



sub AD_class_fetch {
    my ($ldap,$root_dse,$class,$school,$class_type,$ref_sophomorix_config) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. class7a
    my $school_AD="";
    my $class_search="";  # the option i.e. 'class7*'
    if (defined $school){
        $class_search=&AD_get_name_tokened($class,$school,$class_type);
    } else {
        $class_search=&AD_get_name_tokened($class,"---",$class_type);
    }

    my $filter="(& (objectClass=group) "."(cn=".$class_search.") ".
       "(| ".
       "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'ADMINCLASS'}.")".
       "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'TEACHERCLASS'}.")".
       "(sophomorixType=".$ref_sophomorix_config->{'INI'}{'TYPE'}{'EXTRACLASS'}.")".
       " ) )";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                         );
    my $max_class = $mesg->count; 
    for( my $index = 0 ; $index < $max_class ; $index++) {
        my $entry = $mesg->entry($index);
        $dn=$entry->dn();
        $sam_account=$entry->get_value('sAMAccountName');
	$school_AD = $entry->get_value('sophomorixSchoolname');
    }
    return ($dn,$max_class,$school_AD);
}



sub AD_sophomorix_group_fetch {
    # fetch groups for sophomorix-group
    my ($ldap,$root_dse,$group) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. p_abt3
    my $school_AD="";

    my $filter="(&(objectClass=group)(|(sophomorixType=sophomorix-group)(sophomorixType=printer))(sAMAccountName=".$group."))";
    print "Filter: $filter\n";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                         );
    my $max_group = $mesg->count; 
    for( my $index = 0 ; $index < $max_group ; $index++) {
        my $entry = $mesg->entry($index);
        $dn=$entry->dn();
	$school_AD = $entry->get_value('sophomorixSchoolname');
    }
    print "$dn\n";
    return ($dn,$max_group,$school_AD);
}



sub AD_project_fetch {
    my ($ldap,$root_dse,$pro,$school,$info) = @_;
    my $dn="";
    my $sam_account=""; # the search result i.e. p_abt3
    my $school_AD="";
    my $project="";     # the option i.e. 'p_abt*'
    # projects from ldap
    if (defined $school){
        $project=&AD_get_name_tokened($pro,$school,"project");
    } else {
        $project=&AD_get_name_tokened($pro,"---","project");
    }

    my $filter="(&(objectClass=group)(sophomorixType=project)(cn=".$project."))";
    #print "Filter: $filter\n";
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                         );
    my $max_pro = $mesg->count; 
    for( my $index = 0 ; $index < $max_pro ; $index++) {
        my $entry = $mesg->entry($index);
        $dn=$entry->dn();
        $sam_account=$entry->get_value('sAMAccountName');
	$school_AD = $entry->get_value('sophomorixSchoolname');
    }
    return ($dn,$max_pro,$school_AD);
}



sub AD_dn_fetch_multivalue {
    # get multivalue attribute with dn
    my ($ldap,$root_dse,$dn,$attr_name) = @_;
    my $filter="cn=*";
    my $mesg = $ldap-> search( # perform a search
                       base   => $dn,
                       scope => 'base',
                       filter => $filter,
	               );
    my $entry = $mesg->entry(0);
    my @results = sort $entry->get_value($attr_name);
    return @results;
}



sub AD_rolegroup_update {
    my ($ldap,$root_dse,$root_dns,$ref_sophomorix_config)=@_;
    # fetch system data
    my ($ref_AD_check) = &AD_get_AD_for_check({ldap=>$ldap,
                                               root_dse=>$root_dse,
                                               root_dns=>$root_dns,
                                               admins=>"TRUE",
                                               sophomorix_config=>$ref_sophomorix_config,
                                             });
    foreach my $role (keys %{ $ref_sophomorix_config->{'LOOKUP'}{'ROLES_USER'} }){
        my $rolegroup="role-".$role;
        if (not defined $ref_AD_check->{'LIST_user_by_sophomorixRole'}{$role}{$DevelConf::AD_global_ou}){
            print "Skipping sophomorixRole $role: no users of this role found\n";
            next;
        }
        print "Setting member attribute of rolegroup $rolegroup\n";
        print "  $ref_sophomorix_config->{'LOOKUP'}{'ROLES_USER'}{$role}{'GLOBAL_rolegroup_dn'}\n";
        print "to:\n";
        print Dumper ($ref_AD_check->{'LIST_user_by_sophomorixRole'}{$role}{$DevelConf::AD_global_ou});

        foreach my $user (@{ $ref_AD_check->{'LIST_user_by_sophomorixRole'}{$role}{$DevelConf::AD_global_ou} }){
            &AD_group_addmember({ldap => $ldap,
                                  root_dse => $root_dse,
                                  group => $rolegroup,
                                  addmember => $user,
                                });
        }
        # my $member_count=$#{ $ref_AD_check->{'LIST_dn_by_sophomorixRole'}{$role}{$DevelConf::AD_global_ou} }+1;
        # print "$member_count members in $rolegroup\n";
        # print "\n";
        # my $mesg = $ldap->modify( $ref_sophomorix_config->{'LOOKUP'}{'ROLES_USER'}{$role}{'GLOBAL_rolegroup_dn'},
        #     replace => { 'member' => $ref_AD_check->{'LIST_dn_by_sophomorixRole'}{$role}{$DevelConf::AD_global_ou} } 
        #                         );
        # &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
}



sub AD_group_update {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $dn = $arg_ref->{dn};
    my $type = $arg_ref->{type};
    my $description = $arg_ref->{description};
    my $quota = $arg_ref->{quota};
    my $mail = $arg_ref->{mail};
    my $mailquota = $arg_ref->{mailquota};
    my $addquota = $arg_ref->{addquota};
    my $addmailquota = $arg_ref->{addmailquota};
    my $mailalias = $arg_ref->{mailalias};
    my $maillist = $arg_ref->{maillist};
    # change proxyAddresses (multi-value)
    my $proxy_addresses_set = $arg_ref->{proxy_addresses_set};
    #my $proxy_addresses_add = $arg_ref->{proxy_addresses_add};
    #my $proxy_addresses_remove = $arg_ref->{proxy_addresses_remove};
    #my $proxy_addresses_entry = $arg_ref->{proxy_addresses_entry};
    #
    my $status = $arg_ref->{status};
    my $join = $arg_ref->{join};
    my $hide = $arg_ref->{hide};
    my $school = $arg_ref->{school};
    my $maxmembers = $arg_ref->{maxmembers};
    my $members = $arg_ref->{members};
    my $admins = $arg_ref->{admins};
    my $membergroups = $arg_ref->{membergroups};
    my $admingroups = $arg_ref->{admingroups};
    my $creationdate = $arg_ref->{creationdate};
    my $gidnumber = $arg_ref->{gidnumber};
    my $ref_room_ips = $arg_ref->{sophomorixRoomIPs};
    my $ref_room_macs = $arg_ref->{sophomorixRoomMACs};
    my $ref_room_computers = $arg_ref->{sophomorixRoomComputers};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $sync_members=0;
    
    print "\n";
    &Sophomorix::SophomorixBase::print_title("Updating $dn (start)");
    # description   
    if (defined $description){
        print "   * Setting Description to '$description'\n";
        my $mesg = $ldap->modify($dn,replace => {Description => $description}); 
    }

    # quota OR addquota
    my $quota_attr="";
    my $multiquota=""; # containes quota or addquota
    if (defined $quota){
        $quota_attr="sophomorixQuota";
	$multiquota=$quota;
    }
    if (defined $addquota){
        $quota_attr="sophomorixAddQuota";
	$multiquota=$addquota;
    }
    if (defined $quota and defined $addquota){
	print "\nwrong use of function AD_group_update: quota and addquota at the same time\n\n";
        exit;
    }
    
    if (defined $quota or defined $addquota){
        my %quota_new=(); # save old quota and override with new quota
        my @quota_new=(); # option for ldap modify   
        my @sharelist=(); # list of shares, later uniqified and sorted   
        # work on OLD Quota
        my @quota_old = &AD_dn_fetch_multivalue($ldap,$root_dse,$dn,$quota_attr);
        foreach my $quota_old (@quota_old){
            my ($share,$value,$comment)=split(/:/,$quota_old);
	    # save old values in quota_new
            $quota_new{'QUOTA'}{$share}{'VALUE'}=$value;
            $quota_new{'QUOTA'}{$share}{'COMMENT'}=$comment;
	    push @sharelist, $share;
        }

        # work on NEW Quota, given by option
	my @schoolquota=split(/,/,$multiquota);
	foreach my $schoolquota (@schoolquota){
	    my ($share,$value,$comment)=split(/:/,$schoolquota);
	    if (not exists $ref_sophomorix_config->{'samba'}{'net_conf_list'}{$share}){
                print "\nERROR: SMB-share $share does not exist!\n\n";
		exit;
	    }
            if ($value=~/[^0-9]/ and $value ne "---"){
                print "\nERROR: Quota value $value does not consist ",
                      "of numerals 0-9 or is \"---\"\n\n";
		exit;
	    }
            # overriding quota_new
    	    $quota_new{'QUOTA'}{$share}{'VALUE'}=$value;
            if (not defined $comment){
                $comment="---";
            }
    	    $quota_new{'QUOTA'}{$share}{'COMMENT'}=$comment;
   	    push @sharelist, $share;
	}
        # debug
        #print "OLD: @quota_old\n";
	# print Dumper(%quota_new);
	# print "Sharelist: @sharelist\n";
	
        # prepare ldap modify list
	@sharelist = uniq(@sharelist);
	@sharelist = sort(@sharelist);
	foreach my $share (@sharelist){
            if ($quota_new{'QUOTA'}{$share}{'VALUE'} eq "---" and 
                $share ne $ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'} and
                $share ne $school){
                # do nothing
	    } else {
		push @quota_new, $share.":".$quota_new{'QUOTA'}{$share}{'VALUE'}.
                                        ":".$quota_new{'QUOTA'}{$share}{'COMMENT'}.
                                        ":";


	    }
	}
	print "   * Setting $quota_attr to: @quota_new\n";
        my $mesg = $ldap->modify($dn,replace => { $quota_attr => \@quota_new }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }
    
    # mail   
    if (defined $mail){
        print "   * Setting mail to '$mail'\n";
        my $mesg = $ldap->modify($dn,replace => {mail => $mail}); 
    }
    # mailquota   
    if (defined $mailquota){
        my ($value,$comment)=split(/:/,$mailquota);
        if (not defined $comment){
            $comment="---";
        }
        my $mailquota_new=$value.":".$comment.":";
        print "   * Setting sophomorixMailquota to $mailquota_new\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMailquota => $mailquota_new}); 
    }
    # addmailquota   
    if (defined $addmailquota){
        my ($value,$comment)=split(/:/,$addmailquota);
        if (not defined $comment){
            $comment="---";
        }
        my $addmailquota_new=$value.":".$comment.":";
        print "   * Setting sophomorixAddmailquota to $addmailquota_new\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixAddmailquota => $addmailquota_new}); 
    }
    # mailalias   
    if (defined $mailalias){
        if($mailalias==0){$mailalias="FALSE"}else{$mailalias="TRUE"};
        print "   * Setting sophomorixMailalias to $mailalias\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMailalias => $mailalias}); 
    }
    # maillist   
    if (defined $maillist){
        if($maillist==0){$maillist="FALSE"}else{$maillist="TRUE"};
        print "   * Setting sophomorixMaillist to $maillist\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMaillist => $maillist}); 
    }
    # proxyAddresses
    if (defined $proxy_addresses_set){
        my @proxy_addresses=split(/,/,$proxy_addresses_set);
        @proxy_addresses = reverse @proxy_addresses;
        print "   * Setting proxyAddresses to: @proxy_addresses\n";
        my $mesg = $ldap->modify($dn,replace => {'proxyAddresses' => \@proxy_addresses }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
    }

    # status   
    if (defined $status){
        print "   * Setting sophomorixStatus to $status\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixStatus => $status}); 
    }
    # joinable
    if (defined $join){
        if($join==0){$join="FALSE"}else{$join="TRUE"};
        print "   * Setting sophomorixJoinable to $join\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixJoinable => $join}); 
    }
    # hide
    if (defined $hide){
        if($hide==0){$hide="FALSE"}else{$hide="TRUE"};
        print "   * Setting sophomorixHidden to $hide\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixHidden => $hide}); 
    }
    # maxmembers   
    if (defined $maxmembers){
        print "   * Setting sophomorixMaxMembers to $maxmembers\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixMaxMembers => $maxmembers}); 
    }
    # creationdate   
    if (defined $creationdate){
        print "   * Setting sophomorixCreationDate to $creationdate\n";
        my $mesg = $ldap->modify($dn,replace => {sophomorixCreationDate => $creationdate}); 
    }
    # gidnumber   
    if (defined $gidnumber){
        print "   * Setting gidNumber to $gidnumber\n";
        my $mesg = $ldap->modify($dn,replace => {gidNumber => $gidnumber}); 
    }
    # members   
    if (defined $members){
        my @members=split(/,/,$members);
        @members = reverse @members;
        @members = &_keep_object_class_only($ldap,$root_dse,"user",@members);
        print "   * Setting sophomorixMembers to: @members\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixMembers' => \@members }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # admins
    if (defined $admins){
        my @admins=split(/,/,$admins);
        @admins = reverse @admins;
        @admins = &_keep_object_class_only($ldap,$root_dse,"user",@admins);
        print "   * Setting sophomorixAdmins to: @admins\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixAdmins' => \@admins }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # membergroups   
    if (defined $membergroups){
        my @membergroups=split(/,/,$membergroups);
        @membergroups = reverse @membergroups;
        @membergroups = &_keep_object_class_only($ldap,$root_dse,"group",@membergroups);
        print "   * Setting sophomorixMemberGroups to: @membergroups\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixMemberGroups' => \@membergroups }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }
    # admingroups
    if (defined $admingroups){
        my @admingroups=split(/,/,$admingroups);
        @admingroups = reverse @admingroups;
        @admingroups = &_keep_object_class_only($ldap,$root_dse,"group",@admingroups);
        print "   * Setting sophomorixAdmingroups to: @admingroups\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixAdmingroups' => \@admingroups }); 
        &AD_debug_logdump($mesg,2,(caller(0))[3]);
        $sync_members++;
    }

    # room stuff
    if (defined $ref_room_ips){
        print "   * Setting sophomorixRoomIPs to: @{ $ref_room_ips }\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixRoomIPs' => $ref_room_ips }); 
    }

    if (defined $ref_room_macs){
        print "   * Setting sophomorixRoomMACs to: @{ $ref_room_macs }\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixRoomMACs' => $ref_room_macs }); 
    }

    if (defined $ref_room_computers){
        print "   * Setting sophomorixRoomComputers to: @{ $ref_room_computers }\n";
        my $mesg = $ldap->modify($dn,replace => {'sophomorixRoomComputers' => $ref_room_computers }); 
    }

    # sync memberships if necessary
    if ($sync_members>0){
        &AD_project_sync_members($ldap,$root_dse,$dn,$ref_sophomorix_config);
    }
    &Sophomorix::SophomorixBase::print_title("Updating $dn (end)");
    print "\n";
 }



sub AD_project_sync_members {
    my ($ldap,$root_dse,$dn,$ref_sophomorix_config) = @_;
    print "\n";
    &Sophomorix::SophomorixBase::print_title("Sync member: $dn (start)");
    my $filter="cn=*";
    my $mesg = $ldap-> search( # perform a search
                       base   => $dn,
                       scope => 'base',
                       filter => $filter,
                             );
    my $max_pro = $mesg->count;
    if ($max_pro==1){
        my $entry = $mesg->entry(0);
        my $cn = $entry->get_value('cn');
        print "     * $max_pro single project found: $cn\n";

        ##################################################
        # fetch target memberships
        my %target=();
        my @admins = sort $entry->get_value('sophomorixAdmins');
        foreach my $admin (@admins){
            $target{$admin}="admin";
        }
        my @members = sort $entry->get_value('sophomorixMembers');
        foreach my $member (@members){
            $target{$member}="member";
        }
        my @admingroups = sort $entry->get_value('sophomorixAdminGroups');
        foreach my $admingroup (@admingroups){
            $target{$admingroup}="admingroup";
        }
        my @membergroups = sort $entry->get_value('sophomorixMemberGroups');
        foreach my $membergroup (@membergroups){
            $target{$membergroup}="membergroup";
        }
        # print target memberships
        if($Conf::log_level>=3){
            print "   * Target memberships:\n";
            foreach my $key (keys %target) {
                my $value = $target{$key};
                printf "      %-15s -> %-20s\n",$key,$value;
            }
        }

        ##################################################
        # fetch actual memberships
        my %actual=();
        my @ac_members = sort $entry->get_value('member');
        foreach my $member (@ac_members){
            # retrieving object class
            my $filter="cn=*";
            my $mesg2 = $ldap-> search( # perform a search
                                base   => $member,
                                scope => 'base',
                                filter => $filter,
                                      );
            my $max_pro = $mesg2->count;
            my $entry = $mesg2->entry(0);
            my $cn = $entry->get_value('cn');
            my @object_classes = $entry->get_value('objectClass');
            foreach my $object_class (@object_classes){
                if ($object_class eq "group"){
                    $actual{$cn}="group";
                    last;
                } elsif ($object_class eq "user"){
                    $actual{$cn}="user";
                    last;
                }
            }
        }
        # print actual memberships
        if($Conf::log_level>=3){
            print "   * Actual memberships:\n";
            foreach my $key (keys %actual) {
                my $value = $actual{$key};
                printf "      %-15s -> %-20s\n",$key,$value;
            }
        }

        ##################################################
        # sync memberships
        # Deleting
        foreach my $key (keys %actual) {
            my $value = $actual{$key};
            if (exists $target{$key}){
                # OK
            } else {
                #print "Deleting $actual{$key} $key as member from $cn\n";
                if ($actual{$key} eq "user"){
                    &AD_group_removemember({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $cn,
                                            removemember => $key,
                                            sophomorix_config=>$ref_sophomorix_config,
                                          });   
                } elsif ($actual{$key} eq "group"){
                    &AD_group_removemember({ldap => $ldap,
                                            root_dse => $root_dse, 
                                            group => $cn,
                                            removegroup => $key,
                                            sophomorix_config=>$ref_sophomorix_config,
                                          });   
                }
            }
        }

        # Adding
        foreach my $key (keys %target) {
            my $value = $target{$key};
            if (exists $actual{$key}){
                # OK
            } else {
                my $type="";
                if ($target{$key} eq "admin" or $target{$key} eq "member"){
                    #print "Adding user $key as member to $cn\n";
                    &AD_group_addmember({ldap => $ldap,
                                         root_dse => $root_dse, 
                                         group => $cn,
                                         addmember => $key,
                                        }); 
                } elsif ($target{$key} eq "admingroup" or $target{$key} eq "membergroup"){
                    #print "Adding group $key as member to $cn\n";
                    &AD_group_addmember({ldap => $ldap,
                                         root_dse => $root_dse, 
                                         group => $cn,
                                         addgroup => $key,
                                        }); 
                }
            }
        }
    } else {
        print "ERROR: Sync failed: $max_pro projects found\n";
    }
    &Sophomorix::SophomorixBase::print_title("Sync member: $dn (end)");
    print "\n";
}



sub AD_group_list {
    # show==0 return list of project dn's
    my ($ldap,$root_dse,$type,$show) = @_;
    my $filter;
    if ($type eq "project"){
        $filter="(&(objectClass=group)(sophomorixType=project))";
    } elsif ($type eq "sophomorix-group"){
        $filter="(&(objectClass=group)(sophomorixType=sophomorix-group))";
    } elsif ($type eq "adminclass"){
        $filter="(&(objectClass=group)(sophomorixType=adminclass))";
    }
    my $sort = Net::LDAP::Control::Sort->new(order => "sAMAccountName");
    if($Conf::log_level>=2){
        print "Filter: $filter\n";
    }
    my $mesg = $ldap->search( # perform a search
                   base   => $root_dse,
                   scope => 'sub',
                   filter => $filter,
                   control => [ $sort ]
                         );
    my $max_pro = $mesg->count;
    my @projects_dn=();
    for( my $index = 0 ; $index < $max_pro ; $index++) {
        my $entry = $mesg->entry($index);
        $dn=$entry->dn();
        push @projects_dn,$dn;   
    }
    @projects_dn = sort @projects_dn;
    return @projects_dn;
}



sub AD_object_move {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $dn = $arg_ref->{dn};
    my $target_branch = $arg_ref->{target_branch};
    my $rdn = $arg_ref->{rdn};

    &Sophomorix::SophomorixBase::print_title("Move object in tree:");
    print "   * DN:     $dn\n";
    print "   * Target: $target_branch\n";

    # create target branch
    my $result = $ldap->add($target_branch,attr => ['objectClass' => ['top', 'organizationalUnit']]);
    &AD_debug_logdump($result,2,(caller(0))[3]);
    # move object
    $result = $ldap->moddn ( $dn,
                        newrdn => $rdn,
                        deleteoldrdn => '1',
                        newsuperior => $target_branch
                               );
    &AD_debug_logdump($result,2,(caller(0))[3]);
}




sub AD_group_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $group = $arg_ref->{group};
    my $group_basename = $arg_ref->{group_basename};
    my $description = $arg_ref->{description};
    my $school = $arg_ref->{school};
    my $type = $arg_ref->{type};
    my $status = $arg_ref->{status};
    my $joinable = $arg_ref->{joinable};
    my $gidnumber_migrate = $arg_ref->{gidnumber_migrate};
    my $dn_wish = $arg_ref->{dn_wish};
    my $cn = $arg_ref->{cn};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $file = $arg_ref->{file};
    my $sub_ou = $arg_ref->{sub_ou};
    my $ref_room_ips = $arg_ref->{sophomorixRoomIPs};
    my $ref_room_macs = $arg_ref->{sophomorixRoomMACs};
    my $ref_room_computers = $arg_ref->{sophomorixRoomComputers};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    if (not defined $joinable){
        $joinable="FALSE";    
    }
    if (not defined $cn){
        $cn=$group;    
    }
    if (not defined $file){
        $file="none";    
    }

    if (exists $ref_sophomorix_config->{'RUNTIME'}{'GROUPS_CREATED'}{$group}){
        print "   * $group already created RUNTIME\n";
        #print Dumper ($ref_sophomorix_config->{'RUNTIME'});
        return;
    } else {
        print "   * $group must be created RUNTIME\n";
        #print Dumper ($ref_sophomorix_config->{'RUNTIME'});
    }

    print "\n";
    &Sophomorix::SophomorixBase::print_title("Creating group $group of type $type (begin):");

    $school=&AD_get_schoolname($school);

    my $group_ou;
    if (defined $sub_ou){
        $group_ou=$sub_ou;
    } elsif ($file eq "none"){
        $group_ou=$ref_sophomorix_config->{'INI'}{'OU'}{'AD_management_ou'};
    } elsif ($group_basename eq $ref_sophomorix_config->{'INI'}{'VARS'}{'ATTIC_GROUP_BASENAME'}){
        # attic
        $group_ou="OU=\@\@FIELD_1\@\@,".$ref_sophomorix_config->{'INI'}{'OU'}{'AD_student_ou'};
    } else {
        $group_ou=$ref_sophomorix_config->{'FILES'}{'USER_FILE'}{$file}{'GROUP_OU'};
    }
    $group_ou=~s/\@\@FIELD_1\@\@/$group_basename/g; 

    my $target_branch;
    if ($school eq "global"){
         $target_branch = $group_ou.",OU=GLOBAL,".$root_dse;
    } else {
         $target_branch = $group_ou.",OU=".$school.",".$DevelConf::AD_schools_ou.",".$root_dse;
    }

    my $dn="CN=".$group.",".$target_branch;
    my $mail = $group."\@".$root_dns;
    my $maildomain_key;
            if ($school eq $DevelConf::name_default_school){
                $maildomain_key=$type;
            } else {
                $maildomain_key=$school."-".$type;
            }
    if (exists $ref_sophomorix_config->{'TYPES'}{$maildomain_key}{'MAILDOMAIN'}){
        if ($ref_sophomorix_config->{'TYPES'}{$maildomain_key}{'MAILDOMAIN'} ne ""){
            $mail=$group."\@".
                $ref_sophomorix_config->{'TYPES'}{$maildomain_key}{'MAILDOMAIN'};
	}
    }

    if (defined $dn_wish){
        # override DN
        $dn=$dn_wish;
        # override target so it fits to dn
        my ($unused,@used)=split(/,/,$dn);
        $target_branch=join(",",@used);
    }

    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"group",$group);
    if ($count==0){
        # adding the group
        if (not defined $gidnumber_migrate){
            $gidnumber_migrate="---";
        }
        print "   DN:              $dn\n";
        print "   Target:          $target_branch\n";
        print "   Group:           $group\n";
        print "   Unix-gidNumber:  $gidnumber_migrate\n";
        print "   Type:            $type\n";
        print "   Joinable:        $joinable\n";
        print "   Creationdate:    $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}\n";
        print "   Description:     $description\n";
        print "   File:            $file\n";
        print "   School:          $school\n";

        # make sure target ou exists
        my $target = $ldap->add($target_branch,attr => ['objectClass' => ['top', 'organizationalUnit']]);
        &AD_debug_logdump($target,2,(caller(0))[3]);
        # Create object
	my $result;
	if ($type eq "project"){
            my $add_array = [
                objectClass => ['top','group'],
                cn   => $cn,
                description => $description,
                sAMAccountName => $group,
                mail => $mail,
                sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                sophomorixType => $type, 
                sophomorixSchoolname => $school, 
                sophomorixStatus => $status,
                sophomorixAddQuota => ["$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:",
                                       "$school:---:---:"],
                sophomorixAddMailQuota => ["---:---:"],
                sophomorixQuota => "---",
                sophomorixMailQuota => "---",
                sophomorixMaxMembers => "0",
                sophomorixMailAlias => "FALSE",
                sophomorixMailList => "FALSE",
                sophomorixJoinable => $joinable,
                sophomorixHidden => "FALSE",
                    ];
            if (defined $gidnumber_migrate and $gidnumber_migrate ne "---"){
                my $intrinsic_string="MIGRATION gidNumber: ".$gidnumber_migrate;
                push @{ $add_array }, "sophomorixIntrinsic1", $intrinsic_string;
            }

            # do it
            $result = $ldap->add( $dn, attr => [@{ $add_array }]);
            &AD_debug_logdump($result,2,(caller(0))[3]);
	} elsif ($type eq "adminclass" or $type eq "teacherclass" or $type eq "extraclass"){
            my $add_array = [
                objectClass => ['top','group'],
                cn   => $cn,
                description => $description,
                sAMAccountName => $group,
                mail => $mail,
                sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                sophomorixType => $type, 
                sophomorixSchoolname => $school, 
                sophomorixStatus => $status,
                sophomorixAddQuota => ["---"],
                sophomorixAddMailQuota => "---",
                sophomorixQuota => ["$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:",
                                    "$school:---:---:"],
                sophomorixMailQuota => "---:---:",
                sophomorixMaxMembers => "0",
                sophomorixMailAlias => "FALSE",
                sophomorixMailList => "FALSE",
                sophomorixJoinable => $joinable,
                sophomorixHidden => "FALSE",
                    ];
            if (defined $gidnumber_migrate and $gidnumber_migrate ne "---"){
                my $intrinsic_string="MIGRATION gidNumber: ".$gidnumber_migrate;
                push @{ $add_array }, "sophomorixIntrinsic1", $intrinsic_string;
            }

            # do it
            $result = $ldap->add( $dn, attr => [@{ $add_array }]);
            &AD_debug_logdump($result,2,(caller(0))[3]);
	} elsif ($type eq "sophomorix-group"){
            my $add_array = [
                objectClass => ['top','group'],
                cn   => $cn,
                description => $description,
                sAMAccountName => $group,
                mail => $mail,
                sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                sophomorixType => $type, 
                sophomorixSchoolname => $school, 
                sophomorixStatus => $status,
                sophomorixAddQuota => ["$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:",
                                       "$school:---:---:"],
                sophomorixAddMailQuota => ["---:---:"],
                sophomorixQuota => "---",
                sophomorixMailQuota => "---",
                sophomorixMaxMembers => "0",
                sophomorixMailAlias => "FALSE",
                sophomorixMailList => "FALSE",
                sophomorixJoinable => $joinable,
                sophomorixHidden => "FALSE",
                    ];
            if (defined $gidnumber_migrate and $gidnumber_migrate ne "---"){
                my $intrinsic_string="MIGRATION gidNumber: ".$gidnumber_migrate;
                push @{ $add_array }, "sophomorixIntrinsic1", $intrinsic_string;
            }

            # do it
            $result = $ldap->add( $dn, attr => [@{ $add_array }]);
            &AD_debug_logdump($result,2,(caller(0))[3]);
	} elsif ($type eq $ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}){
            my $add_array = [
                objectClass => ['top','group'],
                cn   => $cn,
                description => $description,
                sAMAccountName => $group,
                mail => $mail,
                sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                sophomorixType => $type, 
                sophomorixSchoolname => $school, 
                sophomorixStatus => $status,
                sophomorixAddQuota => ["$ref_sophomorix_config->{'INI'}{'VARS'}{'GLOBALSHARENAME'}:---:---:",
                                       "$school:---:---:"],
                sophomorixAddMailQuota => ["---:---:"],
                sophomorixQuota => "---",
                sophomorixMailQuota => "---",
                sophomorixMaxMembers => "0",
                sophomorixMailAlias => "FALSE",
                sophomorixMailList => "FALSE",
                sophomorixJoinable => $joinable,
                sophomorixHidden => "FALSE",
                    ];
            if (defined $gidnumber_migrate and $gidnumber_migrate ne "---"){
                my $intrinsic_string="MIGRATION gidNumber: ".$gidnumber_migrate;
                push @{ $add_array }, "sophomorixIntrinsic1", $intrinsic_string;
            }

            # do it
            $result = $ldap->add( $dn, attr => [@{ $add_array }]);
            &AD_debug_logdump($result,2,(caller(0))[3]);
	} elsif ($type eq "room"){
            my $add_array = [
                objectClass => ['top','group'],
                cn   => $cn,
                description => $description,
                sAMAccountName => $group,
                mail => $mail,
                sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                sophomorixType => $type, 
                sophomorixSchoolname => $school, 
                sophomorixStatus => $status,
                sophomorixAddQuota => ["---"],
                sophomorixAddMailQuota => "---",
                sophomorixQuota => ["---"],
                sophomorixMailQuota => "---",
                sophomorixMaxMembers => "0",
                sophomorixMailAlias => "FALSE",
                sophomorixMailList => "FALSE",
                sophomorixJoinable => $joinable,
                sophomorixHidden => "FALSE",
                sophomorixRoomIPs => $ref_room_ips,
                sophomorixRoomMACs => $ref_room_macs,
                sophomorixRoomComputers => $ref_room_computers,
                    ];
            if (defined $gidnumber_migrate and $gidnumber_migrate ne "---"){
                my $intrinsic_string="MIGRATION gidNumber: ".$gidnumber_migrate;
                push @{ $add_array }, "sophomorixIntrinsic1", $intrinsic_string;
            }

            # do it
            $result = $ldap->add( $dn, attr => [@{ $add_array }]);
            &AD_debug_logdump($result,2,(caller(0))[3]);
        } else {
            my $add_array = [
                objectClass => ['top','group'],
                cn   => $cn,
                description => $description,
                sAMAccountName => $group,
                mail => $mail,
                sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                sophomorixType => $type, 
                sophomorixSchoolname => $school, 
                sophomorixStatus => $status,
                sophomorixAddQuota => ["---"],
                sophomorixAddMailQuota => "---",
                sophomorixQuota => ["---"],
                sophomorixMailQuota => "---",
                sophomorixMaxMembers => "0",
                sophomorixMailAlias => "FALSE",
                sophomorixMailList => "FALSE",
                sophomorixJoinable => $joinable,
                sophomorixHidden => "FALSE",
                    ];
            if (defined $gidnumber_migrate and $gidnumber_migrate ne "---"){
                my $intrinsic_string="MIGRATION gidNumber: ".$gidnumber_migrate;
                push @{ $add_array }, "sophomorixIntrinsic1", $intrinsic_string;
            }

            # do it
            $result = $ldap->add( $dn, attr => [@{ $add_array }]);
            &AD_debug_logdump($result,2,(caller(0))[3]);

	}
        if ($result!=0){ # add was succesful
	    # log the addition of a user
            &Sophomorix::SophomorixBase::log_group_add({sAMAccountName=>$group,
                                                   sophomorixType=>$type,
                                                   sophomorixSchoolname=>$school,
                                                   sophomorix_config=>$ref_sophomorix_config,
                                                   sophomorix_result=>$ref_sophomorix_result,
                                                 });
	}
    } else {
        print "   * Group $group exists already ($count results)\n";
    }

    if ($type eq "adminclass" or $type eq "extraclass"){
        # a group like 7a, 7b
        #print "Student class of the school: $group\n";
        my $token_students=&AD_get_name_tokened($DevelConf::student,$school,"adminclass");
  
        if ($token_students ne $group){ # do not add group to itself
            # add the group to <token>-students
            &AD_group_addmember({ldap => $ldap,
                                 root_dse => $root_dse, 
                                 group => $token_students,
                                 addgroup => $group,
                               });
        }
        # add group <token>-students to all-students
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'INI'}{'VARS'}{'HIERARCHY_PREFIX'}."-".$DevelConf::student,
                             addgroup => $token_students,
                           });
        if ($type eq "adminclass"){
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.adminclass",
                                   school=>$school,
                                   adminclass=>$group,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        } elsif ($type eq "extraclass") {
            &AD_repdir_using_file({root_dns=>$root_dns,
                                   repdir_file=>"repdir.extraclass",
                                   school=>$school,
                                   adminclass=>$group,
                                   smb_admin_pass=>$smb_admin_pass,
                                   sophomorix_config=>$ref_sophomorix_config,
                                   sophomorix_result=>$ref_sophomorix_result,
                                 });
        }
    } elsif ($type eq "teacherclass"){
        # add <token>-teachers to all-teachers
        &AD_group_addmember({ldap => $ldap,
                             root_dse => $root_dse, 
                             group => $ref_sophomorix_config->{'INI'}{'VARS'}{'HIERARCHY_PREFIX'}."-".$DevelConf::teacher,
                             addgroup => $group,
                           });
        # not needed anymore. is provided by school
        #&AD_repdir_using_file({root_dns=>$root_dns,
        #                       repdir_file=>"repdir.teacherclass",
        #                       school=>$school,
        #                       teacherclass=>$group,
        #                       smb_admin_pass=>$smb_admin_pass,
        #                       sophomorix_config=>$ref_sophomorix_config,
        #                       sophomorix_result=>$ref_sophomorix_result,
        #                     });
    } elsif ($type eq "room"){
        #my $token_examaccounts=&AD_get_name_tokened($DevelConf::examaccount,$school,"examaccount");
        ## add the room to <token>-examaccounts
        #&AD_group_addmember({ldap => $ldap,
        #                     root_dse => $root_dse, 
        #                     group => $token_examaccounts,
        #                     addgroup => $group,
        #                   });
        ## add group <token>-examaccounts to all-examaccounts
        #&AD_group_addmember({ldap => $ldap,
        #                     root_dse => $root_dse, 
        #                     group => $ref_sophomorix_config->{'INI'}{'VARS'}{'HIERARCHY_PREFIX'}."-".$DevelConf::examaccount,
        #                     addgroup => $token_examaccounts,
        #                   });
    } elsif ($type eq "project"){
        &AD_repdir_using_file({root_dns=>$root_dns,
                               repdir_file=>"repdir.project",
                               school=>$school,
                               project=>$group,
                               smb_admin_pass=>$smb_admin_pass,
                               sophomorix_config=>$ref_sophomorix_config,
                               sophomorix_result=>$ref_sophomorix_result,
                             });
    } elsif ($type eq $ref_sophomorix_config->{'INI'}{'TYPE'}{'DGR'}){
        # nothing to do so far
    }
    &Sophomorix::SophomorixBase::print_title("Creating group $group of type $type (end)");
    print "\n";
    # remember the group in RUNTIME hash
    $ref_sophomorix_config->{'RUNTIME'}{'GROUPS_CREATED'}{$group}="created by AD_group_create RUNTIME";
    return;
}



sub AD_group_addmember {
    # requires token-group as groupname
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $group = $arg_ref->{group};
    my $adduser = $arg_ref->{addmember};
    my $addgroup = $arg_ref->{addgroup};
    my ($count_group,$dn_exist_group,$cn_exist_group,$type)=&AD_object_search($ldap,$root_dse,"group",$group);

    &Sophomorix::SophomorixBase::print_title("Adding member to $group:");
    if ($count_group==0){
        # group does not exist -> exit with warning
        print "   * WARNING: Group $group nonexisting ($count_group results)\n";
        return;
    } elsif ($count_group==1){
        print "   * Group $group exists ($count_group results)\n";

    }

    if (defined $adduser){
        my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$adduser);
        if ($count > 0){
            print "   * User $adduser exists ($count results)\n";
            print "   * Adding user $adduser to group $group\n";
            my $mesg = $ldap->modify( $dn_exist_group,
     	         	      add => {
                                  member => $dn_exist,
                                     }
                                    );
            &AD_debug_logdump($mesg,2,(caller(0))[3]);
            return;
	} else {
            # user does not exist -> exit with warning
            print "   * WARNING: User $adduser nonexisting ($count results)\n";
            return;
        }
    } elsif (defined $addgroup){
        print "   * Adding group $addgroup to $group\n";
        my ($count_group,$dn_exist_addgroup,$cn_exist_addgroup)=&AD_object_search($ldap,$root_dse,"group",$addgroup);
        if ($count_group > 0){
            print "   * Group $addgroup exists ($count_group results)\n";
            my $mesg = $ldap->modify( $dn_exist_group,
     	  	                  add => {
                                  member => $dn_exist_addgroup,
                                  }
                              );
            &AD_debug_logdump($mesg,2,(caller(0))[3]);
            return;
        }
    } else {
        return;
    }
}



sub AD_group_addmember_management {
    # requires token-group as groupname
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $group = $arg_ref->{group};
    my $addmember = $arg_ref->{addmember};

    # testing if user can be added
    # ?????? missing

    &AD_group_addmember({ldap => $ldap,
                         root_dse => $root_dse, 
                         group => $group,
                         addmember => $addmember,
                            }); 
}



sub AD_group_removemember {
    # requires token-group as groupname
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $group = $arg_ref->{group};
    my $removeuser = $arg_ref->{removemember};
    my $removegroup = $arg_ref->{removegroup};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};

    &Sophomorix::SophomorixBase::print_title("Removing member from $group:");

    my ($count_group,$dn_exist_group,$cn_exist_group)=&AD_object_search($ldap,$root_dse,"group",$group);
    if ($count_group==0){
        # group does not exist -> create group
        print "   * WARNING: Group $group nonexisting ($count_group results)\n";
        return;
    }

    if (defined $removeuser){
        my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$removeuser);
        if ($count > 0){
            print "   * User $removeuser exists ($count results)\n";
            print "   * Removing user $removeuser from group $group\n";
            my $mesg = $ldap->modify( $dn_exist_group,
	  	                  delete => {
                                  member => $dn_exist,
                                  }
                              );
            return;
        } else {
            # user does not exist -> exit with warning
            print "   * WARNING: User $removeuser nonexisting ($count results)\n";
            return;
        }
    } elsif (defined $removegroup){
        if (not exists $ref_sophomorix_config->{'INI'}{'SYNC_MEMBER'}{'KEEPGROUP_LOOKUP'}{$removegroup}){
            print "   * Removing group $removegroup from $group\n";
            my ($count_group,$dn_exist_removegroup,$cn_exist_removegroup)=&AD_object_search($ldap,$root_dse,"group",$removegroup);
            if ($count_group > 0){
                print "   * Group $removegroup exists ($count_group results)\n";
                my $mesg = $ldap->modify( $dn_exist_group,
     	                          delete => {
                                  member => $dn_exist_removegroup,
                                });
                &AD_debug_logdump($mesg,2,(caller(0))[3]);
                return;
            }
	} else {
            print "   * NOT Removing group $removegroup from $group (sophomorix.ini: SYNC_MEMBER -> KEEPGROUP)\n";
        }
    } else {
        return;
    }
}





sub AD_debug_logdump {
    # dumping ldap message object in loglevels
    my ($message,$level,$text) = @_;
    my $return=-1;
    my $string=$message->error;
    if ($string=~/.*: Success/ or $string eq "Success"){
        # ok
        $return=1;
    } elsif ($string=~/Entry .* already exists/){
        $return=2;
        # not so bad, just display it
        #print "         * OK: $string\n";
    } elsif ($string=~/Attribute member already exists for target/){
        # not so bad, just display it
        #print "         * OK: $string\n";
        $return=3;
    } else {
        # bad error
        $return=0;
        print "\nERROR in $text:\n";
        print "   $string\n\n";
        if($Conf::log_level>=$level){
            if ( $message->code) { # 0: no error
                print "   Debug info from server($text):\n";
                print Dumper(\$message);
            }
        }
    }
    return $return;
}



sub AD_login_test {
    # return 0: success for all tests
    # return -1: no firstpassword found
    # return >0: Error code of smbclient command (sum of all tests)
    my ($ldap,$root_dse,$dn,$password_option)=@_;
    my $filter="(cn=*)";
    my $mesg = $ldap->search(
                      base   => $dn,
                      scope => 'base',
                      filter => $filter,
                      attr => ['sophomorixFirstPassword',
                               'sophomorixExamMode',
                               'sophomorixStatus',
                               'sophomorixRole',
                               'userAccountControl']
                            );
    my $entry = $mesg->entry(0);
    my $firstpassword = $entry->get_value('sophomorixFirstPassword');
    my $testpassword=$firstpassword;
    my $exammode = $entry->get_value('sophomorixExamMode');
    my $status = $entry->get_value('sophomorixStatus');
    my $role = $entry->get_value('sophomorixRole');
    my $user_account_control = $entry->get_value('userAccountControl');
    my $sam_account = $entry->get_value('sAMAccountName');

    # password usage
    if (defined $password_option and $password_option ne ""){
        # use password given by option a password
	$testpassword=$password_option;
    } elsif ($testpassword eq "---" and -e "/etc/linuxmuster/.secret/$sam_account"){
        print "   * Trying to fetch password from .secret/$sam_account\n";
        $testpassword = `cat /etc/linuxmuster/.secret/$sam_account`;
    }
    if (not defined $testpassword){
        # no password found to test
        return (-1,"","no password found to test","no password found to test");
    }
    #my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
    #            " -L localhost --user=$sam_account%'$testpassword' > /dev/null 2>&1 ";
    #print "   # $command\n";
    #my $result=system($command);
    if ($testpassword eq "---"){
        print "   * $sam_account($status,$user_account_control,$exammode):".
              " No password test possible (Password: $testpassword)\n";
        return (2,$testpassword,"no password found to test","no password found to test");
    } elsif ( $exammode ne "---" and $role ne "examuser"){
        # this is a disabled account because of exammode
        print "   * $sam_account ($status,$user_account_control,$exammode):".
              " No password test possible ($sam_account is in ExamMode/disabled)\n";
        return (2,$testpassword,"not tested","not tested");
    } else {
        # exammode account or normal account (not in exammode)
        # pam login
        my $command1="wbinfo --pam-logon=$sam_account%'$testpassword' > /dev/null 2>&1 ";
        print "   # $command1\n";
        my $result1=system($command1);

        # kerberos login
        my $command2="wbinfo --krb5auth=$sam_account%'$testpassword' > /dev/null 2>&1 ";
        print "   # $command2\n";
        my $result2=system($command2);
        my $result=$result1+$result2;
        return ($result,$testpassword,$result1,$result2);
    }
}




sub AD_examuser_create {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $subdir = $arg_ref->{subdir};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    &Sophomorix::SophomorixBase::print_title("Creating examuser for user: $participant (start)");
    # get data from (non-exam-)user
    my ($firstname_utf8_AD,
        $lastname_utf8_AD,
        $adminclass_AD,
        $existing_AD,
        $exammode_AD,
        $role_AD,
        $home_directory_AD,
        $user_account_control_AD,
        $toleration_date_AD,
        $deactivation_date_AD,
        $school_AD,
        $status_AD,
        $firstpassword_AD,
        $unid_AD,
        $firstname_ASCII_AD,
        $lastname_ASCII_AD,
        $firstname_initial_AD,
        $lastname_initial_AD,
        $user_token_AD,
        )=&AD_get_user({ldap=>$ldap,
                        root_dse=>$root_dse,
                        root_dns=>$root_dns,
                        user=>$participant,
                      });
    my $display_name = $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_DISPLAYNAME_PREFIX'}." ".
                       $firstname_utf8_AD." ".$lastname_utf8_AD;
    my $examuser=$participant.$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'};
    my $adminclass=$adminclass_AD.$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'ADMINCLASS_POSTFIX'};

    my $uni_password=&_unipwd_from_plainpwd($DevelConf::student_password_default);

    my $prefix=$school_AD;
    if ($school_AD eq $DevelConf::name_default_school){
        # empty token creates error on AD add 
        $prefix="---";
    }
    my $user_principal_name = $examuser."\@".$root_dns;
    my $mail = $examuser."\@".$root_dns;

    # create OU for session
    my $dn_session;
    if ($subdir eq ""){
        # no sub_ou
        $dn_session=$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_OU'}.
                    ",OU=".$school_AD.",OU=SCHOOLS,".$root_dse;
    } else {
        # use subdir as sub_ou 
        $dn_session="OU=".$subdir.",".$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_SUB_OU'}.
                    ",OU=".$school_AD.",OU=SCHOOLS,".$root_dse;
    }

    $ldap->add($dn_session,attr => ['objectClass' => ['top', 'organizationalUnit']]);
    my $dn="CN=".$examuser.",".$dn_session;

    my $file="---";
    my $unid="---";
    my $status=$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_STATUS'};
    my $tolerationdate=$DevelConf::default_date;
    my $deactivationdate=$DevelConf::default_date;
    my ($homedirectory,$unix_home,$unc,$smb_rel_path)=
        &Sophomorix::SophomorixBase::get_homedirectory($root_dns,
                                                       $school_AD,
                                                       $subdir, # groupname is the subdir
                                                       $examuser,
                                                       $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_ROLE'},
                                                       $ref_sophomorix_config);


        print "   DN:                 $dn\n";
        print "   DN(Parent):         $dn_session\n";
        print "   Surname(UTF8):      $lastname_utf8_AD\n";
        print "   Firstname(UTF8):    $firstname_utf8_AD\n";
        print "   School:             $school_AD\n"; # Organisatinal Unit
        print "   Role(User):         $role_AD\n";
        print "   Status:             $status\n";
        print "   Login (check OK):   $examuser\n";
        # sophomorix stuff
        print "   Creationdate:       $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}\n";
        print "   Tolerationdate:     $tolerationdate\n";
        print "   Deactivationdate:   $deactivationdate\n";
        print "   Unid:               $unid\n";
        print "   File:               $file\n";
        print "   Firstpassword:      $DevelConf::student_password_default\n";
        print "   Examuser:           $exammode_AD\n";
        print "   homeDirectory:      $homedirectory\n";
        print "   unixHomeDirectory:  $unix_home\n";

        if ($json>=1){
            # prepare json object
            my %json_progress=();
            $json_progress{'JSONINFO'}="PROGRESS";
            $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDEXAMUSER_PREFIX_EN'}.
                                         " $examuser ($firstname_utf8_AD $lastname_utf8_AD)".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDEXAMUSER_POSTFIX_EN'};
            $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDEXAMUSER_PREFIX_DE'}.
                                         " $examuser ($firstname_utf8_AD $lastname_utf8_AD) ".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'ADDEXAMUSER_POSTFIX_DE'};
            $json_progress{'STEP'}=$user_count;
            $json_progress{'FINAL_STEP'}=$max_user_count;
            # print JSON Object
            &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                              json=>$json,
                                                              sophomorix_config=>$ref_sophomorix_config,
                                                            });
        }
 
    my $role="examuser";
    my $group_type="ouexamusers";

    my $result = $ldap->add( $dn,
                   attr => [
                   sAMAccountName => $examuser,
                   givenName => $firstname_utf8_AD,
                   sn => $lastname_utf8_AD,
                   displayName => [$display_name],
                   userPrincipalName => $user_principal_name,
                   mail => $mail,
                   unicodePwd => $uni_password,
                   homeDrive => "H:",
                   homeDirectory => $homedirectory,
                   unixHomeDirectory => $unix_home,
                   sophomorixExitAdminClass => "unknown", 
                   sophomorixUnid => $unid,
                   sophomorixStatus => $status,
                   sophomorixAdminClass => $adminclass,    
                   sophomorixAdminFile => $file,    
                   sophomorixFirstPassword => "---", 
                   sophomorixFirstnameASCII => $firstname_ASCII_AD,
                   sophomorixSurnameASCII  => $lastname_ASCII_AD,
                   sophomorixBirthdate  => "01.01.1970",
                   sophomorixRole => $role,
                   sophomorixUserToken => $user_token_AD,
                   sophomorixFirstnameInitial => $firstname_initial_AD,
                   sophomorixSurnameInitial => $lastname_initial_AD,
                   sophomorixMailQuota=>"---:---:",
                   sophomorixMailQuotaCalculated=>$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_MAILQUOTA_CALC'},
                   sophomorixCloudQuotaCalculated=>$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_CLOUDQUOTA_CALC'},
                   sophomorixSchoolPrefix => $prefix,
                   sophomorixSchoolname => $school_AD,
                   sophomorixCreationDate => $ref_sophomorix_config->{'DATE'}{'LOCAL'}{'TIMESTAMP_AD'}, 
                   sophomorixTolerationDate => $tolerationdate, 
                   sophomorixDeactivationDate => $deactivationdate, 
                   sophomorixComment => "created by sophomorix", 
                   sophomorixExamMode => $exammode_AD, 
                   userAccountControl => $DevelConf::default_user_account_control,
                   accountExpires => 0,
                   objectclass => ['top', 'person',
                                     'organizationalPerson',
                                     'user' ],
                           ]
                           );
    &AD_debug_logdump($result,2,(caller(0))[3]);
    # clone the password ???

    my $group_basename="examusers";
    my $exam_group=&AD_get_name_tokened($group_basename,$school_AD,$group_type);
    &AD_group_addmember({ldap => $ldap,
                         root_dse => $root_dse, 
                         group => $exam_group,
                         addmember => $examuser,
                       }); 

    &AD_repdir_using_file({root_dns=>$root_dns,
                           repdir_file=>"repdir.examuser_home",
                           school=>$school_AD,
                           subdir=>$subdir,
                           student_home=>$examuser,
                           smb_admin_pass=>$smb_admin_pass,
                           sophomorix_config=>$ref_sophomorix_config,
                           sophomorix_result=>$ref_sophomorix_result,
                         });
    &Sophomorix::SophomorixBase::print_title("Creating examuser for user: $participant (end)");
}



sub AD_examuser_kill {
    my ($arg_ref) = @_;
    my $ldap = $arg_ref->{ldap};
    my $root_dse = $arg_ref->{root_dse};
    my $root_dns = $arg_ref->{root_dns};
    my $participant = $arg_ref->{participant};
    my $user_count = $arg_ref->{user_count};
    my $max_user_count = $arg_ref->{max_user_count};
    my $smb_admin_pass = $arg_ref->{smb_admin_pass};
    my $json = $arg_ref->{json};
    my $ref_sophomorix_config = $arg_ref->{sophomorix_config};
    my $ref_sophomorix_result = $arg_ref->{sophomorix_result};

    &Sophomorix::SophomorixBase::print_title("Killing examuser of user: $participant");
    my $examuser=$participant.$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'};
    my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,"user",$examuser);

    if ($participant=~/$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'}$/){
        print "WARNING: you must use the account name for --participant",
              " (without $ref_sophomorix_config->{'INI'}{'EXAMMODE'}{'USER_POSTFIX'})\n";
        return;
    } elsif ($count==0){
        print "ERROR: Cannot kill nonexisting examuser $examuser\n";
        return;
    } elsif ($count > 0){
        my ($firstname_utf8_AD,$lastname_utf8_AD,$adminclass_AD,$existing_AD,$exammode_AD,$role_AD,
            $home_directory_AD,$user_account_control_AD,$toleration_date_AD,$deactivation_date_AD,
            $school_AD,$status_AD,$firstpassword_AD,$unid_AD)=
            &AD_get_user({ldap=>$ldap,
                          root_dse=>$root_dse,
                          root_dns=>$root_dns,
                          user=>$examuser,
                        });
        $home_directory_AD=~s/\\/\//g;
        my $smb_home="smb:".$home_directory_AD;

        if ($role_AD ne "examuser"){
            print "Not deleting $examuser beause its role is not examuser";
            return;
	}
        if ($json>=1){
            # prepare json object
            my %json_progress=();
            $json_progress{'JSONINFO'}="PROGRESS";
            $json_progress{'COMMENT_EN'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLEXAMUSER_PREFIX_EN'}.
                                         " $participant".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLEXAMUSER_POSTFIX_EN'};
            $json_progress{'COMMENT_DE'}=$ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLEXAMUSER_PREFIX_DE'}.
                                         " $participant".
                                         $ref_sophomorix_config->{'INI'}{'LANG.PROGRESS'}{'KILLEXAMUSER_POSTFIX_DE'};
            $json_progress{'STEP'}=$user_count;
            $json_progress{'FINAL_STEP'}=$max_user_count;
            # print JSON Object
            &Sophomorix::SophomorixBase::json_progress_print({ref_progress=>\%json_progress,
                                                              json=>$json,
                                                              sophomorix_config=>$ref_sophomorix_config,
                                                            });
        }

        # deleting user
        my $command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SAMBA_TOOL'}.
            " user delete ". $examuser;
        &Sophomorix::SophomorixBase::smb_command($command,$smb_admin_pass);

        my ($smb_server,
            $smb_rel_path)=&Sophomorix::SophomorixBase::smb_share_subpath_from_homedir_attr($home_directory_AD,
                                                                                            $school_AD);
        my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
            " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'******' ".
            $smb_server." -c 'deltree \"$smb_rel_path\";'";
        my $smbclient_return=&Sophomorix::SophomorixBase::smb_command($smbclient_command,$smb_admin_pass);

        # deleting subdir if empty and not 'examusers'-topdir
        my $subdir=$smb_rel_path;
        $subdir=~s/\/$//; # make sure trailing / are gone 
        $subdir=~s/\/$examuser$//; # remove <user>-exam

        if ($subdir=~m/$ref_sophomorix_config->{'INI'}{'EXAMMODE'}{USER_SUB_DIR}$/){
            # 'examusers' still needed
            print "Not deleting $subdir (still needed)\n";
        } else {
            # deleting subdir
            my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
                " --debuglevel=0 -U ".$DevelConf::sophomorix_file_admin."%'******' ".
                $smb_server." -c 'rmdir \"$subdir\";'";

            my $smbclient_return=&Sophomorix::SophomorixBase::smb_command($smbclient_command,$smb_admin_pass);
        }
        return;
    } else {
        print "   * User $examuser nonexisting ($count results)\n";
        return;
    }
}



sub AD_smbclient_testfile {
    # tests if a file exists on a share
    my ($root_dns,$smb_admin_pass,$share,$testfile,$ref_sophomorix_config,$ref_schools)=@_;
    my $file_exists=0;
    my $smbclient_command=$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCLIENT'}.
        " -U ".$DevelConf::sophomorix_file_admin."%'".$smb_admin_pass."'".
        " //$root_dns/$share -c 'ls'";
    my $stdout=`$smbclient_command 2> /dev/null`;
    my $return=${^CHILD_ERROR_NATIVE}; # return of value of last command
    my @lines=split(/\n/,$stdout);
    foreach my $line (@lines){
        my ($unused,$file,@unused)=split(/\s+/,$line);
	if (defined $file){
	    if ($file eq $testfile){
		$file_exists=1;
		last;
	    }
	}
    }
    
    if ($file_exists==1){
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSER'}="TRUE";
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSERDISPLAY'}="OK";
    }  else {
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSER'}="FALSE";
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'AQUOTAUSERDISPLAY'}="NONEXISTING";
    }
}



sub AD_smbcquotas_queryuser {
    my ($root_dns,$smb_admin_pass,$user,$share,$ref_sophomorix_config)=@_;
    print "Querying smbcquotas of user $user on share $share\n";
    my $smbcquotas_command;
    if ($ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_RELEASE'} eq "18.04"){
	# switch back to old protocol
        $smbcquotas_command=
        $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
        " -mNT1".
        " -U ".$DevelConf::sophomorix_file_admin."%'".
        $smb_admin_pass."'".
	    " -u $user //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/$share";
    } else {
        # ubuntu 22.04 or later expected, no -mNT1 option available
        $smbcquotas_command=
        $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
        " ".$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS_PROTOCOL_OPT'}.
        " -U ".$DevelConf::sophomorix_file_admin."%'".
        $smb_admin_pass."'".
	    " -u $user //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/$share";
    }
    my $display_command=$smbcquotas_command;

    # hide password
    $display_command=~s/$smb_admin_pass/******/;

    # my $string=`$smbcquotas_command`;
    my ($return_value,@out_lines)=&Sophomorix::SophomorixBase::smb_command($smbcquotas_command,$smb_admin_pass);
    if (not $return_value==0){
        return("not available","not available","not available","not available","not available","not available","not available","not available","not available");
    }
    my $string=$out_lines[0];
    $string=~s/ //g; # remove whitespace
    my ($userstring,$quota)=split(/:/,$string);
    my ($used,$soft,$hard)=split(/\//,$quota);

    # used
    my $used_kib;
    $used_kib=$used/1024;
    $used_mib=round(10*$used_kib/1024)/10; # MiB rounded to one decimal

    # soft
    my $soft_kib;
    my $soft_mib;
    if ($soft eq "NOLIMIT"){
        $soft="-1"; 
        $soft_kib="-1"; 
        $soft_mib="-1"; 
    } else {
        $soft_kib=$soft/1024;
        $soft_mib=round(10*$soft_kib/1024)/10; # MiB rounded to one decimal
    }

    # hard
    my $hard_kib;
    my $hard_mib;
    if ($hard eq "NOLIMIT"){
        $hard="-1"; 
        $hard_kib="-1"; 
        $hard_mib="-1"; 
    } else {
        $hard_kib=$hard/1024;
        $hard_mib=round(10*$hard_kib/1024)/10; # MiB rounded to one decimal
    }

    if($Conf::log_level>=3){
        print "$smbcquotas_command\n";
        print "   USER: <$userstring>\n";
        print "   USED: <$used> <$used_kib>KiB\n";
        print "   SOFT: <$soft> <$soft_kib>KiB\n";
        print "   HARD: <$hard> <$hard_kib>KiB\n";
    }
    return($used,$soft,$hard,$used_kib,$soft_kib,$hard_kib,$used_mib,$soft_mib,$hard_mib,$string);
}



sub AD_smbcquotas_testshare {
    my ($root_dns,$smb_admin_pass,$share,$ref_sophomorix_config,$ref_schools)=@_;
    my $smbcquotas_command;
    if ($ref_sophomorix_config->{'linux'}{'lsb-release'}{'DISTRIB_RELEASE'} eq "18.04"){
        # switch back to old protocol
        $smbcquotas_command=
        $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
        " -mNT1".
        " -U ".$DevelConf::sophomorix_file_admin."%'".
        $smb_admin_pass."'".
	" -F //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/".$share;
    } else {
	# ubuntu 22.04 or later expected, no -mNT1 option available
        $smbcquotas_command=
        $ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS'}.
        " ".$ref_sophomorix_config->{'INI'}{'EXECUTABLES'}{'SMBCQUOTAS_PROTOCOL_OPT'}.
        " -U ".$DevelConf::sophomorix_file_admin."%'".
        $smb_admin_pass."'".
	" -F //".$ref_sophomorix_config->{'samba'}{'from_smb.conf'}{'ServerDNS'}."/".$share;
    }
    my $return_quota=system("$smbcquotas_command > /dev/null");
    if ($return_quota==0){
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTAS'}="TRUE";
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTASDISPLAY'}="OK";
    }  else {
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTAS'}="FALSE";
        $ref_schools->{'SHARES'}{$share}{'SMB_SHARE'}{'SMBCQUOTASDISPLAY'}="NOT OK";
    }
}



sub AD_sophomorix_schema_update {
    my ($root_dns)=@_;
    print "\n";
    print "* Testing for sophomorix schema update\n";
    my $AD_version=&AD_sophomorix_schema_version($root_dns);
    if (not $AD_version==0){
        # Version in AD found, checking for updates
        print "   * Installed Sophomorix-Schema-Version:  $AD_version\n";
        print "   * Target    Sophomorix-Schema-Version:  $DevelConf::sophomorix_schema_version\n";
        if ($DevelConf::sophomorix_schema_version <= $AD_version){
            print "* No sophomorix schema update needed\n";
        } else {
            my @ldif_list=();
            my %ldif_info=();
            my $ldif_not_found_count=0;
            # Testing for necessary ldif files
            for( my $number = $AD_version+1 ; $number < $DevelConf::sophomorix_schema_version+1 ; $number++) {
		my $ldif_file="sophomorix-schema-update-".$number.".ldif";
		my $ldif_abs=$DevelConf::sophomorix_schema_update_path."/".$ldif_file;
                print "      * Testing for $ldif_file --> Update to Version $number\n";
                if (-f $ldif_abs){
                    push @ldif_list,$ldif_abs;
                    $ldif_info{$ldif_abs}=$number
                } else {
                    print "        NOT FOUND: $ldif_abs\n";
                    $ldif_not_found_count++;
                }
            }
            # decide what to do
            if ($ldif_not_found_count==0){
                # updating
                print "* All ldif files found, running updates:\n";
                &samba_stop();
                foreach my $ldif (@ldif_list){
                    my $ldif_patched=$ldif.".sed";
                    print "   * Running update to Sophomorix-Schema-Version $ldif_info{$ldif}:\n";
                    print "     PATCHING: $ldif\n";
                    my $sed_command="cat \"".$ldif.
                        "\" | sed -e \"s/<SchemaContainerDN>/CN=Schema,CN=Configuration,".
                        $root_dns."/\" > \"$ldif_patched\"";
                    #print "$sed_command\n";
                    system("$sed_command");
                    print "     LOADING: $ldif_patched\n";

                    my $ldbmodify_command="ldbmodify -H /var/lib/samba/private/sam.ldb ".
                          $ldif_patched." ".
                          "--option=\"dsdb:schema update allowed\"=true";
                    #print "$ldbmodify_command\n";
                    my $stdout=`$ldbmodify_command`;
                    chomp($stdout);
                    my $return=${^CHILD_ERROR_NATIVE}; # return of value of last command
                    if ($return==0){
                        print "     SUCCESS: $stdout\n";
                    } else {
                        print "\n";
                        print "ERROR: Update failed: skipping other updates\n";
                        print "\n";
                        last;
                    }
                }
                &samba_start();
            } else {
                # cancel updates (files missing)
                print "\nERROR: No schema update possible (some files are missing)\n\n";
            }
        }
    } else {
        # No AD Version found -> schema never loaded -> no updates
        print "   WARNING: No Sophomorix-Schema-Version in AD found: Skipping updates\n";
    }
}



sub AD_sophomorix_schema_version {
    my ($root_dns) = @_;
    my $ldbsearch_command="ldbsearch -H /var/lib/samba/private/sam.ldb ".
                          "-b CN=Sophomorix-Schema-Version,CN=Schema,CN=Configuration,".
                          $root_dns." ".
                          "rangeUpper | grep rangeUpper";
    my $stdout=`$ldbsearch_command`;
    my $return=${^CHILD_ERROR_NATIVE}; # return of value of last command
    if ($return==0){
        my $version=$stdout;
        $version=~s/rangeUpper//;
        $version=~s/://;
        $version=~s/\s+$//g;# remove trailing whitespace
        $version=~s/^\s+//g;# remove leading whitespace
        return $version;
    } else {
        #print "Something went wrong retrieving Sophomorix-Schema-Version\n";
        return 0; # no version found
    }
}



sub samba_stop {
    my $command="/bin/systemctl stop samba-ad-dc";
    print "\nStopping samba with command $command\n\n";
    system($command);
}



sub samba_start {
    my $command="/bin/systemctl start samba-ad-dc";
    print "\nStarting samba with command $command\n\n";
    system($command);
}



sub samba_status {
    my $command="/bin/systemctl status samba-ad-dc";
    print "\nShowing samba status with command $command\n\n";
    system($command);
}



sub _uac_disable_user {
    my ($uac)=@_;
    # bit 2 to set must be 1, OR
    my $set_disable_bit = 0b0000_0000_0000_0000_0000_0000_0000_0010;
    my $res = $uac | $set_disable_bit;
    return $res;
}



sub _uac_enable_user {
    my ($uac)=@_;
    # bit 2 to set must be 0, AND
    my $set_enable_bit =  0b1111_1111_1111_1111_1111_1111_1111_1101;
    my $res = $uac & $set_enable_bit;
    return $res;
}



sub _keep_object_class_only {
    # keep only items with objectClass $type_to_keep in @keep_list
    my $ldap = shift;
    my $root_dse = shift;
    my $type_to_keep = shift; 
    my @list = @_;
    my @keep_list=();
    foreach my $item (@list){
        my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,$type_to_keep,$item);
        if ($count==1){ #its a user/group
            push @keep_list, $item;
        } else {
            print "   * WARNING: $item is not of objectClass $type_to_keep (Skipping $item)\n";
        }
    } 
    return @keep_list;
}



sub _project_info_prefix {
    my ($ldap,$root_dse,$type,@list)=@_;
    my @list_prefixed=();
    # finding status of user/group
    # ? nonexisting
    # - existing
    foreach my $item (@list){
        #print "$type: $item\n"; 
        my ($count,$dn_exist,$cn_exist)=&AD_object_search($ldap,$root_dse,$type,$item);
        if ($count==0){
            push @list_prefixed,"?".$item;
        } elsif ($count==1){
            push @list_prefixed,"-".$item;
        } else {
            push @list_prefixed,"???".$item;
        }
    }
    return @list_prefixed;
}



sub _unipwd_from_plainpwd{
    # create string for unicodePwd in AD from $sophomorix_first_password 
    my ($sophomorix_first_password) = @_;
    # build the conversion map from your local character set to Unicode 
    my $charmap = Unicode::Map8->new('latin1')  or  die;
    # surround the PW with double quotes and convert it to UTF-16
    my $uni_password = $charmap->tou('"'.$sophomorix_first_password.'"')->byteswap()->utf16();
    return $uni_password;
}



sub _create_filter_alldevices {
    my ($ref_devicelist,$ref_sophomorix_config,$objectclass,$attribute)=@_;
    my $objectclass_filter="(objectClass=".$objectclass.")";
    my $role_filter="(|";
    foreach my $keyname (keys %{$ref_sophomorix_config->{'LOOKUP'}{'ROLES_DEVICE'}}) {
        $role_filter=$role_filter."(sophomorixRole=".$keyname.")";
    }
    $role_filter=$role_filter.")";
    my $sam_filter;
    if ($ref_devicelist eq ""){
        # no list given
        $sam_filter="";
    } elsif ($#{ $ref_devicelist }==0){ # one name, counter 0
        my $sam;
        if ($objectclass eq "computer"){
            $sam=&Sophomorix::SophomorixBase::append_dollar(${ $ref_devicelist }[0]);
        } else {
            $sam=&Sophomorix::SophomorixBase::detach_dollar(${ $ref_devicelist }[0]);
        }
        $sam_filter="(".$attribute."=".$sam.")"; 
    } else {
        $sam_filter="(|";
        foreach my $sam ( @{ $ref_devicelist } ){
            if ($objectclass eq "computer"){
                $sam=&Sophomorix::SophomorixBase::append_dollar($sam);
            } else {
                $sam=&Sophomorix::SophomorixBase::detach_dollar($sam);
            }
            $sam_filter=$sam_filter."(".$attribute."=".$sam.")";
        } 
        $sam_filter=$sam_filter.")";
    }
    $filter="(& ".$objectclass_filter." ".$role_filter." ".$sam_filter." )";
    return $filter;
}



# END OF FILE
# Return true=1
1;
