#!/usr/bin/env perl
#******************************************************************************
# @(#) update_ssh.pl
#******************************************************************************
# @(#) Copyright (C) 2014 by KUDOS BVBA <info@kudos.be>.  All rights reserved.
#
# This program is a free software; you can redistribute it and/or modify
# it under the same terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details
#******************************************************************************
# This script distributes SSH keys to the appropriate files into the designated
# repository based on the 'access', 'alias' and 'keys' configuration files.
# Superfluous usage of 'hostname' reporting in log messages is encouraged to
# make reading of multiplexed output from update_ssh.pl through backgrounded
# jobs via manage_ssh.sh much easier.
#
# @(#) HISTORY: see perldoc 'update_ssh.pl'
# -----------------------------------------------------------------------------
# DO NOT CHANGE THIS FILE UNLESS YOU KNOW WHAT YOU ARE DOING!
#******************************************************************************

#******************************************************************************
# PRAGMAs/LIBs
#******************************************************************************

use strict;
use Net::Domain qw(hostfqdn hostname);
use POSIX qw(uname);
use Data::Dumper;
use Getopt::Long;
use Pod::Usage;


#******************************************************************************
# DATA structures
#******************************************************************************

# ------------------------- CONFIGURATION starts here -------------------------
# define the V.R.F (version/release/fix)
my $MY_VRF = "1.1.0";
# name of global configuration file (no path, must be located in the script directory)
my $global_config_file = "update_ssh.conf";
# name of localized configuration file (no path, must be located in the script directory)
my $local_config_file = "update_ssh.conf.local";
# selinux context labels of key files for different RHEL version
my %selinux_contexts = ( '5' => 'sshd_key_t', 
                         '6' => 'ssh_home_t', 
                         '7' => 'ssh_home_t');
# ------------------------- CONFIGURATION ends here --------------------------- 
# initialize variables
my ($debug, $verbose, $preview, $remove, $global, $use_fqdn) = (0,0,0,0,0,0);
my (@config_files, @zombie_files, $access_dir, $blacklist_file);
my (%options, @uname, @accounts, %aliases, %keys, %access, @blacklist);
my ($os, $hostname, $run_dir);
my ($selinux_status, $selinux_context, $linux_version, $has_selinux) = ("","","",0);
$|++;


#******************************************************************************
# SUBroutines
#******************************************************************************

# -----------------------------------------------------------------------------
sub do_log {
    
    my $message = shift;

    if ($message =~ /^ERROR:/ || $message =~ /^WARN:/) {
        print STDERR "$message\n";
    } elsif ($message =~ /^DEBUG:/) {
        print STDOUT "$message\n" if ($debug);
    } else {
        print STDOUT "$message\n" if ($verbose);
    }

    return (1);
}

# -----------------------------------------------------------------------------
sub parse_config_file {

    my $config_file = shift;

    unless (open (CONF_FD, "<", $config_file)) {
        do_log ("ERROR: failed to open the configuration file ${config_file} [$! $hostname]")
        and exit (1);
    }
    while (<CONF_FD>) {
        chomp ();
        # parse settings
        if (/^\s*$/ || /^#/) {
            next;
        } else {
            if (/^\s*use_fqdn\s*=\s*([0-9]+)\s*$/) {
                $use_fqdn = $1;
                do_log ("DEBUG: picking up setting: use_fqdn=${use_fqdn}");
            }
            if (/^\s*access_dir\s*=\s*([0-9A-Za-z_\-\.\/~]+)\s*$/) {
                $access_dir = $1;
                do_log ("DEBUG: picking up setting: access_dir=${access_dir}");
            }
            if (/^\s*blacklist_file\s*=\s*([0-9A-Za-z_\-\.\/~]+)\s*$/) {
                $blacklist_file = $1;
                # support tilde (~) expansion for ~root
                $blacklist_file =~ s{ ^ ~ ( [^/]* ) }
                { $1
                    ? (getpwnam($1))[7]
                    : ( $ENV{HOME} || $ENV{LOGDIR}
                         || (getpwuid($>))[7]
                       )
                }ex;
                do_log ("DEBUG: picking up setting: blacklist_file=${blacklist_file}");
            }
        }
    }
    
    return (1);
}

# -----------------------------------------------------------------------------
sub resolve_aliases
{
    my $input = shift;
    my (@tmp_array, @new_array, $entry);

    @tmp_array = split (/,/, $input);
    foreach $entry (@tmp_array) {
        if ($entry =~ /^\@/) {
            ($aliases{$entry})
                ? push (@new_array, @{$aliases{$entry}}) 
                : do_log ("WARN: unable to resolve alias $entry [$hostname]");
        } else {
            ($entry)
                ? push (@new_array, $entry)
                : do_log ("WARN: unable to resolve alias $entry [$hostname]");
        }
    }
    return (@new_array);
}

# -----------------------------------------------------------------------------
sub set_file {

    my ($file, $perm, $uid, $gid) = @_;
    
    chmod ($perm, "$file") 
        or do_log ("ERROR: cannot set permissions on $file [$! $hostname]")
        and exit (1);
    chown ($uid, $gid, "$file")
        or do_log ("ERROR: cannot set ownerships on $file [$! $hostname]")
        and exit (1);   
        
    return (1);
}


#******************************************************************************
# MAIN routine
#******************************************************************************

# -----------------------------------------------------------------------------
# process script arguments & options
# -----------------------------------------------------------------------------

if ( @ARGV > 0 ) {
    Getopt::Long::Configure ('prefix_pattern=(--|-|\/)', 'bundling', 'no_ignore_case');
    GetOptions (\%options,
            qw(
                debug|d
                help|h|?
                global|g
                preview|p
                remove|r
                verbose|v
                version|V
            )) || pod2usage(-verbose => 0);
}
pod2usage(-verbose => 0) unless (%options);         
            
# check version parameter
if ($options{'version'}) {
    $verbose = 1;
    do_log ("INFO: $0: version $MY_VRF");
    exit (0);
}
# check help parameter
if ($options{'help'}) {
    pod2usage(-verbose => 3);
    exit (0);
};
# check global parameter
if ($options{'global'}) {
    $global = 1;
}
# check preview parameter
if ($options{'preview'}) {
    $preview = 1;
    $verbose = 1;
    if ($global) {
        do_log ("INFO: running in GLOBAL PREVIEW mode");    
    } else {
        do_log ("INFO: running in PREVIEW mode");
    }
} else {
    do_log ("INFO: running in UPDATE mode");
}
# check remove parameter
if ($options{'remove'}) {
    $remove = 1 unless ($preview);
}
# debug & verbose
if ($options{'debug'}) {
    $debug   = 1;
    $verbose = 1;
}
$verbose = 1 if ($options{'verbose'});

# what am I?
@uname = uname();
$os = $uname[0];
# who am I?
unless ($preview and $global) {
    if ($< != 0) {
        do_log ("ERROR: script must be invoked as user 'root' [$hostname]") 
        and exit (1);
    }
}
# where am I?
unless ($use_fqdn) {
    $hostname = hostfqdn();
} else {
    $hostname = hostname();
}
$0 =~ /^(.+[\\\/])[^\\\/]+[\\\/]*$/;
my $run_dir = $1 || ".";
$run_dir =~ s#/$##;     # remove trailing slash

do_log ("INFO: runtime info: ".getpwuid ($<)."; $hostname\@${run_dir}; Perl v$]"); 

# -----------------------------------------------------------------------------
# check/process configuration files, environment checks
# -----------------------------------------------------------------------------

# don't do anything without configuration file(s)
do_log ("INFO: parsing configuration file(s) ...");
push (@config_files, "$run_dir/$global_config_file") if (-f "$run_dir/$global_config_file");
push (@config_files, "$run_dir/$local_config_file") if (-f "$run_dir/$local_config_file");
unless (@config_files) {
    do_log ("ERROR: unable to find any configuration file, bailing out [$hostname]") 
    and exit (1);
}

# process configuration file: global first, local may override
foreach my $config_file (@config_files) {
    parse_config_file ($config_file);
}

# is the target directory for keys present? (not for global preview)
unless ($preview and $global) {
    do_log ("INFO: checking for SSH control mode ...");
    if (-d $access_dir) {
        do_log ("INFO: host is under SSH control via $access_dir");
    } else {
        do_log ("ERROR: host is not under SSH keys only control [$hostname]") 
        and exit (1);
    }
}

# do we have a blacklist file? (optional) (not for global preview)
unless ($preview and $global) {
    do_log ("INFO: checking for keys blacklist file ...");
    if (-f $blacklist_file) {
        open (BLACKLIST, "<", $blacklist_file) or \
            do_log ("ERROR: cannot read keys blacklist file [$! $hostname]") 
                and exit (1);
        @blacklist = <BLACKLIST>;
        close (BLACKLIST);
        do_log ("INFO: keys blacklist file found with ".scalar (@blacklist)." entr(y|ies) on $hostname");
        print Dumper (\@blacklist) if $debug;
    } else {
        do_log ("WARN: no keys blacklist file found [$hostname]");  
    }
}

# -----------------------------------------------------------------------------
# collect local user accounts from /etc/passwd
# result: %accounts
# -----------------------------------------------------------------------------

do_log ("INFO: reading user accounts from /etc/passwd ...");

open (PASSWD, "/etc/passwd")
    or do_log ("ERROR: cannot read PASSWD file [$! $hostname]") and exit (1);
while (<PASSWD>) {
    
    my @pw_entry;

    chomp ();
    @pw_entry = split (/:/);
    push (@accounts, $pw_entry[0]);
}
close (PASSWD);

do_log ("INFO: ".scalar (@accounts)." user accounts found on $hostname");
print Dumper (\@accounts) if $debug;

# -----------------------------------------------------------------------------
# read aliases for teams, servers and users
# result: %aliases
# -----------------------------------------------------------------------------

do_log ("INFO: reading 'alias' file ...");

open (ALIASES, "<", "${run_dir}/alias")
    or do_log ("ERROR: cannot read 'alias' file [$! $hostname]") and exit (1);
while (<ALIASES>) {

    my ($key, $value, @values);
    
    chomp ();
    next if (/^$/ || /\#/);
    s/\s+//g;
    ($key, $value) = split (/:/);
    next unless ($value);
    @values = sort (split (/\,/, $value));
    $aliases{$key} = [@values];
};
close (ALIASES);
do_log ("DEBUG: dumping unexpanded aliases:");
print Dumper (\%aliases) if $debug;

# we can nest aliases one level deep, so do a one-level recursive sort of lookup
# of the remaining '@' aliases. Input should be passed as comma-separated
# string to resolve_aliases so don't forget to smash everything back together
# first.
foreach my $key (keys (%aliases)) {
    
    $aliases{$key} = [resolve_aliases (join (",", @{$aliases{$key}}))]; 
}

do_log ("INFO: ".scalar (keys (%aliases))." aliases found on $hostname");
do_log ("DEBUG: dumping expanded aliases:");
print Dumper (\%aliases) if $debug;

# -----------------------------------------------------------------------------
# read SSH keys (incl. the blacklisted keys), supports keys stored in a single
# 'keys.d' file or in individual key files in a 'keys' directory
# result: %keys
# -----------------------------------------------------------------------------

do_log ("INFO: reading 'keys' file(s) ...");

my @key_files;

# check if the SSH keys are stored in a directory or file
if (-d "${run_dir}/keys.d" && -f "${run_dir}/keys") {
    do_log ("WARN: found both a 'keys' file and 'keys.d' directory. Ignoring the 'keys' file [$hostname]");
}
if (-d "${run_dir}/keys.d") {
    do_log ("INFO: local 'keys' are stored in a DIRECTORY on $hostname");
    opendir (KEYS_DIR, "${run_dir}/keys.d")
        or do_log ("ERROR: cannot open 'keys.d' directory [$! $hostname]") 
        and exit (1);
    while (my $key_file = readdir (KEYS_DIR)) {
        next if ($key_file =~ /^\./);
        push (@key_files, "${run_dir}/keys.d/$key_file");
    }
    closedir (KEYS_DIR);    
} elsif (-f "${run_dir}/keys") {
    do_log ("INFO: local 'keys' are stored in a FILE on $hostname");
    push (@key_files, "${run_dir}/keys");
} else {
    do_log ("ERROR: cannot find any public keys in the repository! [$hostname]") 
    and exit (1);
}

# process 'keys' files
foreach my $key_file (@key_files) {
    open (KEYS, "<", $key_file)
        or do_log ("ERROR: cannot read 'keys' file [$! $hostname]") and exit (1);
    do_log ("INFO: reading public keys from file: $key_file");
    while (<KEYS>) {

        my ($user, $keytype, $key);

        chomp ();
        next if (/^$/ || /\#/);
    
        # check for blacklisting
        my $key_line = $_;
        if (grep (/\Q${key_line}\E/, @blacklist)) {
            do_log ("WARN: *BLACKLIST*: key match found for '$key_line', ignoring key! [$hostname]");
            next;
        }
        # process key
        s/\s+//g;
        ($user, $keytype, $key) = split (/,/);
        next unless ($key);
        $keys{$user}{"keytype"} = $keytype;
        $keys{$user}{"key"} = $key;
    };
    close (KEYS);
}

do_log ("INFO: ".scalar (keys (%keys))." public key(s) found on $hostname");
print Dumper(\%keys) if $debug;

# -----------------------------------------------------------------------------
# read access definitions
# result: %access (hash of arrays). The keys are the accounts for which 
# access control has been defined for this server. The values are an array 
# with all the people who can access the account.
# -----------------------------------------------------------------------------

do_log ("INFO: reading 'access' file ...");

open (ACCESS, "<", "${run_dir}/access")
    or do_log ("ERROR: cannot read 'access' file [$! $hostname]") and exit (1);
while (<ACCESS>) {

    my ($who, $where, $what, @who, @where, @what);
    
    chomp ();
    next if (/^$/ || /\#/);
    s/\s+//g;
    ($who, $where, $what) = split (/:/);
    next unless ($what);
    @who   = resolve_aliases ($who);
    @where = resolve_aliases ($where);
    @what  = resolve_aliases ($what);
    unless (@who and @where and @what) {
        do_log ("WARN: ignoring line $. in 'access' due to missing/non-resolving values [$hostname]");
        next;
    }
    
    foreach my $account (sort (@what)) {
        
        my @new_array;
    
        foreach my $server (sort (@where)) {
            foreach my $person (sort (@who)) {
                do_log ("DEBUG: adding access for $account to $person on $server in \%access") 
                    if ($server eq $hostname);
                # add person to access list if the entry is for this host
                push (@new_array, $person) if ($server eq $hostname);
            }
        }
        # add to full access list of persons for this host
        push (@{$access{$account}}, @new_array) if (@new_array);
    }
};
close (ACCESS);

# remove duplicates in 'persons' in %access{$account}
foreach my $account (keys (%access)) {
    @{$access{$account}} = keys (%{{ map { $_ => 1 } @{$access{$account}}}});
}

do_log ("INFO: ".scalar (keys (%access))." accounts with applicable access rules found on $hostname");
print Dumper(\%access) if $debug;

# -----------------------------------------------------------------------------
# global preview, show full configuration data only
# -----------------------------------------------------------------------------

if ($preview && $global) {

    do_log ("INFO: display GLOBAL configuration ....");

    open (ACCESS, "<", "${run_dir}/access")
        or do_log ("ERROR: cannot read 'access' file [$! $hostname]") and exit (1);
    while (<ACCESS>) {

        my ($who, $where, $what, @who, @where, @what);
    
        chomp ();
        next if (/^$/ || /\#/);
        s/\s+//g;
        ($who, $where, $what) = split (/:/);
        next unless ($what);
        @who   = resolve_aliases ($who);
        @where = resolve_aliases ($where);
        @what  = resolve_aliases ($what);
        unless (@who and @where and @what) {
            do_log ("WARN: ignoring line $. in 'access' due to missing/non-resolving values [$hostname]");
            next;
        }
    
        foreach my $account (sort (@what)) {
        
            my @new_array;
    
            foreach my $server (sort (@where)) {
                foreach my $person (sort (@who)) {
                    do_log ("$person|$server|$account") 
                }
            }
        }
    };
    close (ACCESS);

    exit (0);
}

# -----------------------------------------------------------------------------
# distribute keys into authorized_keys files in $access_dir
# -----------------------------------------------------------------------------

do_log ("INFO: applying SSH access rules ....");

# check for SELinux & contexts
unless ($preview) {
    SWITCH_OS: {
        $os eq "Linux" && do {
            # figure out selinux mode
            $selinux_status = qx#/usr/sbin/getenforce 2>/dev/null#;
            chomp ($selinux_status);
            if ($selinux_status eq "Permissive" or $selinux_status eq "Enforcing") {
                do_log ("INFO: runtime info: detected active SELinux system on $hostname");
                $has_selinux = 1;
            } 
            # figure out RHEL version (via lsb_release or /etc/redhat-release)
            $linux_version = qx#/usr/bin/lsb_release -rs 2>/dev/null | /usr/bin/cut -f1 -d'.'#;
            chomp ($linux_version);
            if (not (defined ($linux_version)) or $linux_version eq "") {
                my $release_string;
                $release_string = qx#/bin/grep -i "release" /etc/redhat-release 2>/dev/null#;
                chomp ($release_string);
                SWITCH_RELEASE: {
                    $release_string =~ m/release 5/i && do {
                        $linux_version = 5;
                        last SWITCH_RELEASE;
                    };
                    $release_string =~ m/release 6/i && do {
                        $linux_version = 6;
                        last SWITCH_RELEASE;
                    };          
                    $release_string =~ m/release 7/i && do {
                        $linux_version = 7;
                        last SWITCH_RELEASE;
                    };
                }
            }
            # use fall back in case we cannot determine the version
            if (not (defined ($linux_version)) or $linux_version eq "") {               
                $selinux_context = 'etc_t';
                $linux_version = 'unknown';
            } else {
                $selinux_context = $selinux_contexts{$linux_version};
            }
            if ($has_selinux) {
                do_log ("INFO: runtime info: OS major version $linux_version, SELinux context $selinux_context on $hostname");
            } else {
                do_log ("INFO: runtime info: OS major version $linux_version on $hostname");
            }   
            last SWITCH_OS; 
        };
    }
}

# only add authorized_keys for existing local accounts, 
# otherwise revoke access if needed
foreach my $account (sort (@accounts)) {
    
    my $access_file = "$access_dir/$account";
    
    # only add authorised_keys if there are access definitions 
    if ($access{$account}) {
    
        unless ($preview) {
            open (KEYFILE, "+>", $access_file)
                or do_log ("ERROR: cannot open file for writing in $access_dir [$! $hostname]")
                and exit (1);
        }
        foreach my $person (sort (@{$access{$account}})) {
            my $real_name = $person;
            $real_name =~ s/([a-z])([A-Z])/$1 $2/g;
            # only add authorized_keys if $person actually has a key
            if (exists ($keys{$person})) {
                # only add authorized_keys if $person actually has an account
                print KEYFILE "$keys{$person}{keytype} $keys{$person}{key} $real_name\n" 
                    unless $preview;
                do_log ("INFO: granting access to $account for $real_name on $hostname");
            } else {
                do_log ("INFO: denying access (no key) to $account for $real_name on $hostname");            
            }
        }
        close (KEYFILE) unless $preview;

        # set permissions to world readable and check for SELinux context
        unless ($preview) {
            set_file ($access_file, 0644, 0, 0);
            # selinux labels
            SWITCH: {
                $os eq "Linux" && do { 
                    if ($has_selinux) {
                        system ("/usr/bin/chcon -t $selinux_context $access_file") and
                            do_log ("WARN: failed to set SELinux context $selinux_context on $access_file [$hostname]");
                    };
                    last SWITCH; 
                }
            }
        }
    } else {
        # remove obsolete access file if needed (revoking access)
        if (-f $access_file) {
            unless ($preview) {
                unlink ($access_file)
                or do_log ("ERROR: cannot remove obsolete access file(s) [$! $hostname]")
                and exit (1);
            } else {
                do_log ("INFO: removing obsolete access $access_file on $hostname");
            }
        }
    }
}

# -----------------------------------------------------------------------------
# alert on/remove extraneous authorized_keys files 
# (access files for which no longer a valid UNIX account exists)
# -----------------------------------------------------------------------------

do_log ("INFO: checking for extraneous access files ....");

opendir (ACCESS_DIR, $access_dir)
    or do_log ("ERROR: cannot open directory $access_dir [$! $hostname]") 
    and exit (1);
while (my $access_file = readdir (ACCESS_DIR)) {
    next if ($access_file =~ /^\./);
    unless (grep (/$access_file/, @accounts)) {
        do_log ("WARN: found extraneous access file in $access_dir/$access_file [$hostname]");
        push (@zombie_files, "$access_dir/$access_file");
    }
}
closedir (ACCESS_DIR);
do_log ("INFO: ".scalar (@zombie_files)." extraneous access file(s) found on $hostname");
print Dumper (\@zombie_files) if $debug;

# remove if requested and needed
if ($remove && @zombie_files) {
    my $count = unlink (@zombie_files)
        or do_log ("ERROR: cannot remove extraneous access file(s) [$! $hostname]") 
        and exit (1);
    do_log ("INFO: $count extraneous access files removed $hostname");
}

exit (0);

#******************************************************************************
# End of SCRIPT
#******************************************************************************
__END__
#******************************************************************************
# POD
#******************************************************************************

# -----------------------------------------------------------------------------

=head1 NAME

update_ssh.pl - distributes SSH public keys in a desired state model.

=head1 SYNOPSIS

    update_ssh.pl[-d|--debug] 
                 [-h|--help] 
                 ([-p|--preview] [-g|--global]) | [-r|--remove]
                 [-v|--verbose]
                 [-V|--version]

                 
=head1 DESCRIPTION

B<update_ssh.pl> distributes SSH keys to the appropriate files (.e. 'authorized_keys') into the C<$access_dir> repository based on the F<access>, F<alias> and F<keys> files.
This script should be run on each host where SSH key authentication is the exclusive method of (remote) authentication. 

For update SSH public keys must be stored in a generic F<keys> file within the same directory as B<update_ssh.pl> script. 
Alternatively key files may be stored as set of individual key files within a called sub-directory called F<keys.d>. 
Both methods are mutually exclusive and the latter always take precedence.

=head1 CONFIGURATION

B<update_ssh.pl> requires the presence of at least one of the following configuration files:

=over 2

=item * F<update_ssh.conf>

=item * F<update_ssh.conf.local>

=back 

Use F<update_ssh.conf.local> for localized settings per host. Settings in the localized configuration file will always override other values.

Following settings must be configured:

=over 2

=item * B<access_dir>     : target directory for allowed SSH public key files

=item * B<blacklist_file> : location of the file with blacklisted SSH public keys

=back

=head1 BLACKLISTING

Key blacklisting can be performed by adding a public key definition in its entirety to the blacklist keys file. When a blacklisted key is
found in the available F<keys> file(s) during SSH control updates, an alert will be shown on STDOUT and the key will be ignored for the rest.

Examples:

WARN: *BLACKLIST*: key match found for 'John Doe,ssh-rsa,AAAAB3N'<snip>, ignoring key!


=head1 OPTIONS

=over 2

=item -d | --debug

S<       >Be I<very> verbose during execution; show array/hash dumps.

=item -h | --help

S<       >Show the help page.

=item -p | --preview

S<       >Do not actually distribute any SSH public keys, nor update/remove any 'authorized_keys' files.

=item -p | --global

S<       >Must be used in conjunction with the --preview option. This will dump the global namespace/configuration to STDOUT.

=item -r | --remove

S<       >Remove any extraneous 'authorized_keys' files (i.e. belonging to non-existing accounts in /etc/passwd)

=item -v | --verbose

S<       >Be verbose during exection.
       
=item -V | --version

S<       >Show version of the script.

=back 

=head1 NOTES

=over 2

=item * Options may be preceded by a - (dash), -- (double dash) or a / (slash).

=item * Options may be bundled (e.g. -vp)

=back 

=head1 AUTHOR

(c) KUDOS BVBA, Patrick Van der Veken

=head1 history

@(#) 2014-12-04: VRF 1.0.0: first version [Patrick Van der Veken]
@(#) 2014-12-16: VRF 1.0.1: added SELinux context, new config option 'selinux_context' [Patrick Van der Veken]
@(#) 2015-08-08: VRF 1.0.2: small fix for 'cut' command [Patrick Van der Veken]
@(#) 2015-08-15: VRF 1.1.0: replace uname/hostname syscalls, now support for FQDN via $use_fqdn, other fixes [Patrick Van der Veken]
