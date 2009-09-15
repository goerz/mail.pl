#!/usr/bin/perl -w
use strict;
# (c) 2007 Michael Goerz <goerz@physik.fu-berlin.de>
# This script allows to send  email messages with attachments
# through an SMTP server that requires authentification
# The message can optionally be encrypted and signed with GPG,
# and attachments can be zipped in various ways
# Run the program with the --help option for further information

# License:  GPL (http://www.gnu.org/licenses/gpl.txt)
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# In order to adapt the script to your needs, create and edit
my $configfile = "$ENV{HOME}/.mailpl/mailpl.rc";

# Most of the actual SMTP communication was modified from a script
# by Michal Ludvig. See http://www.logix.cz/michal/devel/smtp/


# A little hack:
# You can use this script non-interactively by piping into it.
# The idea is that all interactive input is actually read from
# STDIN, so as long as you know in advance what questions are asked
# in what order, you can provide it all at once. One example of how
# to use this is the 'filter through'-command of Kate, allowing
# you to send mail straight from your text editor!


use MIME::Entity;
use MIME::Types;
use MIME::Parser;
use MIME::Head;
use MIME::Base64 qw(encode_base64 decode_base64);
use Mail::GPG;
use Email::Date;
use Email::MessageID;
use Term::ReadPassword; # this is medium safe. Someone could find passwords entered with this in a coredump.
use IO::Socket::INET;
use IO::Socket::SSL;
use Net::SSLeay;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use Digest::HMAC_MD5 qw(hmac_md5_hex);
use Socket qw(:DEFAULT :crlf);


$SIG{INT} = \&safe_dying; # catch Ctrl-C
$SIG{__DIE__} = \&safe_dying; # catch dying

# TODO: add IMAP/mbox support (any mailbox format?)

# adresses that the email is actually sent to, not related to the header information
my @recipients = ();

# default parameters; will be overwritten by parameters given when running the program
# Don't put your personal defaults here, use the $configfile!
# Only what is declared here his accepted as an option in the config file or on the command line.
my %params = (to                => '',      # That's the only recipient part that can be entered interactively
              from              => '',      # for the header
              cc                => '',      # Only from command line
              bcc               => '',      # Only from command line, does not appear in headers,
              subject           => '',      # '(no subject)' if not entered at any point
              text              => '',      # The message text.
              attachments       => [],      # Attachments are *only* taken from the command line
              backup            => '',      # Should an eml file be saved? It will be unencrypted and unsigned.
              signature         => 0,       # Should a signature be appended?
              sigfile           => "$ENV{HOME}/.signature", # The signature file
              sign              => 0,       # Should the message be signed with GPG?
              encrypt           => 0,       # Should the message be encrypted with GPG?
              gpgmode           => 'mime',  # 'mime' or 'armor', armor can't handle attachments! Assumes 'mime' if empty
              zipfolders        => 1,       # if a folder is passed as attachment, should it be zipped, or should the program abort?
              zip               => '',      # zip all attachments into a file and send only the zip file as attachment
              host              => '',      # The smtp server
              port              => 25,      # The smtp server's port
              user              => '',      # Username for the host
              pass              => '',      # Leave this as '' if you don't want to save the SMTP password
              gpgkey            => '',      # GPG key used for signing.
              gpgpass           => '',      # If you want to, you can save your GPG password, but I don't suggest it. If you leave this blank (you should), you will be asked for it.
              sentbcc           => '',      # Additional BCC that should always receive a copy (e.g. a 'Sent' copy for yourself)
              hello_host        => 'localhost', # Hostname for the HELO string
              disable_ehlo      => 0,       # Don't use EHLO, only HELO
              force_ehlo        => 0,       # Use EHLO even if server doesn't say ESMTP
              encryption        => 1,       # Set this to 0 in order to not use encryption even if the remote host offers it (No TLS/SSL)
              auth              => 1,       # Enable all methods auf SMTP authentication
              auth_login        => 0,       # Enable only AUTH LOGIN method
              auth_plain        => 0,       # Enable only AUTH PLAIN method
              auth_cram_md5     => 0,       # Enable only AUTH CRAM-MD5 method
              auth_digest_md5   => 0,       # Enable only AUTH DIGEST-MD5 method
              textfile          => '',      # File that should be used to fill the email's text
              emlfile           => '',      # Email an already finished eml file. All recipients (only To: and CC:) are taken from the headers. In general, there is no way to modify any part of the message, any such command line options or settings will be ignored. Missing fields can be filled up, however.
              leave_eml_date    => 0,       # together with --emlfile: use the date field that is specified in the headers of the eml file. Default is off, i.e. replace the date field with the current time.
              nochecks          => 0,       # don't check email addresses/lists for well-formedness. Enable this if you want to email to "exotic" email addresses, like user@localhost. Careful, enabeling this makes it easy for you to mess up the headers.
              charset           => 'UTF-8', # The character set for the message. Careful with this! Changing this option doesn't change the  charset, which depends on your system, but only the headers
              verbose           => 0,       # Print out the SMTP communication, for debugging
              xmailer           => "$0",    # The xmailer field  that appears in the mail's header
              editor            => "",      # The editor used to edit the email text before it is sent.
              ask_for_cc        => 0,       # Should the program ask for a CC?
              ask_for_bcc       => 0,       # Should the program ask for a BCC?
              to_list           => "",      # Send the email to the list of addresses specified in this file
              cc_list           => "",      # CC the email to the list of addresses specified in this file
              bcc_list          => "",      # BCC the email to the list of addresses specified in this file
              expandlist        => "",      # Expand email addresses with the information from this file
              recipientrules    => "",      # Read per-recipient rules from this file
              messageid         => "",      # Message ID for message to send. If not specified, this will be auto-generated
              replyto           => ""       # Message ID of message that is being replied to
              );




my $from = ''; # for the actual sending, not for the headers

my $ehlo_ok = 1; # use of EHLO ( is set automatically from server messages.)



my $emailpattern = qr/[\w.+-]{1,64}\@[\w.-]{1,255}\.[a-z]{2,6}/; # the pattern used for recognizing email addresses
my $emailpattern_relaxed = qr/[\w.+-]+\@[\w.-]+/; # a more relaxed version for extracting the "pure" address from 'from'. If --nochecks
                                               # is not used, this is effectively the same as $emailpattern (it's run through both)
my $addresslistpattern = qr/^(  ([A-Za-z_. ]+<$emailpattern>)  |  ($emailpattern)  ) # there must be one address...
                         (,[ ]*(([A-Za-z_. ]+<$emailpattern>)  |  ($emailpattern)  ))*$/x; # ... which can be followed by any number
                                                                                           # of addresses, separated with commas

my @cleanuplist = (); # list of files that should be deleted when we're done sending




# Main Program

parse_configfile(); # first, read the config file ...
parse_cml_parameters(); # ... then, check what's on the command line...


# Deal with the attachments, and zipping.
# Since attachments can only occur on the command line, we should do this now
if ( @{ $params{attachments} } > 0 ){
    if ( $params{zip} ne '' ){ # zip everything
        $params{zip} =~ s'^.*/''; # fix the zip name
        if ( ($params{zip} !~ /.*\.zip$/) or ($params{zip} =~ /[\/?:*]/) ){
            die("The name of the zip file ($params{zip}) you provided is illegal\n");
        } else {print "zip file accepted\n";}
        if (-e $params{zip}){
            die("The zipfile $params{zip} that you wanted to pack the attachments in already exists. Provide a different name\n");
        } else {
            my $zip = Archive::Zip->new();
            add_to_zip($zip, $params{attachments});
            die "Error writing to $params{zip}\n" unless $zip->writeToFileNamed( $params{zip}) == AZ_OK;
            $params{attachments} = [$params{zip}]; # the zip file is the only attachment now
            push( @cleanuplist, $params{zip});
        }
    }
    if ( $params{zipfolders} ){ # zip only folders
        my @newattachmentlist = ();
        foreach my $file_or_folder ( @{ $params{attachments} } ){
            if (-f $file_or_folder){
                push( @newattachmentlist, $file_or_folder); # a file stays on the attachment list
            } elsif (-d $file_or_folder){
                # build the $zipfilename in several steps
                my $zipfilename = $file_or_folder; # start out with the same name as the folder that is zipped
                $zipfilename =~ s'/$''; # remove the whole path
                $zipfilename =~ s'^.*/''; # remove a trailing slash
                $zipfilename .= ".zip"; # append the file extension
                if (-e $zipfilename){
                    die("The zipfile $zipfilename that $file_or_folder was going to be packed into already exists.\n");
                } else {
                    my $zip = Archive::Zip->new();
                    add_to_zip($zip, [$file_or_folder]);
                    die "Error writing to $zipfilename\n" unless $zip->writeToFileNamed($zipfilename) == AZ_OK;
                    push( @newattachmentlist, $zipfilename); # instead of the folder, the zip file goes into the attachment list
                    push( @cleanuplist, $zipfilename); # the newly created zipfile has to be deleted when we're done.
                }
            }
        }
        $params{attachments} = \@newattachmentlist;
    }
}


# (continue with the parameters)
get_from_eml(); # ... then, if --emlfile option was given, read some information from that eml file ...
fill_parameters(); # ... and lastly ask interactively for anything that's still missing


my $msg = undef; # the unsigned, unencrypted email
my $gpg_msg = undef; # the gpg-handled mail, if such options are chosen.


# Build a MIME entity

if ($params{emlfile} ne ''){ # read in a eml file
    open(EMLFILE, $params{emlfile}) or die("Couldn't open $params{emlfile}\n");
    my $parser = new MIME::Parser;
    $parser->output_under("/tmp");
    $msg = $parser->parse(\*EMLFILE);
    close EMLFILE;
    my $head = $msg->head;
    # clean up a little bit (Received, and Thunderbird Draft Headers)
    if ($head->count('Delivery-date') > 0 ){$head->delete("Delivery-date"); }
    if ($head->count('Received') > 0 ){$head->delete("Received"); }
    if ($head->count('X-Mozilla-Draft-Info') > 0 ){$head->delete("X-Mozilla-Draft-Info");}
    if ($head->count('FCC') > 0 ){$head->delete("FCC");}
    if ($head->count('X-Identity-Key') > 0 ){$head->delete("X-Identity-Key");}
    unless ( $params{leave_eml_date} ){
        my $newdate = format_date; # function from Email::Date, referring to now
        $head->replace("Date", $newdate);
    }
    # the following shouldn't make any changes, but in case the original eml file was missing something,
    # this is the time to correct the mistake.
    $head->replace("To", $params{to});
    $head->replace("CC", $params{cc}) if ($params{cc} ne '');
    $head->replace("From", $params{from});
    $head->replace("Subject", $params{subject});
} elsif ( @{ $params{attachments} } > 0 ){ # multipart
    # Create a new multipart message:
    $msg = MIME::Entity->build(
                 From     => $params{from},
                 To       => $params{to},
                 Cc       => $params{cc},
                 Subject  => $params{subject},
                 Type     =>'multipart/mixed',
                 );

    # Add parts (each "attach" has same arguments as "new"):
    $msg->attach(Type     =>'TEXT',
                 Data     => $params{text},
                 Charset  => $params{charset}
                 );
    foreach my $attachment ( @{ $params{attachments} } ){
        my $filename = $attachment;
        $filename =~ s'^.*/''; # the attached filename should not include that path
        $msg->attach(Type        =>'AUTO', # find the MimeType with MIME::Types
                     Path        => $attachment,
                     Filename    => $filename,
                     Disposition => 'attachment',
                     );
    }
    my $head = $msg->head;
    $head->replace("Date", format_date);
} else { # text only
    $msg = MIME::Entity->build(
                 From     => $params{from},
                 To       => $params{to},
                 Cc       => $params{cc},
                 Subject  => $params{subject},
                 Data     => $params{text},
                 Charset  => "UTF-8"
                 );
    my $head = $msg->head;
    $head->replace("Date", format_date);
}

if ($params{signature}){ # append the signature
    $msg->sign(File=>$params{sigfile});
}

# set the X-Mailer
my $head = $msg->head;
$head->replace("X-Mailer", $params{xmailer});

# set In-Reply-To and References
if ($params{replyto} =~ /.+@.+/){
    my $replyto = $params{replyto};
    $head->replace("In-Reply-To", "<$replyto>");
    $head->replace("References", "<$replyto>");
}

# set the Message-ID
my $mid = '';
if ($params{messageid} =~ /.+@.+/){
    $mid = $params{messageid}
} else {
    my $id_hostname = ($params{from} =~ /^(.*)@(.*)$/)? $2: 'localhost';
    $id_hostname =~ s/[<>]//g;
    $mid = Email::MessageID->new( host => $id_hostname );
}
$head->replace("Message-ID", "<$mid>");

# encryption and signing
if ($params{sign} or $params{encrypt}){

    # get the password
    my $gpg = Mail::GPG->new(no_strict_7bit_encoding => 1); # load GPG
    if ($params{sign}){ # we'll need the password
        if ($params{gpgpass} eq ''){ # ask for password if password was not saved
            $params{gpgpass} = read_password("\nEnter password for GPG: "); # imported from Term::ReadPassword
        }
    }

    # set the mode
    if ($params{gpgmode} eq 'armor'){ # sign, encrypt, or both, in armor mode
        if ( @{ $params{attachments} } > 0 ){
            warn("Armor encryption cannot be used on multipart messages. Press Enter to use MIME encryption\n");
            my $answer = <STDIN>;
            $params{gpgmode} = 'mime';
        }
    }
    if ($params{gpgmode} ne 'armor'){ # sign, encrypt, or both, in mime mode
        $params{gpgmode} = 'mime';
    }
    
    # do the signing/encyption, as needed, using the right mode.
    if ( $params{sign} and not $params{encrypt}){ # sign only
        eval('
        $gpg_msg = $gpg->' . "$params{gpgmode}" . '_sign(entity     => $msg,
                                   key_id     => $params{gpgkey},
                                   passphrase => $params{gpgpass});
        '); # if we don't eval, the script will die when gpg has a problem.
        if ($@){gpg_error($@);}

    }
    if ( not $params{sign} and $params{encrypt}){ # encrypt only
        eval('
        $gpg_msg = $gpg->' . "$params{gpgmode}" . '_encrypt(entity     => $msg,
                                      key_id     => $params{gpgkey},
                                      passphrase => $params{gpgpass},
                                      recipients => \@recipients);
        ');
        if ($@){gpg_error($@);}
    }
    if ( $params{sign} and $params{encrypt}){ # encrypt and sign
        eval('
        $gpg_msg = $gpg->' . "$params{gpgmode}" . '_sign_encrypt(entity     => $msg,
                                           key_id     => $params{gpgkey},
                                           passphrase => $params{gpgpass},
                                           recipients => \@recipients);
        ');
        if ($@){gpg_error($@);}
     }
}




if ($params{pass} eq ''){ # ask for SMTP password if password was not saved.
    $params{pass} = read_password("\nEnter password for server $params{host}: "); # imported from Term::ReadPassword
}


# Connect to the SMTP server.
print "\nSending...\n";
my $sock = IO::Socket::INET->new(
    PeerAddr => $params{host},
    PeerPort => $params{port},
    Proto    => 'tcp',
    Timeout  => 8
) or die("Connect failed: $@\n");

my ( $code, $text );
my (%features);

# Wait for the welcome message of the server.
( $code, $text ) = get_line($sock);
die("Unknown welcome string: '$code $text'\n") if ( $code != 220 );
$ehlo_ok--                                     if ( $text !~ /ESMTP/ );

# Send EHLO
say_hello( $sock, $ehlo_ok, $params{hello_host}, \%features ) or die("EHLO failed");

# Run the SMTP session
run_smtp() or die("SMTP failed\n");

# Good bye...
send_line( $sock, "QUIT\n" );
( $code, $text ) = get_line($sock);
die("Unknown QUIT response '$code'.\n") if ( $code != 221 );

print "Done.\n";

if ($params{backup} ne ''){
    # write mail in sendmail_folder, too

    # fix the directory name
    $params{backup} =~ s'/$'';
    unless (-d $params{backup}){
        print "$params{backup} does not exist and will be created\n";
        mkdir($params{backup}) or die ("Could not create $params{backup}\n");
    }
    
    # what is saved is the unencrypted, unsigned message!
    my $outfile = "$params{backup}/sentmail_". time() . ".eml";
    open(OUTPUT, ">$outfile") or die ("Couldn't write to $outfile\n");
    $msg->print(\*OUTPUT) or die("Failed to store message in $outfile\n");
    close(OUTPUT);
    print "Backup saved in $params{backup}/\n";
}

# cleanup
foreach my $file (@cleanuplist){
    unlink($file);
}

exit; # Done














sub gpg_error{
    my $error = shift;
    warn $error;
    print "\nGPG failed. Press Enter to send the message unencrypted and unsigned.\nPress Ctrl-C to exit the program\n";
    my $answer = <STDIN>;
    $gpg_msg = undef; # get rid of everything that's encrypted
}





# parse the command line parameters and set %params
sub parse_cml_parameters{
    foreach my $argument (@ARGV){
        if ($argument =~ /^--([A-Za-z_]*)=?(.*)?$/){    # command
            my $key = lc($1);
            my $value = $2;
            if ($key eq 'help'){usage();}
            $value =~ s/^["']//; # remove ...
            $value =~ s/["']$//; # ... quotes
            if ($argument !~ /=/){ $value = 1 };
            if (exists $params{$key}){
                $params{$key} = $value;
            } else { # only keys that are declared in %params are acceptable!
                warn "Unknown field: $key\n" unless ($key eq 'configfile');
            }
        } else { # anything that doesn't start with '--' must be an attachment
            if (-f $argument){ # has to be an existing file
                push(  @{ $params{attachments} }, $argument  );
            } else {
                if ( (-d $argument) and (($params{zip} ne '') or ($params{zipfolders})) ){ # directories, too, on conditions
                    push(  @{ $params{attachments} }, $argument  );
                } else {
                    warn("File $argument does not exist\n");
                }
            }
        }
    }
    
    # Handle escapes ( /n => newline )
    # somehow I had a hard time with regexes, so let's do this C-style
    if ( $params{text} ne '' ){
        my $rawstring = $params{text};
        $params{text} = '';
        my $escaped = 0;
        foreach my $char (split(//,$rawstring)){
            if ($char eq '\\'){
                if ($escaped){
                    $params{text} .= '\\';
                    $escaped = 0;
                } else {
                    $escaped = 1;
                }
            } elsif ($char eq 'n'){
                 if ($escaped){
                    $params{text} .= "\n";
                    $escaped = 0;
                } else {
                    $params{text} .= "n";
                }
            } else {
                $params{text} .= '\\' if ($escaped);
                $params{text} .= $char;
                $escaped = 0;
            }
        }
        print "Using text:\n$params{text}\n\n" if ($params{editor} eq '');
        }
}


# parse the configfile
sub parse_configfile{

    # get the name of the configfile from the command line
    foreach my $argument (@ARGV){
        if ($argument =~ /--configfile=(.*)/){
            $configfile = $1;
            if (not -f $configfile ){
                die ("The config file that you provided does not exist\n");
            }
        }
    }
    
    open (CONFIG, $configfile) or ( (warn "You should consider putting some data in the config file at $configfile. Try --help for more information.\n") and (return undef ) );
    my $i = 0; # line counter
    foreach my $line (<CONFIG>){
        chomp $line;
        if ($line =~/^\s*(#.*)?$/) { # comment only
            next;
        }
        $i++;
        if ($line =~ /^\s*([A-Za-z]*?)\s*=\s*(.*)$/){    # command, with whitespaces and comments
            my $key = lc($1);
            my $value = $2;
            $value =~ s/\s*#.*$//; # remove comments from end of line
            $value =~ s/^["']//; # remove ...
            $value =~ s/["']$//; # ... quotes
            if (exists $params{$key}){
                $params{$key} = $value;
            } else {
                warn "Unknown field at line $i in $configfile: $key\n";
            }
        } else { # syntax error
            warn("Syntax error at line $i in $configfile. The line reads:\n$line\nRun '$0 --help' for more information\n");
        }
    }
    close CONFIG;
}


# read from, to, cc, and subject from eml file
sub get_from_eml{
    # fill from eml file, if that option is given.
    if ($params{emlfile} ne ''){ # read in a eml file
        if (-f $params{emlfile}){
            open(EMLFILE, $params{emlfile}) or die("Couldn't open $params{emlfile}\n");
            my $parser = new MIME::Parser;
            $parser->output_under("/tmp");
            $msg = $parser->parse(\*EMLFILE);
            close EMLFILE;
            my $head = $msg->head;
            if ($head->count('From') > 0 ){ $params{from} = $head->get("From"); }
            unless ( defined($params{from}) ){$params{from} = ''}
            if ($head->count('To') > 0 ){ $params{to} = $head->get("To"); }
            unless ( defined($params{to}) ){$params{to} = ''}
            if ($head->count('CC') > 0 ){ $params{cc} = $head->get("CC"); }
            unless ( defined($params{to}) ){$params{to} = ''}
            if ($head->count('Subject') > 0 ){ $params{subject} = $head->get("Subject"); }
            unless ( defined($params{subject}) ){$params{subject} = ''}
            $params{text} = '     '; # set text to something, this will be silently ignored.
        } else {
            warn("emlfile $params{emlfile} does not exist. The --emlfile option is discarded\n");
            $params{emlfile} = '';
        }
    }
}


# ask for the essential values in %params that have not been set by command line
# or config file. Also, check all values and build the recipient list.
sub fill_parameters{

    # host
    if ($params{host} eq ''){
        die ("No SMTP server specified\nRun $0 --help\n");
    } else {
        if ( $params{host} =~ /^(.*):(.*)$/ ) {
            $params{host} = $1;
            $params{port} = $2;
        }
    }

    # xmailer
    if ($params{xmailer} eq $0){
        warn ("--xmailer is set to the Default value $0. You should change it in in your config file at $configfile\n");
    }

    # set the $ehlo_ok variable
    $ehlo_ok = 1; # use EHLO if server says ESMTP
    if ($params{disable_ehlo} == 0){ $ehlo_ok = 0 } # Don't use EHLO, only HELO
    if ($params{force_ehlo} == 0  ){ $ehlo_ok = 2 }  # Use EHLO even if server doesn't say ESMTP

    # If at least one --auth-* option was given, enable AUTH.
    if ( $params{auth_login} + $params{auth_plain} + $params{auth_cram_md5} + $params{auth_digest_md5} > 0 ) {
        $params{auth} = 1;
    }
    
    # If --enable-auth was given, enable all AUTH methods.
    elsif ( $params{auth}
        && ( $params{auth_login} + $params{auth_plain} + $params{auth_cram_md5} + $params{auth_digest_md5} == 0 ) )
    {
        $params{auth_login}      = 1;
        $params{auth_plain}      = 1;
        $params{auth_cram_md5}   = 1;
        $params{auth_digest_md5} = 1;
    }

    # Exit if user hasn't specified a username for AUTH.
    if ( $params{auth} && !defined($params{user}) ) {
        die("You requested SMTP AUTH support, but provided no username.\n");
    }


    # checks or no checks?
    if ($params{nochecks}){ # be very very lenient on what a valid email address looks like
        $emailpattern = $emailpattern_relaxed; # set the patterns to match (almost) anyting...
        $addresslistpattern = qr/.+\@.+/; # ... except an empty string
    }

    # To
    if ($params{to_list} ne ''){ # add addresses from a file
        if ($params{to} ne ''){$params{to} .= ' ,'}
        $params{to} .= get_addresses_from_file($params{to_list});
    }
    while ( ($params{to} !~ $addresslistpattern) and ($params{to} !~ /undisclosed.*recipients/) ){
        $params{to} = read_line('To      : ');
        $params{to} = expand_address_list( $params{to} );
    }
    if ($params{to} =~ /undisclosed.*recipients/){$params{to} = 'undisclosed-recipients:;'} # that's for BCC sending
    $params{to} = expand_address_list($params{to});
    print"To      : $params{to}\n\n";
    # add addresses to recipients
    while ( $params{to} =~ /($emailpattern)/g ){
        push(@recipients, $1); 
    }

    # From
    while ($params{from} !~ /($emailpattern)/){$params{from}    = read_line('From    : ')}
    if ( $params{from} =~ /($emailpattern_relaxed)/ ){
        $from = $1; # for the sending, we need the address only
    }

    # sentBCC (just add to recipients)
    while ( $params{sentbcc} =~ /($emailpattern)/g ){
        push(@recipients, $1);
    }
    
    # CC
    if ($params{cc_list} ne ''){ # add addresses from a file
        if ($params{cc} ne ''){$params{cc} .= ' ,'}
        $params{cc} .= get_addresses_from_file($params{cc_list});
    }
    $params{cc} = ' ' if ( ($params{ask_for_cc}) and ($params{cc} eq '') ); # the user should get a chance to enter something
    while ( ($params{cc} !~ $addresslistpattern) and ($params{cc} ne '') ){
        $params{cc} = read_line('CC      : ');
        $params{cc} = expand_address_list($params{cc});
    }
    $params{cc} = expand_address_list($params{cc});
    print"CC      : $params{cc}\n\n" if ($params{cc} ne '');
    # add addresses to recipients
    while ( $params{cc} =~ /($emailpattern)/g ){
        push(@recipients, $1);
    }

    # BCC
    if ($params{bcc_list} ne ''){ # add addresses from a file
        $params{bcc} .= ' ,' if ($params{bcc} ne '');
        $params{bcc} .= get_addresses_from_file($params{bcc_list});
    }
    $params{bcc} = ' ' if ( ($params{ask_for_bcc}) and ($params{bcc} eq '') ); # the user should get a chance to enter something
    while ( ($params{bcc} !~ $addresslistpattern) and ($params{bcc} ne '') ){$params{bcc} = read_line('BCC     : ')}
    # add addresses to recipients
    while ( $params{bcc} =~ /($emailpattern)/g ){
        push(@recipients, $1);
    }

    # now that we know all the recipients, but before the email text is entered, appy the per-recipient rules
    apply_recipient_rules();

    # subject
    if ($params{subject} eq ''){$params{subject} = read_line('Subject : ')}
    if ($params{subject} eq ''){$params{subject} = '(no subject)'}


    # message text
    # read in text from the textfile if options was provided
    if ($params{textfile} ne ''){
        if (-e $params{textfile}){
            open (TEXTFILE, $params{textfile}) or die ("Couldn't read from $params{textfile}\n");
            $params{text} = '';
            foreach my $textline (<TEXTFILE>){
                $params{text} .= $textline;
            }
            close TEXTFILE;
        } else {
            warn("The textfile $params{textfile} you wanted to use for input was not found\n");
        }
    }
    # if we have text from the textfile, or from the command line, we won't ask the user for input
    # but if an editor should be used, the user can edit the existing text
    if ( ($params{text} eq '') or ($params{editor} ne '') ){
        my $editorsuccess = 0;
        if ($params{editor} ne ''){ # use the editor
            $editorsuccess = get_from_editor();
        }
        # if there's no text, and no editor, we need to ask. Alsso, we need to ask if there is an editor, but it failed.
        if (   ( ($params{text} eq '') and ($params{editor} eq '') ) or ( ($params{editor} ne '') and (not $editorsuccess) )   ) { # fall back to terminal
            print "Enter text (finish with Ctrl-D):\n";
            my @multiline = <STDIN>;
            $params{text} = join('', @multiline);
        }
    }

    # signature
    if ($params{signature}){
        unless (-f $params{sigfile}){
            warn("Your signature file $params{signature} was not found. Signature will be left out.\n");
            $params{signature} = 0;
        }
    }
    
    print "\n\nMessage accepted.\nIt will be sent via $params{host}\n";
    print "Recipients are: ", join(', ',@recipients), "\n\n";
}



# adds files to a zipfile, recursively
sub add_to_zip{
    my $zipfile = shift; # must of of type Archive::Zip
    my $filelist = shift;
    foreach my $file (@{$filelist}){
        $zipfile->addFileOrDirectory($file);
        if ( -d $file ){
            my @recfilelist;
            if ($file =~ /[ ]/){
                @recfilelist = glob('"'."$file".'"/*');
            } else {
                @recfilelist = glob("$file/*");
            }
            add_to_zip($zipfile, \@recfilelist);
        }
    }
}


# ask the user to type in something
sub read_line{
    my $msg = shift;
    print $msg;
    my $answer = <STDIN>;
    chomp $answer;
    return $answer;
}

# get the email text from a temp file that the user can edit
sub get_from_editor{
    unless ($params{emlfile}){
    my $tempfile = ".msgtemp$$.txt";
    system("touch $tempfile");
    push(@cleanuplist, $tempfile);

    # fill the textfile with the text that's already there
    if (open (TEXTFILE, ">$tempfile")){
            print TEXTFILE $params{text};
        } else {
            warn ("Couldn't write to $tempfile.\n");
        }
        # write the signature to the text file
        if ($params{signature}){
            if (-f $params{sigfile}){
                print TEXTFILE "\n--\n"; # signature marker
                if ( open(SIGFILE, "$params{sigfile}") ){
                    foreach my $sigline (<SIGFILE>){
                        print TEXTFILE $sigline;
                    }
                } else {
                    warn("Could not read from $params{signature}. Signature will be left out.\n");
                    $params{signature} = 0;
                }
                close SIGFILE;
            } else {
                warn("Your signature file $params{signature} was not found. Signature will be left out.\n");
                $params{signature} = 0;
            }
        }
        $params{signature} = 0; # if we don't set this to false, it will be added again later on
        close TEXTFILE;
    
        # edit the textfile
        my $result = system("$params{editor} $tempfile");
    
        # use it as the email's text, if successfull
        if ($result == 0){ # return code 0 = successful
            if (open (TEXTFILE, $tempfile)){
                $params{text} = '';
                foreach my $textline (<TEXTFILE>){
                    $params{text} .= $textline;
                }
            } else {
                warn ("Couldn't read from $tempfile. Using editor failed\n");
                return undef;
            }
            close TEXTFILE;
            return 1;
        } else {
            warn("The system call '$params{editor} $tempfile' failed. Cannot use editor\n");
            return undef;
        }
    } else {return 1}
    return undef; # this should never be reached
}

# read addresses from a file and return an address list as a string (don't check for validity)
sub get_addresses_from_file{
    my $file = shift;
    my $addresslist = '';
    if (-f $file){
        open(ADDRESSFILE, $file) or ( (warn "Can't get email addresses from $file. Failed to open file.\n") and (return '' ) );
        foreach my $line (<ADDRESSFILE>){
            chomp $line;
            $addresslist .= $line . ", ";
        }
        close ADDRESSFILE;
        $addresslist =~ s/,\s*$//; # remove last comma
    } else {
        warn("Can't get email addresses from $file, file does not exist.\n");
    }
    return $addresslist;
}

# expand an addresslist with full addresses
sub expand_address_list{
    my $list = shift;
    my @addresslist = split(/, /, $list);
    if ( -f $params{expandlist} ){
        open(EXPLIST, $params{expandlist}) or ( (warn "Can't expand addresses from $params{expandlist}. Failed to open file.\n") and (return $list) );
        foreach my $line (<EXPLIST>){
            chomp $line;
            $line =~ s/^\s*//;
            $line =~ s/\s*$//;
            foreach my $arrayelement (@addresslist) {
                if (index( lc($line), lc($arrayelement)) >= 0){
                    $arrayelement = $line
                }
            }
        }
        close EXPLIST;
    }
    return join(", ", @addresslist);
}


sub apply_recipient_rules{
    if ($params{recipientrules} ne ''){
        if (-f $params{recipientrules}){
            my %flags = ( sign          => 0, # keep track of what settings have been made
                          nosign        => 0,
                          encrypt       => 0,
                          noencrypt     => 0,
                          signature     => 0,
                          nosignature   => 0  );
            open(RCPRULES, $params{recipientrules}) or ( (warn "Failed to open $params{recipientrules}.\n") and (return undef) );
            foreach my $line (<RCPRULES>){ # go through all the recipient rules
                my @linedata = split(/\s+/, $line); # separate into the email address and the fields (sign, nosign, encrypt, ...)
                foreach my $address (@recipients){
                    if ($address eq $linedata[0]){ # is the rule for this recipient?
                        foreach my $field (@linedata){
                            if ($field eq 'sign'){
                                unless($flags{nosign}){
                                    $params{sign} = 1;
                                    $flags{sign} = 1;
                                }
                            }
                            if ($field eq 'nosign'){
                                $params{sign} = 0;
                                $flags{nosign} = 1;
                            }
                            if ($field eq 'encrypt'){
                                unless($flags{noencrypt}){
                                    $params{encrypt} = 1;
                                    $flags{encrypt} = 1;
                                }
                            }
                            if ($field eq 'noencrypt'){
                                $params{encrypt} = 0;
                                $flags{noencrypt} = 1;
                            }
                            if ($field eq 'signature'){
                                unless($flags{nosignature}){
                                    $params{signature} = 1;
                                    $flags{signature} = 1;
                                }
                            }
                            if ($field eq 'nosignature'){
                                $params{signature} = 0;
                                $flags{nosignature} = 1;
                            }
                        }
                    }
                }
            }
            close RCPRULES;
            # print a message that tells the user what has been done
            my $checksum = 0; # did the recpient rules do anything?
            foreach my $i (values(%flags)){$checksum += $i}; # add up all the flags
            if ($checksum>0){
                print "Recipient rules: ";
                if ( $flags{nosign} ){
                    print "no signing";
                } else {
                    print "signing" if ( $flags{sign} );
                }
                if ( $flags{noencrypt} ){
                    print ", no encryption";
                } else {
                    print ", encryption" if ( $flags{encrypt} );
                }
                if ( $flags{nosignature} ){
                    print ", no signature";
                } else {
                    print ", signature" if ( $flags{signature} );
                }
                print "\n";
            }
        } else {
            warn("The file $params{recipientrules} could not be found\n");
        }
    }
}

# This is the main SMTP "engine".
sub run_smtp {

    # See if we could start encryption
    if ( ( defined( $features{'STARTTLS'} ) || defined( $features{'TLS'} ) )
        && $params{encryption} )
    {
        printf("Starting TLS...\n") if ( $params{verbose} >= 1 );

        # Do Net::SSLeay initialization
        Net::SSLeay::load_error_strings();
        Net::SSLeay::SSLeay_add_ssl_algorithms();
        Net::SSLeay::randomize();

        send_line( $sock, "STARTTLS\n" );
        ( $code, $text ) = get_line($sock);
        die("Unknown STARTTLS response '$code'.\n") if ( $code != 220 );

        if (
            !IO::Socket::SSL::socket_to_SSL(
                $sock, SSL_version => 'SSLv3 TLSv1'
            )
          )
        {
            die( "STARTTLS: " . IO::Socket::SSL::errstr() . "\n" );
        }

        if ( $params{verbose} >= 1 ) {
            printf( "Using cipher: %s\n", $sock->get_cipher() );
            printf( "%s",                 $sock->dump_peer_certificate() );
        }

        # Send EHLO again (required by the SMTP standard).
        say_hello( $sock, $ehlo_ok, $params{hello_host}, \%features ) or return 0;
    }

    # See if we should authenticate ourself
    if ( defined( $features{'AUTH'} ) && $params{auth} ) {
        if ( $params{verbose} >= 1 ) {
            printf( "AUTH method (%s): ", $features{'AUTH'} );
        }

        # Try CRAM-MD5 if supported by the server
        if ( $features{'AUTH'} =~ /CRAM-MD5/i && $params{auth_cram_md5} ) {
            printf("using CRAM-MD5\n") if ( $params{verbose} >= 1 );
            send_line( $sock, "AUTH CRAM-MD5\n" );
            ( $code, $text ) = get_line($sock);
            if ( $code != 334 ) {
                warn("AUTH failed '$code $text'.\n");
                return 0;
            }

            my $response = encode_cram_md5( $text, $params{user}, $params{pass} );
            send_line( $sock, "%s\n", $response );
            ( $code, $text ) = get_line($sock);
            if ( $code != 235 ) {
                warn("AUTH failed: '$code'.\n");
                return 0;
            }
        }

        # Or try LOGIN method
        elsif ( $features{'AUTH'} =~ /LOGIN/i && $params{auth_login} ) {
            printf("using LOGIN\n") if ( $params{verbose} >= 1 );
            send_line( $sock, "AUTH LOGIN\n" );
            ( $code, $text ) = get_line($sock);
            if ( $code != 334 ) {
                warn("AUTH failed '$code $text'.\n");
                return 0;
            }

            send_line( $sock, "%s\n", encode_base64( $params{user}, "" ) );

            ( $code, $text ) = get_line($sock);
            if ( $code != 334 ) {
                warn("AUTH failed '$code $text'.\n");
                return 0;
            }

            send_line( $sock, "%s\n", encode_base64( $params{pass}, "" ) );

            ( $code, $text ) = get_line($sock);
            if ( $code != 235 ) {
                warn("AUTH failed '$code $text'.\n");
                return 0;
            }
        }

        # Or finally PLAIN if nothing else was supported.
        elsif ( $features{'AUTH'} =~ /PLAIN/i && $params{auth_plain} ) {
            printf("using PLAIN\n") if ( $params{verbose} >= 1 );
            send_line(
                $sock,
                "AUTH PLAIN %s\n",
                encode_base64( "$params{user}\0$params{user}\0$params{pass}", "" )
            );
            ( $code, $text ) = get_line($sock);
            if ( $code != 235 ) {
                warn("AUTH failed '$code $text'.\n");
                return 0;
            }
        }

        # Complain otherwise.
        else {
            warn(   "No supported authentication method\n"
                  . "advertised by the server.\n" );
            return 0;
        }

        if ( $params{verbose} >= 1 ) {
            printf("Authentication of $params{user}\@$params{host} succeeded\n");
        }
    }

    # We can do a relay-test now if a recipient was set.
    if ( @recipients > 0 ) {
        if ( !defined($from) ) {
            warn("From: address not set. Using empty one.\n");
            $from = "";
        }
        send_line( $sock, "MAIL FROM: <%s>\n", $from );
        ( $code, $text ) = get_line($sock);
        if ( $code != 250 ) {
            warn("MAIL FROM failed: '$code $text'\n");
            return 0;
        }

        my $i;
        for ( $i = 0 ; $i <= $#recipients ; $i++ ) {
            send_line( $sock, "RCPT TO: <%s>\n", $recipients[$i] );
            ( $code, $text ) = get_line($sock);
            if ( $code != 250 ) {
                warn("RCPT TO <" . $recipients[$i] . "> " . "failed: '$code $text'\n" );
                return 0;
            }
        }
    }

    # Wow, we should even send something!
    my @full_text = (); # The full message, including headers and attachments
    if (defined($gpg_msg)){ # send the signed/encryped mail
        @full_text = split("\n", $gpg_msg->as_string());
    } else { # send the unsigned/unencrypted mail
        @full_text = split("\n", $msg->as_string());
    }


    # begin transmission...
    send_line( $sock, "DATA\n" );
    ( $code, $text ) = get_line($sock);
    if ( $code != 354 ) {
        warn("DATA failed: '$code $text'\n");
        return 0;
    }

    # send every line in @full_text
    foreach my $line (@full_text){
        $line .= "\n" unless ($line =~/\n$/); # make line end in \n
        $line =~ s/^\.$CRLF$/\. $CRLF/; # remove lines that ...
        $line =~ s/^\.\n$/\. $CRLF/;    # ... only consist of a dot
        $sock->print($line);
    }


    $sock->printf("$CRLF.$CRLF");

    ( $code, $text ) = get_line($sock);
    if ( $code != 250 ) {
        warn("DATA not send: '$code $text'\n");
        return 0;
    }

    # Perfect. Everything succeeded!
    return 1;
}

# Get one line of response from the server.
sub get_one_line{
    my $sock = shift;
    my ( $code, $sep, $text ) = ( $sock->getline() =~ /(\d+)(.)([^\r]*)/ );
    my $more;
    $more = ( $sep eq "-" );
    if ($params{verbose}) {
        printf( "[%d] '%s'\n", $code, $text );
    }
    return ( $code, $text, $more );
}

# Get concatenated lines of response from the server.
sub get_line{
    my $sock = shift;
    my ( $code, $text, $more ) = &get_one_line($sock);
    while ($more) {
        my ( $code2, $line );
        ( $code2, $line, $more ) = &get_one_line($sock);
        $text .= " $line";
        die("Error code changed from $code to $code2. That's illegal.\n")
          if ( $code ne $code2 );
    }
    return ( $code, $text );
}

# Send one line back to the server
sub send_line{
    my $socket = shift;
    my @args   = @_;

    if ($params{verbose}) {
        printf("> ");
        printf(@args);
    }
    $args[0] =~ s/\n/$CRLF/g;
    $socket->printf(@args);
}

# Helper function to encode CRAM-MD5 challenge
sub encode_cram_md5 ($$$) {
    my ( $ticket64, $username, $password ) = @_;
    my $ticket = decode_base64($ticket64)
      or die("Unable to decode Base64 encoded string '$ticket64'\n");

    my $password_md5 = hmac_md5_hex( $ticket, $password );
    return encode_base64( "$username $password_md5", "" );
}

# Store all server's ESMTP features to a hash.
sub say_hello {
    my ( $sock, $ehlo_ok, $hello_host, $featref ) = @_;
    my ( $feat, $param );
    my $hello_cmd = $ehlo_ok > 0 ? "EHLO" : "HELO";

    send_line( $sock, "$hello_cmd $hello_host\n" );
    my ( $code, $text, $more ) = &get_one_line($sock);

    if ( $code != 250 ) {
        warn("$hello_cmd failed: '$code $text'\n");
        return 0;
    }

    # Empty the hash
    %{$featref} = ();

    ( $feat, $param ) = ( $text =~ /^(\w+)[= ]*(.*)$/ );
    $featref->{$feat} = $param;

    # Load all features presented by the server into the hash
    while ( $more == 1 ) {
        ( $code, $text, $more ) = &get_one_line($sock);
        ( $feat, $param ) = ( $text =~ /^(\w+)[= ]*(.*)$/ );
        $featref->{$feat} = $param;
    }

    return 1;
}

# allows to save a started email message as eml file before dying
sub safe_dying{
    my @error_msgs = @_;
    warn @error_msgs;
    if ( defined($msg) or defined($gpg_msg)){
        my $message;
        if ( defined($msg) ){
            $message = $msg;
        }
        if ( defined($gpg_msg) ){
            $message = $gpg_msg;
        }
        print "\nProgram exits with error.\n";
        print "\nThere is an unfinished/unsent message. You can save the message as an eml file before the program exits. ";
        print "To save the email, enter the name of the eml file to which you want to save, just press Enter if you don't want to save.\n";
        print "Eml file: ";
        my $filename = <STDIN>;
        chomp $filename;
        if ($filename ne ''){
            close OUTPUT;
            open(OUTPUT, ">$filename") or warn ("Couldn't write to $filename\n");
            $message->print(\*OUTPUT) or warn("Failed to store message in $filename\n");
            close(OUTPUT);
            print "Backup saved in $filename\n";
        } else {
            print "No backup saved\n";
        }
    }
    exit 1;
}


sub usage{
print "
(c) 2006 Michael Goerz <goerz\@physik.fu-berlin.de>
License:  GPL (http://www.gnu.org/licenses/gpl.txt)

This script allows to send  email messages with attachments through an SMTP server that
requires authentification. The message can optionally be encrypted and signed with GPG,
and attachments can be zipped in various ways.

Usage: $0 [parameters] [attachments]

Parameters are:
  --to=<addresslist>          Recipients of message. You can use 'undisclosed recipients' to
                              leave this blank
  --from=<address>            From-address
  --cc=<addresslist>          Carbon copy recipients
  --bcc=<addresslist>         Blind carbon copy recipients
  --subject=<string>          Subject line of the message
  --text=<string>             Text of the message. \\n gets escaped to newline,
                              \\\\ to \\. Make sure that string is enclosed in  single
                              quotes, otherwise you get weird escaping issues in bash.
  --help                      Show this information
  --backup=<folder>           Save an additional eml backup of the message in <folder>. File is
                              saved even if the sending fails. (default: off)
  --signature                 Append ~/.signature (default: off)
  --sign                      Sign with GPG (default: off)
  --encrypt                   Encrypt with GPG (default: off)
  --xmailer=<string>          The xmailer field that appears in the headers
  --editor=<command>          Instead of taking the email's text from stdin, use this editor
  --gpgmode=<mime|armor>      Set GPG to MIME (default) or Armor
  --host=<smtphost>           The SMTP hostname
  --port=<portnumber>         The smtp server's port (25)
  --user=<username>           Username for the host
  --pass=<password>           The SMTP password belonging to user
  --sentmailfolder=<folder>   The message is saved in this folder as an eml file,
                              in addition to sending it (it's even saved there if
                              the sending fails).
  --gpgkey=<key>              The GPG key used for signing.
  --gpgpass=<password>        The password belonging to gpgkey
  --zipfolders                if a folder is passed as attachment, should it be zipped, or
                              should the program abort (default: on)
  --zip=<filename>            Put all attachments into a compressed zip file named <filename>,
                              and attach only that zip file (default: off)
  --sentbcc=<addresslist>     Additional BCC list that should *always* receive a
                              copy (e.g. a 'Sent' copy for yourself)
  --configfile=<file>         An alternative config file.
  --hello_host                Hostname for the HELO string.
  --disable_ehlo              Don't use EHLO, only HELO (default: off)
  --force-ehlo'               Use EHLO even if server doesn't say ESMTP (default: off)
  --encryption[=0|=1]         Set this to 0 in order to not use encryption even if the
                              remote host offers it (No TLS/SSL). (default: on)
  --auth                      Enable all methods of SMTP authentication (default: on)
  --auth_login                Enable only AUTH LOGIN method (default: off)
  --auth_plain                Enable only AUTH PLAIN method (default: off)
  --auth_cram_md5             Enable only AUTH CRAM-MD5 method (default: off)
  --auth_digest_md5           Enable only AUTH DIGEST-MD5 method (default: off)
  --textfile=<file>           File that should be used to fill the email's text
  --emlfile=<file>            Email an already finished eml file. All recipients (except BCC)
                              are taken from the headers. In general, there is no way to modify
                              any part of the message, any such command line options or settings
                              will be ignored. Missing fields can be filled up, however.
                              Encryption can be applied to an unencrypted eml file.
  --leave_eml_date            Together with --emlfile: use the date field that is specified in
                              the headers of the eml file. Default is off, i.e. replace the
                              date field with the current time.
  --nochecks                  Don't check email addresses for well-formedness. Use this to mail to
                              user\@localhost, e.g. Careful with this, you can mess up your headers!
  --charset                   The character set for the message. Careful with this!
                              Changing this option doesn't change the charset, which
                              depends on your system, only the headers
  --verbose                   Print out the SMTP communication, for debugging
  --editor                    The editor used to edit the email text before it is sent.
  --ask_for_cc                Should the program ask for a CC? (default: off)
  --ask_for_bcc               Should the program ask for a BCC? (default: off)
  --to_list=<file>            Send the email to the list of addresses specified in this file
  --cc_list=<file>            CC the email to the list of addresses specified in this file
  --bcc_list=<file>           BCC the email to the list of addresses specified in this file
  --expandlist=<file>         Use this file as an \"addressbook\" to expand addresses. For example,
                              if the line \"Michael Goerz <goerz\@physik.fu-berlin.de>\" is in the
                              file, when you enter \"Michael Goerz\", or \"goerz\@physik\" in To,
                              or CC, the program will replace those strings with the line form the
                              file.
  --recipientrules=<file>     Read per-recipient rules from this file, that can determine whether the
                              the email will be encrypted, signed, and appended a signature. The file
                              must have one rule per line, consisting of an email address followed by
                              the fields sign, nosign, encrypt, noencrypt, signature, nosignature. For
                              example:
                              goerz\@physik.fu-berlin.de    encrypt nosignature sign
                              Turning an option off overrides turning the option on in case of conflict.


Values containing spaces must be quoted.

You can specify defaults for any of these parameters in your config file
at $configfile. The syntax is the same as above, but leave out the leading
'--'. For backup, signature, sign, encrypt, etc., append '= 1' or '= 0'. You
can have spaces left and right of the the '=', also blank lines and comments
are allowed

An example file would be:

from     = 'My Name <my.name\@my.server.com>'
gpgmode  = mime      # 'mime' or 'armor' armor can't handle attachments!
host     = mail.server.com  # the smtp server
port     = 25         # the smtp server's port
xmailer  = 'mail.pl'  # The X-Mailer field
user     = 'username' # username for the host
pass     = 'secret  ' # leave this as '' if you don't want to save the
                      # SMTP password
backup   = '/path/sentfolder' # the message is saved in this folder as
                              # an eml file in addition to sending it.
                              # (it's even saved there if the sending fails).
gpgkey   = '2E7DAEC1' # GPG key used for signing.
gpgpass  = ''         # if you want to you can save your GPG password but
                      # I don't suggest it. If you leave this blank (you
                      # should), you will be asked for it.
editor   = 'kwrite'   # use this editor to write the email text
expandlist        = '$ENV{HOME}/.mailpl/addressbook.txt'
recipientrules    = '$ENV{HOME}/.mailpl/recipientrules.txt'

Command line parameters overwrite your settings in the config file.

If you do not provide the --from --to, --subject, or --text
parameters, or if the format of the parameters was invalid, the
program will ask you for the information. Also, it will ask for
any non-saved passwords. All other parameters must be given in
the config file or on the command line.

Attachments can be any exisiting file.

Note: If you use no password for gpg, you will have to modify Mail::GPG
";
exit;
}
