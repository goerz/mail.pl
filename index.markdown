--- 
layout: default
title: mail.pl
github-url: http://github.com/goerz/mail.pl
---

The mail.pl script allows to send  email messages with attachments through an
SMTP server that requires authentification. The message can optionally be
encrypted and signed with GPG, and attachments can be zipped in various ways.

Author: [Michael Goerz](http://michaelgoerz.net)

This code is licensed under the [GPL](http://www.gnu.org/licenses/gpl.html)

## Download ##

Download the latest development head of the script:
[mail.pl](http://github.com/goerz/mail.pl/raw/master/mail.pl)

You can also clone the project with Git by running:

    $ git clone git://github.com/goerz/mail.pl

## Install ##

Store the `mail.pl` script anywhere in your `$PATH`.

## Dependencies ##

`mail.pl` depends on a number of Perl modules which can be obtained from
[CPAN](http://www.cpan.org) (try `sudo perl -MCPAN -e shell`).

* [MIME::Entity](http://search.cpan.org/~doneill/MIME-tools-5.428/lib/MIME/Entity.pm)
* [MIME::Types](http://perl.overmeer.net/mimetypes/)
* [MIME::Parser](http://search.cpan.org/~doneill/MIME-tools-5.428/lib/MIME/Parser.pm)
* [MIME::Head](http://search.cpan.org/~doneill/MIME-tools-5.428/lib/MIME/Head.pm)
* [MIME::Base64](http://search.cpan.org/~gaas/MIME-Base64-3.09/Base64.pm)
* [Mail::GPG](http://search.cpan.org/~doneill/MIME-tools-5.428/lib/MIME/Head.pm)
* [Email::Date](http://search.cpan.org/~rjbs/Email-Date-1.103/lib/Email/Date.pm)
* [Email::MessageID](http://search.cpan.org/~rjbs/Email-MessageID-1.402/lib/Email/MessageID.pm)
* [Term::ReadPassword](http://search.cpan.org/~phoenix/Term-ReadPassword-0.11/ReadPassword.pm)
* [IO::Socket::INET](http://search.cpan.org/~gbarr/IO-1.25/lib/IO/Socket/INET.pm)
* [IO::Socket::SSL](http://search.cpan.org/~sullr/IO-Socket-SSL-1.33/SSL.pm)
* [Net::SSLeay](http://search.cpan.org/~flora/Net-SSLeay-1.36/lib/Net/SSLeay.pm)
* [Archive::Zip](http://search.cpan.org/~adamk/Archive-Zip-1.30/lib/Archive/Zip.pm)
* [Digest::HMAC_MD5](http://search.cpan.org/~gaas/Digest-HMAC-1.02/lib/Digest/HMAC_MD5.pm)

## Usage ##

    Usage: ./mail.pl [parameters] [attachments]

    Parameters are:
      --to=<addresslist>          Recipients of message. You can use 'undisclosed recipients' to
                                  leave this blank
      --from=<address>            From-address
      --cc=<addresslist>          Carbon copy recipients
      --bcc=<addresslist>         Blind carbon copy recipients
      --subject=<string>          Subject line of the message
      --text=<string>             Text of the message. \n gets escaped to newline,
                                  \\ to \. Make sure that string is enclosed in  single
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
                                  user@localhost, e.g. Careful with this, you can mess up your headers!
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
      --expandlist=<file>         Use this file as an "addressbook" to expand addresses. For example,
                                  if the line "Michael Goerz <goerz@physik.fu-berlin.de>" is in the
                                  file, when you enter "Michael Goerz", or "goerz@physik" in To,
                                  or CC, the program will replace those strings with the line form the
                                  file.
      --recipientrules=<file>     Read per-recipient rules from this file, that can determine whether the
                                  the email will be encrypted, signed, and appended a signature. The file
                                  must have one rule per line, consisting of an email address followed by
                                  the fields sign, nosign, encrypt, noencrypt, signature, nosignature. For
                                  example:
                                  goerz@physik.fu-berlin.de    encrypt nosignature sign
                                  Turning an option off overrides turning the option on in case of conflict.


    Values containing spaces must be quoted.

    You can specify defaults for any of these parameters in your config file
    at /Users/goerz/.mailpl/mailpl.rc. The syntax is the same as above, but leave out the leading
    '--'. For backup, signature, sign, encrypt, etc., append '= 1' or '= 0'. You
    can have spaces left and right of the the '=', also blank lines and comments
    are allowed

    An example file would be:

    from     = 'My Name <my.name@my.server.com>'
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
    expandlist        = '/Users/goerz/.mailpl/addressbook.txt'
    recipientrules    = '/Users/goerz/.mailpl/recipientrules.txt'

    Command line parameters overwrite your settings in the config file.

    If you do not provide the --from --to, --subject, or --text
    parameters, or if the format of the parameters was invalid, the
    program will ask you for the information. Also, it will ask for
    any non-saved passwords. All other parameters must be given in
    the config file or on the command line.

    Attachments can be any exisiting file.

    Note: If you use no password for gpg, you will have to modify Mail::GPG
