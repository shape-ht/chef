#!/usr/bin/perl
#CHEF - A configurable hardware trojan evaluation framework
#Copyright (C) 2015  Daniel Neubacher and Christian Krieg
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Please cite the paper in which we introduced CHEF:
#
#Krieg, C. & Neubacher, D. CHEF: A Configurable Hardware Trojan
#Evaluation Framework Proceedings of the 10th Workshop on Embedded
#Systems Security (WESS 2015), 2015
#
#@INPROCEEDINGS{Krieg2015,
#  author = {Christian Krieg and Daniel Neubacher},
#  title = {CHEF: A Configurable Hardware Trojan Evaluation Framework},
#  booktitle = {Proceedings of the 10th Workshop on Embedded Systems
#Security (WESS 2015)},
#  year = {2015},
#}


use strict;
use Term::ANSIColor;

eval ("use LWP::Simple;");
die "[err] LWP::Simple not installed.\n" if $@;
eval ("use Getopt::Std;");
die "[err] Getopt::Std not installed.\n" if $@;
eval ("use File::Basename;");
die "[err] File::Basename not installed.\n" if $@;
eval ("use LWP 5.6.9;");
die "[err] LWP is not the required version (5.6.9).\n" if $@;
eval ("use Term::ProgressBar;");
die "[err] Term::ProgressBar not installed.\n" if $@;
eval ("use IO::Tee;");
die "[err] IO::Tee not installed.\n" if $@;
eval ("use Digest::SHA;");
die "[err] Digest::SHA not installed.\n" if $@;
eval ("use Doxygen::Filter::Perl;");
die "[err] Doxygen::Filter::Perl not installed.\n" if $@;
eval ("use XML::LibXML;");
die "[err] XML::LibXML not installed.\n" if $@;

use vars qw/ %opt /;

use constant VERBOSE => 0;
use constant SHOW_XML => 0;
use constant DELETE_SCRIPTS => 1;
use constant DELETE_ARCHIVES => 1;

$Getopt::Std::STANDARD_HELP_VERSION = 1;
my $SCRIPTNAME = $0;
my ($benchmarkurl,$workdir,$benchmarkdir,$decompress,$normalize,$bugfix,$diff,$checksum,$suitedir,$suite,$name, $filename, $dirs, $suffix);
my ($top_original,$top_module_original,$run,$output_file);
my $final_data;
my $progress;
my $next_update = 0;
my $total_size;
my $evaldir;
my $yosysexecutable;
my $logfilehandle;
my $tee;
my $logfilename;
my $archivedirectory;

#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Subroutine to print the help message, when chef.pl is invoked with the --help option
# 
#*
sub HELP_MESSAGE {


  print  "\nHelp for "; 
  print color 'bold';
  print "chef.pl";
  print color 'reset';
  print ".\n\n";
  print color 'bold';
  print "Usage: ./chef.pl [options]\n\n";
  print color 'reset';
  print "Command line switches:\n\n"; 
  print color 'bold';
  print "-p XML File or directory containing XML Files";
  print color 'reset';
  print "\n\tParse this XML File(s). Either a single XML File or a directory. In the latter case ALL Files";
  print "\n\tin this directory will be processed. No default.\n\n";
  print color 'bold';
  print "-d";
  print color 'reset';
  print "\n\tDownload the files as given in the XML File(s). No arguments.\n\n";
  print color 'bold';
  print "-x";
  print color 'reset';
  print "\n\tExtract the downloaded Files with the commands given in the XML File(s). No arguments.\n\n";
  print color 'bold';
  print "-e";
  print color 'reset';
  print "\n\tExecute the <normalize> and <bugfix> part as given in the XML File(s). No arguments.\n\n";
  print color 'bold';
  print "-r";
  print color 'reset';
  print "\n\tRun the yosys commands, hardcoded in the runyosys function. No arguments. Mutually exclusive";
  print "\n\twith the -s option.\n\n";
  print color 'bold';
  print "-s script.ys";
  print color 'reset';
  print "\n\tRun yosys with the script supplied as argument. Mutually exclusive with";
  print "\n\tthe -r option.\n\n";
  print color 'bold';
  print "-w directory";
  print color 'reset';
  print "\n\tUse the argument supplied as working directory. Default is a timestamped directory";
  print "\n\tin the current directory.\n\n";
  print color 'bold';
  print "-u suite";
  print color 'reset';
  print "\n\tOnly include xml files with the suite attribute in yosysrun, only works when -p is";
  print "\n\tcalled on a directory\n\n";
  print color 'bold';
  print "-a archivedir";
  print color 'reset';
  print "\n\tUse the archives stored in archivedir instead of downloadin them from the sources";
  print "\n\tconfigured in the xml file(s) supplied to -p\n\n";
  print color 'bold';
  print "-f";
  print color 'reset';
  print "\n\tFlat. Used to download all archives from the parsed file flat into a directory";
  print "\n\tsupplied to the -w command to create a archivedirectory. No arguments.\n\n";
  print color 'bold';
  print "-W workbench.xml";
  print color 'reset';
  print "\n\tWorkbench";
  print "\n\t\n\n";
  print color 'bold';
  print "-t trojanname";
  print color 'reset';
  print "\n\tInsert a Trojan specified in the xml file supplied to -p. Takes the name of the Trojan as argument.";
  print "\n\t\n\n";
  print color 'bold';
  print "-T trojan technology level";
  print color 'reset';
  print "\n\tTechnology level, used to select different technology levels when inserting Trojans with -t.";
  print "\n\tTakes the technology level as an argument.\n\n";
  print color 'bold';
  print "-h";
  print color 'reset';
  print "\n\tPrint this help message.\n\n";
  print "Examples: ";
  print color 'bold';
  print "\tchef.pl -p sample.xml -dxer\n\n";
  print "\t\tchef.pl -p sample.xml -dxe -w workingdirectory -s yosys_scriptfile\n\n\n\n";
  print color 'reset';
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Print the help message when chef.pl is invoked with the -h option
#
#*
sub usage {
  HELP_MESSAGE;
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Print versiont information when invoked with --version
#
#*
sub VERSION_MESSAGE {
  print "chef.pl v0.6\n";
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Initialization subroutine, initialize basic variables like workdir, starttime.
#   Create working directory workdir if needed.
#   Define valid options and read them
#*
sub init {
  if ( ! -e "chef.conf" )
  {
    #   No chef.conf configuration file found, switching to defaults
    print "Configuration file not found, switching to defaults.\n";
    $yosysexecutable = "~/shape-ht_prj/yosys/yosys";
    $evaldir = "~/shape-ht_prj/evaluation";
    $logfilename = "evaluation.log";
    $archivedirectory = "benchmarkarchive";
  }
  else
  {
    #   Reading configuration file, initializing variables with values found there

    print ( "Config file chef.conf found.\n" ) if VERBOSE;
    open ( configfilehandle , "<" , "chef.conf" );
    my @cf = <configfilehandle>;
    foreach my $config_line (@cf)
    {
      if ( index( $config_line , "#" ) == 0 ) #	Skip comments in the configuration file
      { 
	next;
      }  
      my @line = split ( "=" , $config_line );
      for ( $line[0] )
      {
	if ( $line[0] eq "yosysexecutable" )
	{
	  chomp $line[1];
	  $yosysexecutable = $line[1];
	}
	elsif ( $line[0] eq "evaldir" )
	{
	  chomp $line[1];
	  $evaldir = $line[1];
	}
	elsif ( $line[0] eq "logfilename" )
	{
	  chomp $line[1];
	  $logfilename = $line[1];
	}
	elsif ( $line[0] eq "archivedirectory" )
	{
	  chomp $line[1];
	  $archivedirectory = $line[1];
	}
      }
    }
    close configfilehandle;

  }
#   $logfilename is now defined throught the chef.conf file or initialized with
#   a default value, open it and tee the output to it
    open $logfilehandle, ">", $logfilename;
    $tee=IO::Tee->new(\*STDOUT,\*$logfilehandle); 

  print "CHEF - A configurable hardware trojan evaluation framework
#Copyright (C) 2015  Daniel Neubacher and Christian Krieg
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Please cite the paper in which we introduced CHEF:
#
#Krieg, C. & Neubacher, D. CHEF: A Configurable Hardware Trojan
#Evaluation Framework Proceedings of the 10th Workshop on Embedded
#Systems Security (WESS 2015), 2015
#
#\@INPROCEEDINGS{Krieg2015,
#  author = {Christian Krieg and Daniel Neubacher},
#  title = {CHEF: A Configurable Hardware Trojan Evaluation Framework},
#  booktitle = {Proceedings of the 10th Workshop on Embedded Systems
#Security (WESS 2015)},
#  year = {2015},
#}\n";
  print color 'green';
  print $tee "Initializing\n", color 'reset';
  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
  $min ='0'.$min if $min < 10;
  $year += 1900;
  $mon+=1;
  my $cur_time = "$wday $mday $mon $year, $hour:$min:$sec";
  print ( $tee "$cur_time\n" ) if VERBOSE;
  getopts('p:hdxers:w:u:a:ft:W:T:', \%opt);

  die usage() if defined $opt{r} and $opt{s}; #	  -r and -s are mutually exclusive

#   if no workdir is defined through the w option, use a timestamp as name of
#   the working directory
  if ( $opt{w} )
  {
    print ( $tee "Working directory $opt{w} defined through the -w option\n" ) if VERBOSE;
    $workdir = "$opt{w}";
  }
  else
  {
    $workdir = "$year-$mon-$mday-$hour:$min";
  }
  print ($tee "$workdir\n") if VERBOSE;
  if ( ! -d $workdir )
  {
    `mkdir $workdir`;
  }
  
#   If the archivedirectory option is supplied, check if this directory exists
  if ( $opt{a} )
  {
    $archivedirectory = "$opt{a}";
    if ( ! -d $archivedirectory )
    {
      print $tee "Archive directory $archivedirectory not found\n";
    }
  }

  usage() if $opt{h};

}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Download file specified in xml file. If archive directory is supplied via
#   the -a option use the previously stored archive.
#*
sub download {
  print $tee "Starting Download\n";
  my ($url,$workdir,$benchmarkdir,$checksum,$suitedir) = @_;
  ($filename, $dirs, $suffix) = fileparse("$url");
  print ( $tee "Start function download with benchmarkurl $url, workdir $workdir, benchmarkdir $benchmarkdir, checksum $checksum, suitedir $suitedir\n" ) if VERBOSE;

  print ( $tee "$filename filename, $dirs dirs, $suffix suffix\n" ) if VERBOSE;
  print $tee "Downloading $url\n";
 
  my $archivepath;
  if ( ! $opt{f} )
  { 
    if ( -d $suitedir) 
    {
    }
    else 
    {
      system "mkdir $suitedir";
    }
    $archivepath = $suitedir."/".$filename;
  }
  else
  {
    $archivepath = $workdir.$filename;
    print ( $tee "$archivepath\n" ) if VERBOSE;
  }

  my $filehandle;

  if ( ! $opt{a} )
  {
#   No archivedir, actual downloading required 
    if ( -e $archivepath ) 
    {
      print $tee "File already exists\n";
      print ( $tee "Calculating sha256 for existing file\n" ) if VERBOSE;
      open $filehandle, "<", $archivepath or die ("Could not open file. $!");
      binmode($filehandle);
      my $existingfilesha = Digest::SHA->new(256);
      while (<$filehandle>) 
      {
	$existingfilesha->add($_);
      }
      close $filehandle;
    
      my $existingfiledigest = $existingfilesha->hexdigest;
  
      if ( $checksum eq $existingfiledigest ) 
      {
	print $tee "SHA of existing file matches SHA provided in XML File!\n";
	return;
      } 
      else 
      {
	print $tee "SHA of existing file doesn't match SHA provided in XML File!\n";
      }
    }

    my $useragent = LWP::UserAgent->new( );
    my $result = $useragent->head("$url");
    my $remote_headers = $result->headers;
    $total_size = $remote_headers->content_length;
    
    $progress = Term::ProgressBar->new({name => "$url", count => $total_size, ETA => 'linear'});
    $progress->minor(0);
    $progress->max_update_rate(1);
  
    my $response = $useragent->get("$url", ':content_cb' => \&callback );
    $progress->update($total_size);
    print ( $tee "$archivepath\n") if VERBOSE;
    open my $filehandle, ">", $archivepath or die ("Could not open file. $!");
    print $filehandle $final_data;
    close $filehandle;
  }
  else
  {
#   We us an archivedir
    
    print ( $tee "Archivedir $archivedirectory\n" ) if VERBOSE;
    $archivedirectory =~s/\/*$/\//g;                                            #       Add trailing slash to path if there isn't one
    my $archivepath = $archivedirectory;
    $archivepath .= $filename;
    print ( $tee "ARCHIVPATH $archivepath\n" ) if VERBOSE;
    system "cp $archivepath  $suitedir";
  }
  open $filehandle, "<", $archivepath or die ("Could not open file. $!");
  binmode($filehandle);
  my $sha = Digest::SHA->new(256);
  while (<$filehandle>) {
    $sha->add($_);
  }
  close $filehandle;
  
#** Create SHA256 checksum from downloaded file, compare it to the checksum 
#   stored in the XML file
#*
  print ( $tee $checksum, " checksum from xml\n" ) if VERBOSE;
  my $digest = $sha->hexdigest;
  print ( $tee $digest, " $filename SHA256 created from downloaded file.\n" ) if VERBOSE;
  if ( $checksum ne $digest ) {
    print $tee "[";
    print color 'red';
    print $tee "ERR";
    print color 'reset';
    print $tee "] Checksum mismatch!!\n";
  } 
  else {
    print $tee "[";
    print color 'green';
    print $tee "OK";
    print color 'reset';
    print $tee "] Checksum correct!!\n";
  }    
  $final_data=();
  $next_update=();
  $progress=();
  print ( $tee "Finished Download\n" ) if VERBOSE;
}

sub callback {
  my ($data, $response, $protocol) = @_;
  $final_data .= $data;
  
  $next_update = $progress->update(length($final_data))if length($final_data) >= $next_update;
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** This function uses the information in the <decompress> part of the parsed
#   xml files to decompress a downloaded benchmark.
#*
sub decompress {
  print $tee "Start extracting files\n";
  my ($suite,$decompress) = @_;
  use Cwd;
  chdir $suite;

  if ( VERBOSE )
  {
    system "$decompress";
  }
  else
  {
    my $output = ` $decompress`;
    print $logfilehandle "$output";
  }
#  print $tee $stdout;
  ( system "rm $filename" ) if DELETE_ARCHIVES;
  print $tee "Finished extracting files\n";
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Here the content of the <normalize> part of the parsed xml files is
#   passed to the shell. Hopefully it's a shell script.
#   TODO: ensure only valid and allowed code is passed to the system or at least catch
#   ocurring errors.
#*
sub normalize {
  print $tee "Start normalizing\n";
  my ($normalize) = @_;
  if ( $normalize =~ /^\s*$/ ) {
    print $tee "Nothing to be done here\n";
  }
  else {
    print ( $tee $normalize ) if VERBOSE;
    if ( VERBOSE )
    {
      system "$normalize";
    }
    else
    {


     open my $normalizefilehandle, ">", 'normalizefile.sh' or die ("Could not create normalize script. $!");
     print $normalizefilehandle $normalize;
     close $normalizefilehandle;
     system "chmod u+x normalizefile.sh";

     `./normalizefile.sh 1>&2 2> normalize.log`;
      
    open ( normalizelogfilehandle , "<" , "normalize.log" );
    my @nl = <normalizelogfilehandle>;
    foreach my $log_line (@nl)
    {
      print $logfilehandle $log_line;

    }
    close normalizelogfilehandle;
    ( `rm normalizefile.sh normalize.log` ) if DELETE_SCRIPTS;
    }

  }
    print $tee "Finished normalizing\n";
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** The bugfix function uses the information stored in the <bugfix> part of the
#   parsed xml files to patch processed files as necessary. The information is
#   stored in a temporary file and the content streamed to the patch command.
#*
sub bugfix {
  print $tee "Start bugfixing\n";
  my ($bugfix) = @_;
  if ($bugfix =~ /^\s*$/) {
    print $tee "Nothing to be done here\n";
  }
  else {
    open my $bugfixfilehandle, ">", 'bugfixfile' or die ("Could not create patch file. $!");
    print $bugfixfilehandle $bugfix;
    print $bugfixfilehandle "\n";
    close $bugfixfilehandle;
    system "cat bugfixfile | patch -t -p0";
    ( system "rm bugfixfile" ) if DELETE_SCRIPTS;
  }
  print $tee "Finished bugfixing\n";
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** This function is called by the -r option. It executes a few basic yosys commands, 
#   output goes only to the console. Better use -s and specify a yosys script to be
#   run.
#*
sub runyosys {
  my ($top_original,$top_module_original,$suitedir,$run) = @_;
  print $tee "Building yosys script file for evaluation run!\n";
  open my $yshandle, ">", 'chef.ys' or die ("Could not open file . $!");
  my($filename,$dirs,$suffix) = fileparse($top_original);
  print $tee $filename."\n";
  print $tee $dirs."\n";
  print $tee $suffix."\n";
  print $yshandle "read_verilog $evaldir"."/"."$suitedir"."/"."$top_original\n";
  print $yshandle "hierarchy -libdir $evaldir"."/"."$suitedir"."/"."$dirs -top $top_module_original\n";
  print $yshandle "proc\nflatten\nclean\nstat\nscc\n";
  close $yshandle;
  system "$yosysexecutable -s chef.ys";
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** This function takes the yosys script supplied as an argument to the -s 
#   option, replaces the placeholders in the script with the correct values
#   (i.e. name of the verilog file, top module of the design, etc.) and
#   executes yosys with this modified script as argument. 
#*
sub runyosys_script {
  system "pwd";
  print $tee "Run yosys script file.\n";
  print $tee "Script to run: ".$opt{s}."\n";
  my $template = $evaldir;
  $template .= "/";
  $template .= $opt{s};
  print $tee "Template: ".$template."\n";
  print $tee "verilog: ".$top_original."\n";
  open my $yosys_template_script, "<", $template or die ("Could not open file ". $!);
  chdir($suitedir);
  open my $yosys_script, ">", 'run.ys';
  my($filename,$dirs,$suffix) = fileparse($top_original);
# read yosys template script and write actual yosys script to run
  while (<$yosys_template_script>) {
    if (index($_,"#")==0)   #	Skip comments in the yosys template script
    {
      next;
    }
#   Substitute placeholders with actual values
    $_ =~ s#%VERILOGFILE%#$top_original#;
    $_ =~ s#%BENCHMARKDIRECTORY%#$evaldir/$suitedir/$dirs#;
    $_ =~ s#%TOPMODULENAME%#$top_module_original#;
    $_ =~ s#%ILANGFILENAME%#$evaldir/$suitedir/$output_file#;
    print "ACHTUNG " ,$name, "ACHTUNG\n";
    $_ =~ s#%BENCHMARKNAME%#$name#;
    print $yosys_script $_;
  }
  close $yosys_script;
  close $yosys_template_script;
  chdir($suitedir);
  system "$yosysexecutable -s run.ys ";
  ( system "rm run.ys" ) if DELETE_SCRIPTS;
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Parse an xml file supplied as argument
#   using XML::LibXML instead of XML::Rules
#   TODO: suitedir, benchmarkdir
#*
sub run_parse {
  my ($xmltoparsename) = @_;

  print $tee "Parsing $xmltoparsename\n";

  my ($uid,$language,$url,$trojan_insertion,$filename,$type);
  my ($top_infected,$top_module_infected,$format);
  my ($trojan_patch, $trojan_uid, $trojan_name, $trojan_abstractionlvl, $trojan_technology);

  my $filedoc = XML::LibXML->load_xml(
    location => $xmltoparsename,
     huge => 1,);
  
  my ($original_design_top_file, $original_design_top_module);

  $name = $filedoc->documentElement->getAttribute('name');
  $uid = $filedoc->documentElement->getAttribute('uid');
  $suite = $filedoc->documentElement->getAttribute('suite');

  $suitedir = $workdir."/".$suite;
  $benchmarkdir = $suitedir."/".$name;
  
  
  
  for my $archive ($filedoc->findnodes('/benchmark/archive')) 
  {
    for my $property ($archive->findnodes('./*'))
    {
      if ($property->nodeName() eq "url")
      {
	$url = $property->textContent();
      }      
      else
      {
	$checksum = $property->textContent();
	$type = $property->getAttribute('type');
      }
    }

    print ( '[$url]', "\t\t\t\t\t\t\t\t", $archive->findnodes('./url'), "\t\t\t$url\n" ) if SHOW_XML;
    print ( '[$checksum]', "\t\t\t\t\t\t\t", $archive->findnodes('./checksum'), "\t$checksum\n" ) if SHOW_XML;
    print ( '[$type]', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", "\t$type\n" ) if SHOW_XML;

    download($url,$workdir,$benchmarkdir,$checksum,$suitedir) if $opt{d};

  } 
  print ( '[$name]', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", $name, "\n" ) if SHOW_XML;
  print ( '[$uid]', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", $uid, "\n" ) if SHOW_XML;
  print ( '[$suite', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", $suite, "\n" ) if SHOW_XML;

  $decompress = $filedoc->findnodes('/benchmark/decompress')->to_literal;
  print ( '[$decompress]', "\t\t\t\t\t\t\t", $filedoc->findnodes('/benchmark/decompress'), "\t\t\t\t\t\t\t\t$decompress\n" ) if SHOW_XML;
  $normalize = $filedoc->findnodes('benchmark/normalize')->to_literal;
  print ( '[$normalize]', "\n", $filedoc->findnodes('/benchmark/normalize'), "\n" ) if SHOW_XML;
  $bugfix = $filedoc->findnodes('benchmark/bugfix')->to_literal;
  print ( '[$bugfix]', "\n", $filedoc->findnodes('/benchmark/bugfix'), "\n" ) if SHOW_XML;

  chdir("$workdir") if $opt{x};
  decompress($suite,$decompress) if $opt{x};
  chdir("$suitedir") if $opt{e};
  normalize($normalize) if $opt{e};
  bugfix($bugfix) if $opt{e};
  
  foreach my $file ($filedoc->findnodes('/benchmark/original_design')) 
  {
    $original_design_top_file = $file->findnodes('./top_file')->to_literal;
    print ( '[$top_original, $original_design_top_file]', "\t\t\t", $file->findnodes('./top_file'), "\t\t\t\t\t\t\t$original_design_top_file\n" ) if SHOW_XML;
    $original_design_top_module= $file->findnodes('./top_module')->to_literal;
    print ( '[$top_module_original, $original_design_top_module]', "\t\t", $file->findnodes('./top_module'), "\t\t\t\t\t\t\t\t\t$original_design_top_module\n" ) if SHOW_XML;
    $top_original = $original_design_top_file;
    $top_module_original = $original_design_top_module;
  } 

  for my $trojan ($filedoc->findnodes('/benchmark/trojan')) 
  {
    $trojan_uid = $trojan->getAttribute('uid');
    $trojan_name = $trojan->getAttribute('name');
    $trojan_abstractionlvl = $trojan->getAttribute('abstraction_level');
    $trojan_technology = $trojan->getAttribute('technology');
    for my $property ($trojan->findnodes('./*'))
    {
      if ($property->nodeName() eq "trojan_patch")
      {
        $trojan_patch = $property->textContent();
      }
    }

    print ( '[$trojan_uid]', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t$trojan_uid\n" ) if SHOW_XML;
    print ( '[$trojan_name]', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t$trojan_name\n" ) if SHOW_XML;
    print ( '[$trojan_abstractionlvl]', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t$trojan_abstractionlvl\n" ) if SHOW_XML;
    print ( '[$trojan_technology]', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t$trojan_technology\n" ) if SHOW_XML;
    #print ( '[$trojan_patch]', "","$trojan_patch" ) if SHOW_XML;
 
     if ( $opt{t} eq "*" || $trojan_name eq $opt{t} )
     {
       if ( $opt{T} eq "" || $trojan_technology eq $opt{T} , )
       {
          print ( $tee "Trojan to be inserted found.\n" ) if VERBOSE;
          trojan_insertion($trojan_uid, $trojan_name, $trojan_abstractionlvl, $trojan_patch, $trojan_technology, $workdir, $benchmarkdir, $suitedir, $name);
       }
     }
  }
   
  $run = $filedoc->findnodes('benchmark/run')->to_literal;
  print ( '[$run]', "\n", $filedoc->findnodes('/benchmark/run'), "\n" ) if SHOW_XML;
  foreach my $file ($filedoc->findnodes('/benchmark/output_file'))
  {
    $format = $file->getAttribute('format');
    print ( '[$format]', "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", $format, "\n" ) if SHOW_XML; 
  }
  $output_file = $filedoc->findnodes('benchmark/output_file')->to_literal;
  print ( '[$output_file]', "\t\t\t\t\t\t\t", $filedoc->findnodes('/benchmark/output_file'), "\t\t\t\t\t\t$output_file\n" ) if SHOW_XML;
}



#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Check if a single file or a directory is supplied to the -p option
#   Either call the corresponding functions for the one file or for all
#   XML files in the directory
#*
sub init_parse {
  my ($argument) = @_;
  print ( $argument."\n" ) if VERBOSE;
  if ( -d "$opt{p}" ) {
  # Directory supplied to the -p option
    print ( $tee "Directory $opt{p}\n" ) if VERBOSE;
    my $directoryname = $opt{p};
    $directoryname =~s/\/*$/\//g;
    opendir(directoryhandle, "$directoryname");
    my @files = readdir(directoryhandle);
    closedir(directoryhandle);

    foreach my $file (@files) {
#     Skip current directory, parent directory and files with names not ending in xml
#     ATTENTION, case sensitive, *.XML files will be skipped
      next if($file =~/^\.$/);
      next if($file =~ /^\.\.$/);
      next if($file !~ /.*xml$/);
      run_parse($directoryname.$file);
#     Check if -u option set and its argument matches the suite attribute in 
#     the XML file, if not, skip this file
      next if($opt{u} && "$opt{u}" ne "$suite");
      runyosys($top_original,$top_module_original,$suitedir) if $opt{r};
      print("allright\n");
      runyosys_script if $opt{s};
      chdir("$evaldir");
    }

  }
  elsif ( -e "$opt{p}" ) {
  # Single XML file supplied to the -p option
    print ( $tee "Single file $opt{p}\n" ) if VERBOSE;
    run_parse($opt{p});
    runyosys($top_original,$top_module_original,$suitedir) if $opt{r};
    runyosys_script if $opt{s};
    chdir ("$evaldir");
  }
  else {
  # No file or directory with this name exists, ERROR
    print $tee "[";
    print $tee color 'red';
    print $tee "ERR";
    print $tee color 'reset';
    print $tee "] $opt{p} not found!!\n";
  } 
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
sub trojan_insertion {
  
  print "Starting Trojan insertion\n";
  
  my ($trojan_uid, $trojan_name, $trojan_abstractionlvl, $trojan_patch, $trojan_technology, $workdir, $benchmarkdir, $suitedir, $benchmark_name) = @_;
  
  chdir ("$suitedir");
  system "cp -rp $benchmark_name $benchmark_name.ori";
  
  open my $patchfilehandle, ">", 'patchfile' or die ("Could not create patch file. $!");
  print $patchfilehandle $trojan_patch;
  print $patchfilehandle "\n";
  close $patchfilehandle;
  

  print ( $tee "Inserting Trojan $trojan_name level $trojan_abstractionlvl technology $trojan_technology\n" );
  my $output = `cat patchfile | patch -t -p0`;
  print $logfilehandle "$output";
  system "rm patchfile"; 
  
  if ( $trojan_technology eq "" )
  {
    system "mv $benchmark_name $benchmark_name-$trojan_name";
    system "mv $benchmark_name.ori $benchmark_name";
  }
  else
  {
    system "mv $benchmark_name $benchmark_name-$trojan_name-$trojan_technology";
    system "mv $benchmark_name.ori $benchmark_name";
  }
  
  print "Finished Trojan insertion\n"; 
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Run testbench function. Reads a testbench xml file
#   TODO: improve/implement error handling
#*
sub run_testbench {
  if ( -e "$opt{W}" ) 
  {

    print "running testbench $opt{W}\n";
    
    my $testbenchname = $opt{W};
    my $testbenchparser = XML::LibXML->new();
    my $testbenchdoc = $testbenchparser->parse_file($opt{W});

    my ($testbench_dir) = $testbenchdoc->findnodes('/testbench/testbench_dir')->to_literal;
    print $testbench_dir."\n";
    $testbench_dir = $opt{w};
    print "TESTBENCHDIR $testbench_dir\n";;
    my ($test) = $testbenchdoc->findnodes('/testbench/test')->to_literal;
    print $testbenchdoc->findnodes('/testbench/test'), "\n";
    my ($output_dir) = $testbenchdoc->findnodes('/testbench/output_dir')->to_literal;
    print $testbenchdoc->findnodes('/testbench/output_dir'), "\n";
    my ($csv_file) = $testbenchdoc->findnodes('/testbench/csv_file')->to_literal;
    print $testbenchdoc->findnodes('/testbench/csv_file'), "\n";
    my ($yosys_script) = $testbenchdoc->findnodes('/testbench/yosys_script')->to_literal;
    print $testbenchdoc->findnodes('/testbench/yosys_script'), "\n";
    foreach my $benchmark ($testbenchdoc->findnodes('/testbench/benchmark'))
    {
      my ($uid) = $benchmark->findnodes('./uid')->to_literal;
      print $benchmark->findnodes('./uid'), "\n";
      my ($path) = $benchmark->findnodes('./path')->to_literal;
      print $benchmark->findnodes('./path'), "\n";
      
      parse_benchmark_xml($path,$uid,$testbench_dir,$yosys_script);
    }
    
  }
  else
  {
  # No file with this name exists, ERROR
    print $tee "[";
    print $tee color 'red';
    print $tee "ERR";
    print $tee color 'reset';
    print $tee "] $opt{W} not found, can not run testbench!\n";
    
  }
}


#
#------------------------------------------------------------------------------------------------------------------------------------------
#
#** Parse the xml file of an benchmark. Called by the run_testbench function.
#   Read the required information from the benchmark.xml (supplied as argument
#   in two parts: path and benchmark_xml) an run the yosys script supplied 
#   in the testbench.xml on the benchmarks in the testbench_directory.
#   As in runyosys_script create a temporary .ys file and replace placeholders
#   with the appropriate values from the xml files.
#   TODO: improve/implement error handling
#*
sub parse_benchmark_xml {

  my ($path,$benchmark_xml,$testbench_dir,$yosys_script) = @_;
  
  print "Parsing $benchmark_xml.xml in path $path, benchmark in $testbench_dir.\n";
  my $benchmarkfile = $path;
  $benchmarkfile .= "/".$benchmark_xml.".xml";
  my $benchmarkparser = XML::LibXML->new();
  my $benchmarkdoc = $benchmarkparser->parse_file($benchmarkfile);
  my ($top_original) = $benchmarkdoc->findnodes('/benchmark/top_original')->to_literal;
  print $benchmarkdoc->findnodes('/benchmark/top_original'), "\n";
  my ($top_module_original) = $benchmarkdoc->findnodes('/benchmark/top_module_original')->to_literal;
  print $benchmarkdoc->findnodes('benchmark/top_module_original'), "\n";
  my ($design_top_file,$name,$suite);
  foreach my $sections ($benchmarkdoc->findnodes('/benchmark')) 
  {
    $suite = $sections->getAttribute('suite');
    $name = $sections->getAttribute('name');

    print $suite."\n".$top_original."\n".$top_module_original."\n";
    print "Let's run $yosysexecutable on $top_original in $testbench_dir $suite\n";
    $design_top_file = $testbench_dir;
    $design_top_file .= "/";
    $design_top_file .= $suite;
    $design_top_file .= "/";
    $design_top_file .= $top_original;
  }
  
  my $template = $yosys_script;
  open my $template_script, "<", $template or die ("Could not open file ". $!);
  open my $yosys_script, ">", 'run.ys';
  
  while (<$template_script>) {
    if (index($_,"#")==0)   #	Skip comments in the yosys template script
    {
      next;
    }
#   Substitute placeholders with actual values
    $_ =~ s#%VERILOGFILE%#$design_top_file#;
    $_ =~ s#%BENCHMARKDIRECTORY%#$testbench_dir/$suite/$name#;
    $_ =~ s#%TOPMODULENAME%#$top_module_original#;
    $_ =~ s#%ILANGFILENAME%#$testbench_dir/$suite/$name/ilangfile#;
    $_ =~ s#%BENCHMARKNAME%#$name#;
    print $yosys_script $_;
  }

  close $yosys_script;
  close $template_script;
  system "cat run.ys";
  system "$yosysexecutable -s run.ys ";

}

init();

init_parse($opt{p}) if $opt{p};
run_testbench($opt{W}) if $opt{W};

close $logfilehandle;
