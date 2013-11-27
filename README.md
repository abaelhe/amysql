<h1> Simple and High Performance MySQL Driver(Python). </h1>
<ul>
<li> <h3>0. This is community version, supported and tested on Linux x64, Python 2.7;
<li> <h3>1. This driver works fine and with very high performance for most company and most scene;
<li> <h3>2. Note: not fully compatiable with MySQL offcial protocol;
<li> <h3>3.  contact the maintainer for License and/or business collaboration.
</ul>
<h1>Current Supported Functions:</h1>
<ul>
<li> <h3>0. MySQL safe handshake(SHA1, MY_SCRAMBLE_LENGTH:20 byte);
<li> <h3>1. SQL CRUD;
<li> <h3>2. MySQL Store procedure.
</ul>
<h1>Interface:</h1>
<ul>
<li> <h3>0. new connection:</h3>
<code> 
>>> import amysql;c=amysql.Con();c.connect(
<br><code> 'localhost', # server host
<br><code>        3306, # server port 
<br><code>      'xweb', # username
<br><code>   'xweb123', # password
<br><code>    'xweb')   # database
<br><code>  );
<li> <h3>1. SQL CRUD:</h3>
<br><code>
>>> c.query("select * from sys_usr")
</code>
<li> <h3>2. MySQL Store Procedure:</h3>
<code>
>>> c.query("call sys_usr_list()")
<li> <h3>3. get query result:</h3>
<code>
>>> c.rows
>>> c.fields
<li> <h3>4. adapte to Python async socket( c.sock is instance of Python socket class. ):</h3>
<code>
>>> c.sock
</ul>
<h1>Todo:<h1>
<ul>
<li> <h2> 0. As needed; <h2>
</ul>

