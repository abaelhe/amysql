<h1> Simple and High Performance MySQL Driver(Python). </h1>
<ul>
<li> 1. This driver works fine and with very high performance for most company and most scene;
<li> 2. Note: not fully compatiable with MySQL offcial protocol;
<li> 3. License and/or business collaboration. contact the maintainer.
</ul>
<h1>Current Support Functions:<h1>
<ul>
<li> 0. MySQL safe handshake(SHA1, MY_SCRAMBLE_LENGTH:20 byte);
<li> 1. SQL CRUD;
<li> 2. MySQL Store procedure.
</ul>
<h1>Interface:<h1>
<ul>
<li> 0. new connection:  
<br><code> >>> import amysql;c=amysql.Con();c.connect('localhost', #### server host
<br><code>         3306,       #### server port 
<br><code>               'xweb',     #### username
<br><code>               'xweb123',  #### password
<br><code>               'xweb')     #### database
<br><code>  );
<li> 1. SQL CRUD:
<br><code>
>>> c.query("select * from sys_usr")
</code>
<li> 2. MySQL Store procedure.
<br><code>
>>> c.query("call sys_usr_list()")
<li> 3. get query result:
<br><code>
>>> c.rows
>>> c.fields
<li> 4. adapte to Python async socket( c.sock is instance of Python socket class. ):
<br><code>
>>> c.sock
</ul>
<h1>Todo:<h1>
<ul>
<li> <h2> 0. As needed; <h2>
</ul>

