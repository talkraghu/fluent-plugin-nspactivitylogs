# fluent-plugin-nspactivitylogs, a plugin for [Fluentd](http://fluentd.org)

## Installation:

- Prereq: Install nspactivitylogsql headers: `apt-get install libpq-dev`
- Install the gem:
  - `gem install fluent-plugin-nspactivitylogs` or
  - `/usr/lib/fluent/ruby/bin/fluent-gem install fluent-plugin-nspactivitylogs`

## Changes from mysql:

- We currently don't suppor json format
- You need to specify a SQL query
- Placeholders are numbered (yeah, I know).

Other than that, just bear in mind that it's Postgres SQL.

### Quick example

    <match output.by.sql.*>
      type nspactivitylogs
      host master.db.service.local
      # port 3306 # default
      database application_logs
      username myuser
      password mypass
      key_names status,bytes,vhost,path,rhost,agent,referer
      sql INSERT INTO accesslog (status,bytes,vhost,path,rhost,agent,referer) VALUES ($1,$2,$3,$4,$5,$6,$7)
      flush_intervals 5s
    </match>



## Component

### PostgresOutput

Plugin to store Postgres tables over SQL, to each columns per values, or to single column as json.

## Configuration

### MysqlOutput

MysqlOutput needs MySQL server's host/port/database/username/password, and INSERT format as SQL, or as table name and columns.

    <match output.by.sql.*>
      type mysql
      host master.db.service.local
      # port 3306 # default
      database application_logs
      username myuser
      password mypass
      key_names status,bytes,vhost,path,rhost,agent,referer
      sql INSERT INTO accesslog (status,bytes,vhost,path,rhost,agent,referer) VALUES (?,?,?,?,?,?,?)
      flush_intervals 5s
    </match>

    <match output.by.names.*>
      type mysql
      host master.db.service.local
      database application_logs
      username myuser
      password mypass
      key_names status,bytes,vhost,path,rhost,agent,referer
      table accesslog
      # 'columns' names order must be same with 'key_names'
      columns status,bytes,vhost,path,rhost,agent,referer
      flush_intervals 5s
    </match>

Or, insert json into single column.

    <match output.as.json.*>
      type mysql
      host master.db.service.local
      database application_logs
      username root
      table accesslog
      columns jsondata
      format json
      flush_intervals 5s
    </match>

To include time/tag into output, use `include_time_key` and `include_tag_key`, like this:

    <match output.with.tag.and.time.*>
      type mysql
      host my.mysql.local
      database anydatabase
      username yourusername
      password secret

      include_time_key yes
      ### default `time_format` is ISO-8601
      # time_format %Y%m%d-%H%M%S
      ### default `time_key` is 'time'
      # time_key timekey

      include_tag_key yes
      ### default `tag_key` is 'tag'
      # tag_key tagkey

      table anydata
      key_names time,tag,field1,field2,field3,field4
      sql INSERT INTO baz (coltime,coltag,col1,col2,col3,col4) VALUES (?,?,?,?,?,?)
    </match>

Or, for json:

    <match output.with.tag.and.time.as.json.*>
      type mysql
      host database.local
      database foo
      username root

      include_time_key yes
      utc   # with UTC timezome output (default: localtime)
      time_format %Y%m%d-%H%M%S
      time_key timeattr

      include_tag_key yes
      tag_key tagattr
      table accesslog
      columns jsondata
      format json
    </match>
    #=> inserted json data into column 'jsondata' with addtional attribute 'timeattr' and 'tagattr'

## TODO

* implement 'tag_mapped'
  * dynamic tag based table selection

## Copyright

* Copyright
  * Copyright 2013 Uken Games
* License
  * Apache License, Version 2.0
