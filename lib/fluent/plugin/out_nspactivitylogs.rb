require "fluent/plugin/output"
require "pg"
require "yajl"
require "json"

module Fluent::Plugin
  class NSPActivityLogOutput < Fluent::Plugin::Output
    Fluent::Plugin.register_output("nspactivitylogs", self)

    helpers :compat_parameters

    DEFAULT_BUFFER_TYPE = "memory"

    desc "The hostname of PostgreSQL server"
    config_param :host, :string, default: "localhost"
    desc "The port of PostgreSQL server"
    config_param :port, :integer, default: 5432
    desc "Set the sslmode to enable Eavesdropping protection/MITM protection"
    config_param :sslmode, :enum, list: %i[disable allow prefer require verify-ca verify-full], default: :prefer
    desc "The database name to connect"
    config_param :database, :string
    desc "The table name to insert records"
    config_param :table, :string
    desc "The user name to connect database"
    config_param :user, :string, default: nil
    desc "The password to connect database"
    config_param :password, :string, default: nil, secret: true
    desc "If true, insert records formatted as msgpack"
    config_param :msgpack, :bool, default: false
    desc "JSON encoder (yajl/json)"
    config_param :encoder, :enum, list: [:yajl, :json], default: :yajl

    config_param :time_format, :string, default: "%Y.%m.%d %H:%M:%S.%L"

    config_section :buffer do
      config_set_default :@type, DEFAULT_BUFFER_TYPE
      config_set_default :chunk_keys, ["tag"]
    end

    def initialize
      super
      @conn = nil
    end

    def configure(conf)
      compat_parameters_convert(conf, :buffer)
      super
      unless @chunk_key_tag
        raise Fluent::ConfigError, "'tag' in chunk_keys is required."
      end
      @encoder = case @encoder
                 when :yajl
                   Yajl
                 when :json
                   JSON
                 end
    end

    def shutdown
      if ! @conn.nil? and ! @conn.finished?
        @conn.close()
      end

      super
    end

    def formatted_to_msgpack_binary
      true
    end

    def multi_workers_ready?
      true
    end

    def format(tag, time, record)
	[time, record].to_msgpack
    end

    def write(chunk)
      init_connection
      @conn.exec("COPY #{@table} (time, uid, app, host, client_host, user_name, 
      req_method, req_url, resp_code, action, action_params, affected_objects, additional_params) 
      FROM STDIN WITH DELIMITER E'\\x01'")
      begin
        chunk.msgpack_each do |time, record|
          @conn.put_copy_data "#{time}\x01#{record['uid']}\x01#{record['app']}\x01" \
          "N/A\x01#{record['clientHost']}\x01#{record['user']}\x01#{record['reqMethod']}\x01" \
          "#{record['reqURL']}\x01#{record['respCode']}\x01#{record['action']}\x01#{record_value(record['actionParams'])}\x01" \
          "#{record_value(record['affObjs'])}\x01#{record_value(record['addlParams'])}\n"
        end
      rescue => err
        errmsg = "%s while copy data: %s" % [ err.class.name, err.message ]
        @conn.put_copy_end( errmsg )
        @conn.get_result
        raise
      else
        @conn.put_copy_end
        res = @conn.get_result
        raise res.result_error_message if res.result_status!=PG::PGRES_COMMAND_OK
      end
    end

    private

    def init_connection
      if @conn.nil?
        log.debug "connecting to PostgreSQL server #{@host}:#{@port}, database #{@database}..."

        begin
          @conn = PG::Connection.new(dbname: @database, host: @host, port: @port, sslmode: @sslmode, user: @user, password: @password)
        rescue
          if ! @conn.nil?
            @conn.close()
            @conn = nil
          end
          raise "failed to initialize connection: #$!"
        end
      end
    end

    def record_value(record)
      if @msgpack
        "\\#{@conn.escape_bytea(record.to_msgpack)}"
      else
        json = @encoder.dump(record)
        json.gsub!(/\\/){ '\\\\' }
        json
      end
    end
  end
end
