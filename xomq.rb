#!/usr/bin/env ruby

require 'getoptlong'
require 'ipaddr'
require 'net/http'
require 'openssl'
require 'securerandom'
require 'set'

XomqConfig = Struct.new(:query_url, :secret_key, keyword_init: true) do
  USAGE = <<~USAGE.freeze
    Usage: #{$PROGRAM_NAME} -k <key> -u <url>
    -k, --key   - secret key for access token generation,
                  can also be set via XOMQ_SECRET_KEY env variable
    -u, --url   - url for POST query,
                  can also be set via XOMQ_QUERY_URL env variable
    -h, --help  - this message
  USAGE

  def process!
    options = GetoptLong.new(
      ['--key', '-k', GetoptLong::REQUIRED_ARGUMENT],
      ['--url', '-u', GetoptLong::REQUIRED_ARGUMENT],
      ['--help', '-h', GetoptLong::NO_ARGUMENT]
    )
    options.quiet = true

    options.each do |option, value|
      case option
      when  '--key'
        self.secret_key ||= value
      when '--url'
        self.query_url ||= value
      when '--help'
        @need_help = true
      end
    end

    self.secret_key ||= ENV['XOMQ_SECRET_KEY']
    self.query_url ||= ENV['XOMQ_QUERY_URL']

    @problem = 'Please provide configuration.' unless filled?
  rescue GetoptLong::MissingArgument, GetoptLong::InvalidOption => e
    @problem = e.message
  end

  def usage
    USAGE
  end

  def filled?
    secret_key && query_url
  end

  def need_help?
    @need_help
  end

  def problem
    @problem
  end
end

class XomqLoader
  class HTTPError < StandardError; end

  def initialize(config:)
    @config = config
  end

  def each_line
    return enum_for(:each_line) unless block_given?

    knob = nil

    fetch do |chunk|
      prev_nugget = nil
      chunk.split("\n", -1) do |nugget|
        if knob
          prev_nugget = knob << nugget
          knob = nil
          next
        end

        yield prev_nugget if prev_nugget
        prev_nugget = nugget
      end

      knob = prev_nugget
    end

    yield knob unless knob.empty?
  end

  def reset!
    @access_token = nil
    @nonce = nil
  end

  private

  def nonce
    @nonce ||= SecureRandom.hex(6)
  end

  def request_body
    %({"report_type":"plain","nonce":"#{nonce}"})
  end

  def access_token
    @access_token ||= OpenSSL::HMAC.hexdigest('SHA256', secret_key, request_body)
  end

  def post_headers
    {
      'Content-Type': 'application/json',
      'Authorization': access_token
    }
  end

  def secret_key
    @config.secret_key
  end

  def uri
    @uri ||= URI(@config.query_url)
  end

  def use_ssl?
    uri.is_a?(URI::HTTPS)
  end

  def fetch
    Net::HTTP.start(uri.host, uri.port, use_ssl: use_ssl?) do |http|
      request = Net::HTTP::Post.new(uri, post_headers)
      request.body = request_body

      http.request(request) do |response|
        raise HTTPError.new("#{response.code} #{response.message}") unless response.is_a?(Net::HTTPSuccess)

        response.read_body { |chunk| yield chunk }
      end
    end
  ensure
    reset!
  end
end

class XomqParser
  REPORT_REGEX = %r|(?<ip>\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}) - '(?<path>/[^']*)'|

  def initialize(err_io: $stderr)
    @stats = Hash.new { |h, k| h[k] = Set.new }
    @err_io = err_io
  end

  def to_proc
    lambda do |line|
      data = line.match(REPORT_REGEX)

      unless data
        @err_io.puts "bad string ignored: #{line.strip}"
        next
      end

      path = data[:path]
      ip = IPAddr.new(data[:ip]).to_i
      @stats[path] << ip
    rescue IPAddr::InvalidAddressError
      @err_io.puts "bad ip ignored: #{line.strip}"
      next
    end
  end

  def report
    @stats.map { |path, ips| "#{path} - #{ips.size}" }
  end
end

if __FILE__ == $PROGRAM_NAME
  config = XomqConfig.new
  config.process!

  if config.problem
    $stderr.puts config.problem
    $stderr.puts
    $stderr.puts config.usage
    exit 1
  end

  if config.need_help?
    $stderr.puts config.usage
    exit
  end

  loader = XomqLoader.new(config: config)
  parser = XomqParser.new

  begin
    loader.each_line(&parser)
  rescue => e
    $stderr.puts "error: #{e}"
    exit 2
  end

  puts parser.report
end
