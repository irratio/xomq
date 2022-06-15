#!/usr/bin/env ruby

require 'ipaddr'
require 'net/http'
require 'openssl'
require 'securerandom'
require 'set'

REPORT_REGEX = %r|(?<ip>\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}) - '(?<path>/[^']*)'|

def query_url
  @query_url ||= ENV['XOMQ_QUERY_URL']
end

def secret_key
  @secret_key ||= ENV['XOMQ_SECRET_KEY']
end

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

def each_body_line(resp)
  knob = ''
  resp.read_body do |chunk|
    *nuggets, new_knob = chunk.split("\n", -1)
    if nuggets.empty?
      knob << new_knob
      next
    end

    nuggets.first.prepend(knob)
    nuggets.each { |nugget| yield nugget }
    knob = new_knob
  end
  yield knob unless knob.empty?
end


uri = URI(query_url)
use_ssl = uri.is_a?(URI::HTTPS)

stats = Hash.new { |h, k| h[k] = Set.new }

begin
  Net::HTTP.start(uri.host, uri.port, use_ssl: use_ssl) do |http|
    request = Net::HTTP::Post.new(uri, post_headers)
    request.body = request_body

    http.request request do |response|
      unless response.code == '200'
        $stderr.puts "something happened:: #{response.message}"
        puts response.inspect
        exit 1
      end

      each_body_line(response) do |line|
        data = line.match(REPORT_REGEX)

        unless data
          $stderr.puts "bad string ignored: #{line.strip}"
          next
        end

        path = data[:path]
        ip = IPAddr.new(data[:ip]).to_i
        stats[path] << ip
      rescue IPAddr::InvalidAddressError
        $stderr.puts "bad ip ignored: #{line.strip}"
      end
    end
  end
rescue => e
  $stderr.puts "something happened: #{e}"
  exit 1
end

stats.each { |path, ips| puts "#{path} - #{ips.size}" }