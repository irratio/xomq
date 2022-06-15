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

uri = URI(query_url)

stats = Hash.new { |h, k| h[k] = Set.new }

begin
  result = Net::HTTP.post(uri, request_body, post_headers)
  result.body.each_line do |line|
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
rescue => e
  $stderr.puts "something happened: #{e}"
  exit 1
end

stats.each { |path, ips| puts "#{path} - #{ips.size}" }