#!/usr/bin/env ruby

require 'minitest/autorun'
require 'webmock/minitest'
require 'json'
require_relative 'xomq'

describe XomqConfig do
  describe 'when data provided' do
    let(:config) { XomqConfig.new(secret_key: 'key', query_url: 'http://example.com/reports') }

    it('is filled') { assert_predicate(config, :filled?) }
    it('has no problem') { assert_nil(config.problem) }
    it('does not need to show help') { refute_predicate(config, :need_help?) }

    it 'has data' do
      assert_equal('key', config.secret_key)
      assert_equal('http://example.com/reports', config.query_url)
    end
  end

  describe 'when data provided by environment' do
    let(:config) { XomqConfig.new }

    before do
      @real_env = ENV.to_h
      ENV.replace({'XOMQ_SECRET_KEY' => 'key', 'XOMQ_QUERY_URL' => 'http://example.com/reports'})
      config.process!
    end

    after { ENV.replace @real_env }

    it('is filled') { assert_predicate(config, :filled?) }
    it('has no problem') { assert_nil(config.problem) }
    it('does not need to show help') { refute_predicate(config, :need_help?) }

    it 'has data' do
      assert_equal('key', config.secret_key)
      assert_equal('http://example.com/reports', config.query_url)
    end
  end

  describe 'when data provided by command line' do
    let(:config) { XomqConfig.new }

    before do
      @real_env = ENV.to_h
      ENV.replace({'XOMQ_SECRET_KEY' => 'key'})

      @real_argv = ARGV
      ARGV.replace %w[-k real_key -u http://example.com/reports]

      config.process!
    end

    after do
      ENV.replace @real_env
      ARGV.replace @real_argv
    end

    it('is filled') { assert_predicate(config, :filled?) }
    it('has no problem') { assert_nil(config.problem) }
    it('does not need to show help') { refute_predicate(config, :need_help?) }

    it 'has data' do
      assert_equal('real_key', config.secret_key)
      assert_equal('http://example.com/reports', config.query_url)
    end
  end

  describe 'without data' do
    let(:config) { XomqConfig.new }

    before do
      @real_env = ENV.to_h
      ENV.replace({})

      config.process!
    end

    after { ENV.replace @real_env }

    it('has a problem') { refute_nil(config.problem) }
  end

  describe 'when help requested by user' do
    let(:config) { XomqConfig.new }

    before do
      @real_argv = ARGV
      ARGV.replace %w[-h]

      config.process!
    end

    after { ARGV.replace @real_argv }

    it('does need to show help') { assert_predicate(config, :need_help?) }
  end
end

describe XomqLoader do
  let(:secret_key) { '1234567890abcdef' }
  let(:query_url) { 'https://example.com/api/reports' }
  let(:config) { XomqConfig.new(query_url: query_url, secret_key: secret_key) }
  let(:loader) { XomqLoader.new(config: config) }
  let(:response) do
    <<~REPORT.strip
      233.252.0.17 - '/'
      233.252.0.17 - '/login'
      233.252.0.28 - '/'
    REPORT
  end

  describe 'with normal server behavior' do
    before { stub_request(:post, query_url).and_return(body: response) }

    it 'makes correct request and processes data' do
      response_body = loader.each_line.to_a.join("\n")

      assert_equal(response, response_body)

      assert_requested :post, query_url do |req|
        parsed_body = JSON.parse(req.body)
        hmac = OpenSSL::HMAC.hexdigest('SHA256', secret_key, req.body)

        assert_equal('plain', parsed_body['report_type'])
        assert_includes(parsed_body, 'nonce')
        assert_equal('application/json', req.headers['Content-Type'])
        assert_equal(hmac, req.headers['Authorization'])
      end
    end
  end

  describe 'when server responds with unusual code' do
    before { stub_request(:post, query_url).and_return(status: 500) }

    it 'throws error' do
      assert_raises(XomqLoader::HTTPError) { loader.each_line.to_a }
    end
  end
end

describe XomqParser do
  let(:response) do
    <<~RESPONSE.strip
      233.252.0.17 - '/'
      233.252.0.17 - '/login'
      288.252.0.17 - '/login'
      233.252.0.17 - '/login
      233.252.0.17 - '/login'
      233.252.0.28 - '/'
    RESPONSE
  end

  let(:expected_errors) do
    <<~ERRORS
      bad ip ignored: 288.252.0.17 - '/login'
      bad string ignored: 233.252.0.17 - '/login
    ERRORS
  end

  let(:expected_report) { ['/ - 2', '/login - 1'] }
  let(:errors) { StringIO.new }
  let(:parser) { XomqParser.new(err_io: errors) }

  it 'processes data correctly' do
    response.each_line(&parser)

    assert_equal(expected_report, parser.report)
    assert_equal(expected_errors, errors.string)
  end
end
