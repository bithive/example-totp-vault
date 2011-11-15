#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'base64'
require 'erb'
require 'highline/import'
require 'lib/vault'
require 'sinatra'
require 'yaml'

puts "Warning: qrencode not found, web interface will not display QR codes" unless %x[which qrencode] and $?.success?

vault = Vault.new ask('Enter the vault password: ') {|q| q.echo = false }

configure do
  set :show_exceptions, false
  set :domain, 'example.com'
end

error ArgumentError do
  request.env['sinatra.error'].message
end

before do
  cache_control :private, :no_cache, :no_store, :must_revalidate
end

get '/' do
  @members = vault.members.sort
  erb :index
end

get '/check' do
  @result = vault.authenticate params[:uid], params[:otp]
  status @result ? 200 : 401
end

post '/delete' do
  vault.delete params[:uid]
  redirect '/'
end

post '/insert' do
  @uid = params[:uid].downcase
  @key = vault.insert @uid
  @url = "otpauth://totp/#{@uid}@#{settings.domain}?secret=#{@key}"
  @png = Base64.encode64 %x[qrencode "#{@url}" -o -]

  erb :key
end