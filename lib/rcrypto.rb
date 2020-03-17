require "rcrypto/version"
require 'awesome_print' if ENV['USE_AWESOME_PRINT'] == 'true'

module Rcrypto
  require 'rcrypto/sss'
  require 'rcrypto/base_error'
  extend self
end

