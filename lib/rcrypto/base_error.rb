module Rcrypto
  class BaseError < StandardError
    def initialize(error, cause = nil)
      @error = error
      @cause = cause
    end

    def to_s
      if !!@cause
        JSON[error: @error, cause: @cause] rescue {error: @error, cause: @cause}.to_s
      else
        JSON[@error] rescue @error
      end
    end
  end
end
