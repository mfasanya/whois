#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2014 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/scanners/base'


module Whois
  class Record
    module Scanners

      class WhoisNetworksolutionsCom < BaseW

        self.tokenizers += [
            :scan_response_throttled,
        ]

        tokenizer :scan_response_throttled do
          if @input.match?(/contained within a list of IP addresses that may have failed/)
            @ast["response:throttled"] = true
            @input.skip(/^.+\n/)
          end
        end

      end

    end
  end
end
